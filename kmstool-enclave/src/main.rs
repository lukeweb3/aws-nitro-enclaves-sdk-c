use nitro_enclaves_ffi::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::io;
use std::sync::{Arc, Mutex};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tracing::{error, info};

#[derive(Error, Debug)]
enum ServerError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Nitro Enclaves error: {0}")]
    NitroEnclaves(#[from] NitroEnclavesError),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("Client not set")]
    ClientNotSet,
    #[error("Invalid operation")]
    #[allow(dead_code)]
    InvalidOperation,
    #[error("Initialization error: {0}")]
    InitializationError(String),
    #[error("Missing required field: {0}")]
    MissingField(String),
    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),
}

type Result<T> = std::result::Result<T, ServerError>;

#[derive(Serialize, Deserialize)]
struct Request {
    operation: String,
    #[serde(flatten)]
    params: HashMap<String, serde_json::Value>,
}

#[derive(Serialize, Deserialize)]
struct Response {
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    plaintext: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ciphertext: Option<String>,
}

struct ClientInfo {
    region: String,
    endpoint: Option<String>,
    port: u16,
    #[allow(dead_code)]
    ca_bundle: Option<String>,
    credentials: (String, String, Option<String>),
    default_key_id: Option<String>,
}

struct Server {
    client_info: Arc<Mutex<Option<ClientInfo>>>,
}

impl Server {
    fn new() -> Self {
        Self {
            client_info: Arc::new(Mutex::new(None)),
        }
    }
    
    fn try_auto_configure(&self) -> bool {
        // Check if we can auto-configure from environment
        if self.client_info.lock().unwrap().is_some() {
            return true; // Already configured
        }
        
        info!("Attempting auto-configuration for enclave");
        
        // Get region - try environment first, then use a sensible default
        let region = env::var("AWS_DEFAULT_REGION")
            .or_else(|_| env::var("AWS_REGION"))
            .unwrap_or_else(|_| {
                info!("No region in environment, using default: ap-southeast-2");
                "ap-southeast-2".to_string()
            });
        
        // Try to get credentials from environment variables first
        let aws_key_id = env::var("AWS_ACCESS_KEY_ID");
        let aws_secret_key = env::var("AWS_SECRET_ACCESS_KEY");
        let aws_session_token = env::var("AWS_SESSION_TOKEN").ok();
        
        let credentials = match (aws_key_id, aws_secret_key) {
            (Ok(key_id), Ok(secret_key)) => {
                info!("Found AWS credentials in environment variables");
                (key_id, secret_key, aws_session_token)
            },
            _ => {
                // If no environment credentials, we need to fail here
                // In the future, we could try to get credentials from instance metadata
                // through a vsock proxy, but for now we require explicit credentials
                error!("No AWS credentials found in environment variables");
                error!("Please set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY");
                return false;
            }
        };
        
        info!("Auto-configuring with region: {}", region);
        
        let default_key_id = env::var("DEFAULT_KMS_KEY_ID").ok();
        if let Some(ref key) = default_key_id {
            info!("Using default KMS key ID: {}", key);
        }
        
        let client_info = ClientInfo {
            region,
            endpoint: None,
            port: 8000, // KMS proxy port
            ca_bundle: None,
            credentials,
            default_key_id,
        };
        
        *self.client_info.lock().unwrap() = Some(client_info);
        info!("Auto-configuration completed");
        true
    }
    
    fn set_client(&self, params: &HashMap<String, serde_json::Value>) -> Result<()> {
        let region = params.get("region")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ServerError::MissingField("region".into()))?
            .to_string();
            
        let endpoint = params.get("endpoint")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
            
        let port = params.get("port")
            .and_then(|v| v.as_u64())
            .unwrap_or(443) as u16;
            
        let ca_bundle = params.get("ca_bundle")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
            
        let aws_key_id = params.get("aws_key_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ServerError::MissingField("aws_key_id".into()))?
            .to_string();
            
        let aws_secret_key = params.get("aws_secret_key")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ServerError::MissingField("aws_secret_key".into()))?
            .to_string();
            
        let aws_session_token = params.get("aws_session_token")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        
        let default_key_id = params.get("default_key_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
            
        let client_info = ClientInfo {
            region,
            endpoint,
            port,
            ca_bundle,
            credentials: (aws_key_id, aws_secret_key, aws_session_token),
            default_key_id,
        };
        
        *self.client_info.lock().unwrap() = Some(client_info);
        Ok(())
    }
    
    fn create_kms_client(&self) -> Result<KmsClient> {
        info!("Creating KMS client");
        
        // Try auto-configuration if not already configured
        if !self.try_auto_configure() {
            error!("KMS client not configured and auto-configuration failed");
            return Err(ServerError::ClientNotSet);
        }
        
        let client_info = self.client_info.lock().unwrap();
        let info = client_info.as_ref().ok_or(ServerError::ClientNotSet)?;
        
        info!("Client info - region: {}, endpoint: {:?}, port: {}", 
            info.region, info.endpoint, info.port);
        
        let allocator = AwsAllocator::default()
            .map_err(|e| {
                error!("Failed to create allocator: {}", e);
                ServerError::InitializationError(format!("Allocator error: {}", e))
            })?;
        
        let region = AwsString::new(&allocator, &info.region)
            .map_err(|e| {
                error!("Failed to create region string: {}", e);
                ServerError::InitializationError(format!("Region string error: {}", e))
            })?;
        
        let _access_key_id = AwsString::new(&allocator, &info.credentials.0)
            .map_err(|e| {
                error!("Failed to create access_key_id string: {}", e);
                ServerError::InitializationError(format!("Access key string error: {}", e))
            })?;
            
        let _secret_access_key = AwsString::new(&allocator, &info.credentials.1)
            .map_err(|e| {
                error!("Failed to create secret_access_key string: {}", e);
                ServerError::InitializationError(format!("Secret key string error: {}", e))
            })?;
            
        let _session_token = info.credentials.2.as_ref()
            .map(|t| AwsString::new(&allocator, t))
            .transpose()
            .map_err(|e| {
                error!("Failed to create session_token string: {}", e);
                ServerError::InitializationError(format!("Session token string error: {}", e))
            })?;
        
        info!("Creating credentials and vsock config for KMS proxy");
        
        // Create AWS credentials from the provided access keys
        let credentials = AwsCredentials::new(
            &allocator,
            &info.credentials.0,
            &info.credentials.1,
            info.credentials.2.as_ref().map(String::as_str),
        ).map_err(|e| {
            error!("Failed to create credentials: {}", e);
            ServerError::InitializationError(format!("Credentials error: {}", e))
        })?;
        
        // In enclave, we must use vsock proxy to reach KMS
        // Parent instance is always CID 3, proxy port is typically 8000
        let config = KmsClientConfig::vsock(
            &allocator,
            &region,
            &credentials,
            "3",  // CID 3 for parent instance
            8000, // Standard vsock-proxy port
        ).map_err(|e| {
            error!("Failed to create KMS client config: {}", e);
            ServerError::InitializationError(format!("Config error: {}", e))
        })?;
        
        info!("Creating KMS client from config");
        
        KmsClient::new(config)
            .map_err(|e| {
                error!("Failed to create KMS client: {}", e);
                // Check if it's a connection error to KMS proxy
                match e {
                    NitroEnclavesError::NullPointer => {
                        ServerError::InitializationError(
                            "KMS proxy connection failed (vsock to CID 3 port 8000). Please ensure:\n\
                             1. KMS proxy is running on the parent instance (port 8000)\n\
                             2. Run: sudo netstat -tlnp | grep 8000\n\
                             3. If not running, start your KMS proxy service".to_string()
                        )
                    },
                    NitroEnclavesError::AwsError(code) if code == 0 => {
                        ServerError::InitializationError(
                            "KMS proxy connection failed. Check if KMS proxy is running on port 8000".to_string()
                        )
                    },
                    _ => {
                        ServerError::InitializationError(format!("KMS client error: {}", e))
                    }
                }
            })
    }
    
    fn decrypt(&self, params: &HashMap<String, serde_json::Value>) -> Result<String> {
        info!("Decrypt called with params: {:?}", params);
        
        let ciphertext_b64 = params.get("ciphertext")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ServerError::MissingField("ciphertext".into()))?;
            
        info!("Decoding base64 ciphertext");
        use base64::Engine as _;
        let ciphertext_bytes = base64::engine::general_purpose::STANDARD.decode(ciphertext_b64)?;
        info!("Ciphertext decoded, {} bytes", ciphertext_bytes.len());
        
        info!("Creating allocator for decrypt operation");
        let allocator = AwsAllocator::default()?;
        
        info!("Creating KMS client for decrypt");
        let client = self.create_kms_client()?;
        
        info!("Creating byte buffers");
        let ciphertext_buf = AwsByteBuffer::from_slice(&allocator, &ciphertext_bytes)?;
        let mut plaintext_buf = AwsByteBuffer::new(&allocator, 4096)?;
        
        // Check if we have encryption context
        if let Some(context_value) = params.get("encryption_context") {
            if let Some(context_str) = context_value.as_str() {
                info!("Decrypting with encryption context");
                let context = AwsString::new(&allocator, context_str)?;
                client.decrypt_with_context(None, None, &ciphertext_buf, &context, &mut plaintext_buf)?;
            } else {
                info!("Decrypting without encryption context (context not a string)");
                client.decrypt(None, None, &ciphertext_buf, &mut plaintext_buf)?;
            }
        } else {
            info!("Decrypting without encryption context");
            client.decrypt(None, None, &ciphertext_buf, &mut plaintext_buf)
                .map_err(|e| {
                    error!("Decrypt failed: {}", e);
                    e
                })?;
        }
        
        Ok(base64::engine::general_purpose::STANDARD.encode(plaintext_buf.as_slice()))
    }
    
    fn generate_data_key(&self, params: &HashMap<String, serde_json::Value>) -> Result<(String, String)> {
        info!("GenerateDataKey called with params: {:?}", params);
        
        // Try to get key_id from params, fall back to default if configured
        let key_id_string = if let Some(key) = params.get("key_id").and_then(|v| v.as_str()) {
            key.to_string()
        } else {
            // Try to get default key from client info
            let client_info = self.client_info.lock().unwrap();
            client_info
                .as_ref()
                .and_then(|info| info.default_key_id.clone())
                .ok_or_else(|| {
                    error!("Missing required field: key_id (and no default key configured)");
                    ServerError::MissingField("key_id".into())
                })?
        };
        
        let key_id = key_id_string.as_str();
            
        let key_spec = params.get("key_spec")
            .and_then(|v| v.as_str())
            .unwrap_or("AES_256");
            
        info!("Generating data key with key_id: {}, key_spec: {}", key_id, key_spec);
        
        info!("Creating allocator for generate data key operation");
        let allocator = AwsAllocator::default()
            .map_err(|e| {
                error!("Failed to create allocator: {:?}", e);
                e
            })?;
        
        info!("Creating KMS client for generate data key");
        let client = self.create_kms_client()
            .map_err(|e| {
                error!("Failed to create KMS client: {:?}", e);
                e
            })?;
        
        // Convert key_spec string to enum
        let key_spec_enum = match key_spec {
            "AES_128" => {
                info!("Using AES_128 key spec (value: 1)");
                1 // AWS_KS_AES_128
            },
            "AES_256" => {
                info!("Using AES_256 key spec (value: 0)");
                0 // AWS_KS_AES_256
            },
            _ => {
                error!("Invalid key_spec provided: {}", key_spec);
                return Err(ServerError::InvalidParameter(format!("Invalid key_spec: {}. Must be AES_128 or AES_256", key_spec)))
            },
        };
        
        info!("Creating AWS string for key_id: {}", key_id);
        let key_id_str = AwsString::new(&allocator, &key_id_string)
            .map_err(|e| {
                error!("Failed to create AWS string for key_id: {:?}", e);
                e
            })?;
        
        info!("Creating byte buffers for output");
        let mut plaintext_buf = AwsByteBuffer::new(&allocator, 4096)
            .map_err(|e| {
                error!("Failed to create plaintext buffer: {:?}", e);
                e
            })?;
        let mut ciphertext_buf = AwsByteBuffer::new(&allocator, 4096)
            .map_err(|e| {
                error!("Failed to create ciphertext buffer: {:?}", e);
                e
            })?;
        
        info!("Calling KMS generate_data_key with key_spec_enum: {}", key_spec_enum);
        client.generate_data_key(&key_id_str, key_spec_enum, &mut plaintext_buf, &mut ciphertext_buf)
            .map_err(|e| {
                error!("KMS GenerateDataKey call failed with error: {:?}", e);
                e
            })?;
        
        info!("GenerateDataKey successful, plaintext size: {}, ciphertext size: {}", 
            plaintext_buf.len(), ciphertext_buf.len());
        
        use base64::Engine as _;
        let plaintext_b64 = base64::engine::general_purpose::STANDARD.encode(plaintext_buf.as_slice());
        let ciphertext_b64 = base64::engine::general_purpose::STANDARD.encode(ciphertext_buf.as_slice());
        
        info!("Encoded results to base64, plaintext_b64 length: {}, ciphertext_b64 length: {}",
            plaintext_b64.len(), ciphertext_b64.len());
        
        Ok((plaintext_b64, ciphertext_b64))
    }
    
    fn encrypt(&self, params: &HashMap<String, serde_json::Value>) -> Result<String> {
        info!("Encrypt called with params: {:?}", params);
        
        let plaintext_b64 = params.get("plaintext")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                error!("Missing required field: plaintext");
                ServerError::MissingField("plaintext".into())
            })?;
            
        // Try to get key_id from params, fall back to default if configured
        let key_id_string = if let Some(key) = params.get("key_id").and_then(|v| v.as_str()) {
            key.to_string()
        } else {
            // Try to get default key from client info
            let client_info = self.client_info.lock().unwrap();
            client_info
                .as_ref()
                .and_then(|info| info.default_key_id.clone())
                .ok_or_else(|| {
                    error!("Missing required field: key_id (and no default key configured)");
                    ServerError::MissingField("key_id".into())
                })?
        };
        
        let key_id = key_id_string.as_str();
            
        info!("Encrypting with key_id: {}", key_id);
        
        info!("Decoding base64 plaintext");
        use base64::Engine as _;
        let plaintext_bytes = base64::engine::general_purpose::STANDARD.decode(plaintext_b64)
            .map_err(|e| {
                error!("Failed to decode base64 plaintext: {}", e);
                ServerError::Base64(e)
            })?;
        info!("Plaintext decoded, {} bytes", plaintext_bytes.len());
        
        info!("Creating allocator for encrypt operation");
        let allocator = AwsAllocator::default()
            .map_err(|e| {
                error!("Failed to create allocator: {:?}", e);
                e
            })?;
        
        info!("Creating KMS client for encrypt");
        let client = self.create_kms_client()
            .map_err(|e| {
                error!("Failed to create KMS client: {:?}", e);
                e
            })?;
        
        info!("Creating AWS string for key_id: {}", key_id);
        let key_id_str = AwsString::new(&allocator, &key_id_string)
            .map_err(|e| {
                error!("Failed to create AWS string for key_id: {:?}", e);
                e
            })?;
        
        info!("Creating byte buffers");
        let plaintext_buf = AwsByteBuffer::from_slice(&allocator, &plaintext_bytes)
            .map_err(|e| {
                error!("Failed to create plaintext buffer: {:?}", e);
                e
            })?;
        let mut ciphertext_buf = AwsByteBuffer::new(&allocator, 8192)
            .map_err(|e| {
                error!("Failed to create ciphertext buffer: {:?}", e);
                e
            })?;
        
        // Check if we have encryption context
        if let Some(context_value) = params.get("encryption_context") {
            if let Some(context_str) = context_value.as_str() {
                info!("Encrypting with encryption context");
                let context = AwsString::new(&allocator, context_str)?;
                client.encrypt_with_context(&key_id_str, &plaintext_buf, &context, &mut ciphertext_buf)?;
            } else {
                info!("Encrypting without encryption context (context not a string)");
                client.encrypt(&key_id_str, &plaintext_buf, &mut ciphertext_buf)?;
            }
        } else {
            info!("Encrypting without encryption context");
            client.encrypt(&key_id_str, &plaintext_buf, &mut ciphertext_buf)
                .map_err(|e| {
                    error!("Encrypt failed: {:?}", e);
                    e
                })?;
        }
        
        info!("Encrypt successful, ciphertext size: {}", ciphertext_buf.len());
        
        Ok(base64::engine::general_purpose::STANDARD.encode(ciphertext_buf.as_slice()))
    }
    
    async fn handle_request(&self, request: Request) -> Response {
        match request.operation.as_str() {
            "SetClient" => {
                match self.set_client(&request.params) {
                    Ok(_) => Response {
                        error: None,
                        plaintext: None,
                        ciphertext: None,
                    },
                    Err(e) => Response {
                        error: Some(e.to_string()),
                        plaintext: None,
                        ciphertext: None,
                    },
                }
            },
            "Decrypt" => {
                match self.decrypt(&request.params) {
                    Ok(plaintext) => Response {
                        error: None,
                        plaintext: Some(plaintext),
                        ciphertext: None,
                    },
                    Err(e) => Response {
                        error: Some(e.to_string()),
                        plaintext: None,
                        ciphertext: None,
                    },
                }
            },
            "GenerateDataKey" => {
                match self.generate_data_key(&request.params) {
                    Ok((plaintext, ciphertext)) => Response {
                        error: None,
                        plaintext: Some(plaintext),
                        ciphertext: Some(ciphertext),
                    },
                    Err(e) => Response {
                        error: Some(e.to_string()),
                        plaintext: None,
                        ciphertext: None,
                    },
                }
            },
            "Encrypt" => {
                match self.encrypt(&request.params) {
                    Ok(ciphertext) => Response {
                        error: None,
                        plaintext: None,
                        ciphertext: Some(ciphertext),
                    },
                    Err(e) => Response {
                        error: Some(e.to_string()),
                        plaintext: None,
                        ciphertext: None,
                    },
                }
            },
            _ => Response {
                error: Some("Invalid operation".to_string()),
                plaintext: None,
                ciphertext: None,
            },
        }
    }
}

fn create_vsock_listener(port: u32) -> io::Result<UnixListener> {
    use libc::{socket, bind, listen, sockaddr_vm, AF_VSOCK, SOCK_STREAM, VMADDR_CID_ANY};
    use std::mem;
    
    unsafe {
        // Create vsock socket
        let fd = socket(AF_VSOCK, SOCK_STREAM, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        
        // Bind to port
        let mut addr: sockaddr_vm = mem::zeroed();
        addr.svm_family = AF_VSOCK as u16;
        addr.svm_cid = VMADDR_CID_ANY;
        addr.svm_port = port;
        
        if bind(fd, &addr as *const _ as *const _, mem::size_of::<sockaddr_vm>() as u32) < 0 {
            return Err(io::Error::last_os_error());
        }
        
        // Listen
        if listen(fd, 128) < 0 {
            return Err(io::Error::last_os_error());
        }
        
        // Convert to UnixListener
        use std::os::unix::io::FromRawFd;
        let std_listener = std::os::unix::net::UnixListener::from_raw_fd(fd);
        UnixListener::from_std(std_listener)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .init();
    
    info!("Starting kmstool-enclave server");
    
    // Initialize AWS SDK first with NULL (default) allocator
    info!("Initializing AWS Nitro Enclaves library...");
    init_with_null();
    
    // Now get the allocator after initialization
    info!("Getting allocator after library initialization...");
    let _allocator = AwsAllocator::default()
        .map_err(|e| ServerError::InitializationError(e.to_string()))?;
    
    // Seed entropy
    if let Err(e) = seed_entropy(256) {
        error!("Failed to seed entropy: {}", e);
    }
    
    // Get port from environment or use default
    let port = env::var("KMSTOOL_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000);
    
    // Create server
    let server = Arc::new(Server::new());
    
    // Create vsock listener
    let listener = create_vsock_listener(port)?;
    info!("Listening on vsock port {}", port);
    
    loop {
        match listener.accept().await {
            Ok((mut stream, _)) => {
                let server = server.clone();
                
                tokio::spawn(async move {
                    let mut buffer = vec![0u8; 65536];
                    
                    loop {
                        // Read request
                        match stream.read(&mut buffer).await {
                            Ok(0) => break, // Connection closed
                            Ok(n) => {
                                match serde_json::from_slice::<Request>(&buffer[..n]) {
                                    Ok(request) => {
                                        info!("Received operation: {} with {} params", request.operation, request.params.len());
                                        let response = server.handle_request(request).await;
                                        
                                        // Log response details
                                        if let Some(ref err) = response.error {
                                            error!("Operation failed with error: {}", err);
                                        } else {
                                            info!("Operation completed successfully");
                                        }
                                        
                                        // Send response
                                        match serde_json::to_vec(&response) {
                                            Ok(response_bytes) => {
                                                info!("Sending response ({} bytes)", response_bytes.len());
                                                if let Err(e) = stream.write_all(&response_bytes).await {
                                                    error!("Failed to send response: {}", e);
                                                    break;
                                                }
                                            }
                                            Err(e) => {
                                                error!("Failed to serialize response: {}", e);
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        error!("Failed to parse request from {} bytes: {}", n, e);
                                        let received_str = String::from_utf8_lossy(&buffer[..n]);
                                        error!("Received data: {}", received_str);
                                        
                                        let error_response = Response {
                                            error: Some(format!("Invalid request: {}", e)),
                                            plaintext: None,
                                            ciphertext: None,
                                        };
                                        if let Ok(response_bytes) = serde_json::to_vec(&error_response) {
                                            let _ = stream.write_all(&response_bytes).await;
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                error!("Failed to read from stream: {}", e);
                                break;
                            }
                        }
                    }
                });
            }
            Err(e) => {
                error!("Failed to accept connection: {}", e);
            }
        }
    }
}