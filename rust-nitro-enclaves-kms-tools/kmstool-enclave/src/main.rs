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
    InvalidOperation,
    #[error("Initialization error: {0}")]
    InitializationError(String),
    #[error("Missing required field: {0}")]
    MissingField(String),
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
}

struct ClientInfo {
    region: String,
    endpoint: Option<String>,
    port: u16,
    ca_bundle: Option<String>,
    credentials: (String, String, Option<String>),
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
        
        let client_info = ClientInfo {
            region,
            endpoint,
            port,
            ca_bundle,
            credentials: (aws_key_id, aws_secret_key, aws_session_token),
        };
        
        *self.client_info.lock().unwrap() = Some(client_info);
        Ok(())
    }
    
    fn create_kms_client(&self) -> Result<KmsClient> {
        let client_info = self.client_info.lock().unwrap();
        let info = client_info.as_ref().ok_or(ServerError::ClientNotSet)?;
        
        let allocator = AwsAllocator::default()?;
        let region = AwsString::new(&allocator, &info.region)?;
        
        let access_key_id = AwsString::new(&allocator, &info.credentials.0)?;
        let secret_access_key = AwsString::new(&allocator, &info.credentials.1)?;
        let session_token = info.credentials.2.as_ref()
            .map(|t| AwsString::new(&allocator, t))
            .transpose()?;
        
        let config = KmsClientConfig::default(
            &region,
            &access_key_id,
            &secret_access_key,
            session_token.as_ref(),
            info.endpoint.as_deref(),
            info.port,
        )?;
        
        KmsClient::new(config)
            .map_err(|e| ServerError::InitializationError(e.to_string()))
    }
    
    fn decrypt(&self, params: &HashMap<String, serde_json::Value>) -> Result<String> {
        let ciphertext_b64 = params.get("ciphertext")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ServerError::MissingField("ciphertext".into()))?;
            
        use base64::Engine as _;
        let ciphertext_bytes = base64::engine::general_purpose::STANDARD.decode(ciphertext_b64)?;
        
        let allocator = AwsAllocator::default()?;
        let client = self.create_kms_client()?;
        
        let ciphertext_buf = AwsByteBuffer::from_slice(&allocator, &ciphertext_bytes)?;
        let mut plaintext_buf = AwsByteBuffer::new(&allocator, 4096)?;
        
        // Check if we have encryption context
        if let Some(context_value) = params.get("encryption_context") {
            if let Some(context_str) = context_value.as_str() {
                let context = AwsString::new(&allocator, context_str)?;
                client.decrypt_with_context(None, None, &ciphertext_buf, &context, &mut plaintext_buf)?;
            } else {
                client.decrypt(None, None, &ciphertext_buf, &mut plaintext_buf)?;
            }
        } else {
            client.decrypt(None, None, &ciphertext_buf, &mut plaintext_buf)?;
        }
        
        use base64::Engine as _;
        Ok(base64::engine::general_purpose::STANDARD.encode(plaintext_buf.as_slice()))
    }
    
    async fn handle_request(&self, request: Request) -> Response {
        match request.operation.as_str() {
            "SetClient" => {
                match self.set_client(&request.params) {
                    Ok(_) => Response {
                        error: None,
                        plaintext: None,
                    },
                    Err(e) => Response {
                        error: Some(e.to_string()),
                        plaintext: None,
                    },
                }
            },
            "Decrypt" => {
                match self.decrypt(&request.params) {
                    Ok(plaintext) => Response {
                        error: None,
                        plaintext: Some(plaintext),
                    },
                    Err(e) => Response {
                        error: Some(e.to_string()),
                        plaintext: None,
                    },
                }
            },
            _ => Response {
                error: Some("Invalid operation".to_string()),
                plaintext: None,
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
    
    // Initialize AWS SDK
    let allocator = AwsAllocator::default()
        .map_err(|e| ServerError::InitializationError(e.to_string()))?;
    init(&allocator);
    
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
                                        info!("Received operation: {}", request.operation);
                                        let response = server.handle_request(request).await;
                                        
                                        // Send response
                                        if let Ok(response_bytes) = serde_json::to_vec(&response) {
                                            if let Err(e) = stream.write_all(&response_bytes).await {
                                                error!("Failed to send response: {}", e);
                                                break;
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        error!("Failed to parse request: {}", e);
                                        let error_response = Response {
                                            error: Some(format!("Invalid request: {}", e)),
                                            plaintext: None,
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