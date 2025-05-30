use clap::Parser;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use thiserror::Error;
use tracing::{error, info};
use aws_credential_types::provider::ProvideCredentials;

#[derive(Error, Debug)]
enum ClientError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    ServerError(String),
    #[error("Missing required argument")]
    MissingArgument,
    #[error("AWS credentials not found")]
    CredentialsNotFound,
    #[error("Invalid CID format")]
    InvalidCidFormat,
}

type Result<T> = std::result::Result<T, ClientError>;

#[derive(Parser)]
#[command(name = "kmstool_instance")]
#[command(about = "AWS KMS tool for Nitro Enclaves (instance/client version)")]
struct Cli {
    /// Enclave CID (from nitro-cli describe-enclaves)
    #[arg(long)]
    cid: Option<u32>,
    
    /// Port to connect to (default: 3000)
    #[arg(long, default_value = "3000")]
    port: u32,
    
    /// AWS region
    #[arg(long)]
    region: Option<String>,
    
    /// KMS endpoint (optional)
    #[arg(long)]
    kms_endpoint: Option<String>,
    
    /// KMS proxy port (default: 8000)
    #[arg(long, default_value = "8000")]
    kms_proxy_port: u16,
    
    /// CA bundle path
    #[arg(long)]
    ca_bundle: Option<String>,
    
    /// Base64 encoded ciphertext (for decrypt, read from stdin if not provided)
    #[arg(long)]
    ciphertext: Option<String>,
    
    /// Base64 encoded plaintext (for encrypt, read from stdin if not provided)
    #[arg(long)]
    plaintext: Option<String>,
    
    /// Encryption context as JSON string
    #[arg(long)]
    encryption_context: Option<String>,
    
    /// Operation to perform (decrypt, encrypt, or generate-data-key)
    #[arg(long, default_value = "decrypt")]
    operation: String,
    
    /// Key ID for generate-data-key operation
    #[arg(long)]
    key_id: Option<String>,
    
    /// Key spec for generate-data-key operation (AES_128 or AES_256)
    #[arg(long, default_value = "AES_256")]
    key_spec: String,
    
    /// For generate-data-key: only output ciphertext (encrypted key)
    #[arg(long)]
    ciphertext_only: bool,
    
    /// For generate-data-key: only output plaintext (raw key)
    #[arg(long)]
    plaintext_only: bool,
}

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

fn create_vsock_stream(cid: u32, port: u32) -> io::Result<UnixStream> {
    use libc::{socket, connect, sockaddr_vm, AF_VSOCK, SOCK_STREAM};
    use std::mem;
    use std::os::unix::io::FromRawFd;
    
    unsafe {
        // Create vsock socket
        let fd = socket(AF_VSOCK, SOCK_STREAM, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        
        // Connect to enclave
        let mut addr: sockaddr_vm = mem::zeroed();
        addr.svm_family = AF_VSOCK as u16;
        addr.svm_cid = cid;
        addr.svm_port = port;
        
        if connect(fd, &addr as *const _ as *const _, mem::size_of::<sockaddr_vm>() as u32) < 0 {
            return Err(io::Error::last_os_error());
        }
        
        Ok(UnixStream::from_raw_fd(fd))
    }
}

struct AwsConfig {
    credentials: (String, String, Option<String>),
    region: Option<String>,
    endpoint_url: Option<String>,
}

async fn get_aws_config() -> Result<AwsConfig> {
    // Load AWS SDK config once and extract all needed information
    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    
    // Get credentials
    let credentials_provider = config.credentials_provider()
        .ok_or(ClientError::CredentialsNotFound)?;
    
    let credentials = credentials_provider
        .provide_credentials()
        .await
        .map_err(|_| ClientError::CredentialsNotFound)?;
    
    // Get region
    let region = config.region().map(|r| r.to_string());
    
    // Get endpoint URL if configured
    let endpoint_url = config.endpoint_url().map(|u| u.to_string());
    
    Ok(AwsConfig {
        credentials: (
            credentials.access_key_id().to_string(),
            credentials.secret_access_key().to_string(),
            credentials.session_token().map(|s| s.to_string()),
        ),
        region,
        endpoint_url,
    })
}


async fn get_region_from_config() -> Result<String> {
    // Try to get region from AWS SDK config (includes environment vars and EC2 metadata)
    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    
    if let Some(region) = config.region() {
        Ok(region.to_string())
    } else {
        Err(ClientError::MissingArgument)
    }
}

fn get_region_from_env() -> Result<String> {
    env::var("AWS_DEFAULT_REGION")
        .or_else(|_| env::var("AWS_REGION"))
        .map_err(|_| ClientError::MissingArgument)
}

fn read_ciphertext(cli_arg: Option<String>) -> Result<String> {
    if let Some(ciphertext) = cli_arg {
        Ok(ciphertext)
    } else {
        // Read from stdin
        let mut buffer = String::new();
        io::stdin().read_to_string(&mut buffer)?;
        Ok(buffer.trim().to_string())
    }
}

fn read_plaintext(cli_arg: Option<String>) -> Result<String> {
    if let Some(plaintext) = cli_arg {
        // If provided as argument, encode to base64
        use base64::Engine as _;
        Ok(base64::engine::general_purpose::STANDARD.encode(plaintext.as_bytes()))
    } else {
        // Read from stdin and encode to base64
        let mut buffer = Vec::new();
        io::stdin().read_to_end(&mut buffer)?;
        use base64::Engine as _;
        Ok(base64::engine::general_purpose::STANDARD.encode(&buffer))
    }
}

fn send_request(stream: &mut UnixStream, request: &Request) -> Result<Response> {
    // Send request as JSON without newline (matching enclave's expectation)
    info!("Preparing to send {} request", request.operation);
    let request_bytes = serde_json::to_vec(request)?;
    
    // Debug: log the request
    let request_json = serde_json::to_string_pretty(request)?;
    info!("Sending request ({} bytes): {}", request_bytes.len(), request_json);
    
    stream.write_all(&request_bytes)?;
    stream.flush()?;
    info!("Request sent successfully");
    
    // Read response
    let mut response_buffer = vec![0u8; 65536];
    info!("Waiting for response...");
    let n = stream.read(&mut response_buffer)?;
    
    if n == 0 {
        error!("Connection closed by server - no data received");
        return Err(ClientError::ServerError("Connection closed by server".to_string()));
    }
    
    info!("Received {} bytes from server", n);
    
    // Debug: log the response
    let response_str = String::from_utf8_lossy(&response_buffer[..n]);
    info!("Raw response data: {}", response_str);
    
    let response: Response = serde_json::from_slice(&response_buffer[..n])
        .map_err(|e| {
            error!("Failed to parse response JSON: {}", e);
            ClientError::Json(e)
        })?;
    
    if let Some(ref error) = response.error {
        error!("Server returned error: {}", error);
        
        // Parse and improve error messages for common issues
        let improved_error = if error.contains("KMS proxy connection failed") {
            format!("Internal Error: {}\n\nSolution: Start the KMS proxy service on the EC2 instance", error)
        } else if error.contains("Null pointer error") && error.contains("Client creation") {
            "Internal Error: KMS connection failed. The KMS proxy service is not accessible.\n\n\
             Possible causes:\n\
             1. KMS proxy is not running on the parent instance\n\
             2. Incorrect vsock configuration\n\
             3. Network connectivity issues\n\n\
             To diagnose: Run 'sudo netstat -tlnp | grep 8000' on the parent instance".to_string()
        } else if error.contains("Missing required field: key_id") {
            "Error: Missing required parameter --key-id\n\n\
             Usage: --key-id alias/your-key-name or --key-id arn:aws:kms:...".to_string()
        } else if error.contains("Invalid key_spec") {
            "Error: Invalid key specification\n\n\
             Valid values: AES_128, AES_256".to_string()
        } else if error.contains("Base64 decode error") {
            "Error: Invalid input format\n\n\
             The ciphertext must be valid base64 encoded data".to_string()
        } else {
            format!("Server Error: {}", error)
        };
        
        return Err(ClientError::ServerError(improved_error));
    }
    
    info!("Response parsed successfully");
    Ok(response)
}

fn check_client_configured(stream: &mut UnixStream) -> Result<bool> {
    let check_request = Request {
        operation: "CheckClient".to_string(),
        params: HashMap::new(),
    };
    
    let response = send_request(stream, &check_request)?;
    
    if let Some(status) = response.plaintext {
        Ok(status == "configured")
    } else {
        Ok(false)
    }
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("\n{}\n", e);
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .init();
    
    let cli = Cli::parse();
    
    // Get CID from argument or environment
    let cid = cli.cid
        .or_else(|| env::var("ENCLAVE_CID").ok()?.parse().ok())
        .ok_or(ClientError::InvalidCidFormat)?;
    
    info!("Connecting to enclave CID {} port {}", cid, cli.port);
    
    // Connect to enclave
    info!("Creating vsock connection to CID {} port {}", cid, cli.port);
    let mut stream = create_vsock_stream(cid, cli.port)
        .map_err(|e| {
            error!("Failed to connect to enclave: {}", e);
            e
        })?;
    info!("Successfully connected to enclave");
    
    // Check if client is already configured in the enclave
    info!("Checking if client is already configured in enclave");
    let client_already_configured = check_client_configured(&mut stream)
        .unwrap_or_else(|e| {
            info!("Failed to check client status, assuming not configured: {}", e);
            false
        });
    
    let need_set_client = !client_already_configured;
    
    if client_already_configured {
        info!("Client already configured in enclave, skipping SetClient");
    } else {
        info!("Client not configured in enclave, will send SetClient");
    }
    
    if need_set_client {
        // Get AWS configuration from SDK
        info!("Fetching AWS configuration");
        let aws_config = get_aws_config().await
            .map_err(|e| {
                error!("Failed to get AWS configuration: {}", e);
                e
            })?;
        
        let (aws_key_id, aws_secret_key, aws_session_token) = aws_config.credentials;
        info!("AWS credentials obtained successfully");
        
        // Get region with fallback chain
        info!("Getting AWS region");
        let region = if let Some(r) = cli.region {
            // Use explicitly provided region
            info!("Using region from command line");
            r
        } else if let Some(r) = aws_config.region {
            // Use region from AWS SDK config
            info!("Using region from AWS SDK config");
            r
        } else if let Ok(r) = get_region_from_env() {
            // Fallback to environment variables
            info!("Using region from environment variables");
            r
        } else {
            error!("AWS region not specified. Please provide --region or configure AWS_DEFAULT_REGION/AWS_REGION");
            return Err(ClientError::MissingArgument);
        };
        info!("Using AWS region: {}", region);
        
        // Get endpoint with fallback chain
        let endpoint = if let Some(e) = cli.kms_endpoint {
            // Use explicitly provided endpoint
            info!("Using KMS endpoint from command line");
            Some(e)
        } else if let Some(e) = aws_config.endpoint_url {
            // Use endpoint from AWS SDK config
            info!("Using KMS endpoint from AWS SDK config");
            Some(e)
        } else {
            None
        };
        
        // Load CA bundle if specified
        let ca_bundle = cli.ca_bundle
            .as_ref()
            .map(|path| fs::read_to_string(path))
            .transpose()?;
        
        // Build SetClient request
        let mut set_client_params = HashMap::new();
        set_client_params.insert("region".to_string(), serde_json::Value::String(region));
        set_client_params.insert("aws_key_id".to_string(), serde_json::Value::String(aws_key_id));
        set_client_params.insert("aws_secret_key".to_string(), serde_json::Value::String(aws_secret_key));
        
        if let Some(token) = aws_session_token {
            set_client_params.insert("aws_session_token".to_string(), serde_json::Value::String(token));
        }
        
        if let Some(endpoint) = endpoint {
            set_client_params.insert("endpoint".to_string(), serde_json::Value::String(endpoint));
        }
        
        set_client_params.insert("port".to_string(), serde_json::Value::Number(cli.kms_proxy_port.into()));
        
        if let Some(ca) = ca_bundle {
            set_client_params.insert("ca_bundle".to_string(), serde_json::Value::String(ca));
        }
        
        let set_client_request = Request {
            operation: "SetClient".to_string(),
            params: set_client_params,
        };
        
        info!("Setting KMS client configuration");
        send_request(&mut stream, &set_client_request)?;
    }
    
    // Perform the requested operation
    match cli.operation.as_str() {
        "decrypt" => {
            // Read ciphertext
            let ciphertext = read_ciphertext(cli.ciphertext)?;
            
            // Build Decrypt request
            let mut decrypt_params = HashMap::new();
            decrypt_params.insert("ciphertext".to_string(), serde_json::Value::String(ciphertext));
            
            if let Some(context) = cli.encryption_context {
                decrypt_params.insert("encryption_context".to_string(), serde_json::Value::String(context));
            }
            
            let decrypt_request = Request {
                operation: "Decrypt".to_string(),
                params: decrypt_params,
            };
            
            info!("Sending decrypt request");
            let response = send_request(&mut stream, &decrypt_request)?;
            
            // Output plaintext
            if let Some(plaintext_b64) = response.plaintext {
                use base64::Engine as _;
                let plaintext_bytes = base64::engine::general_purpose::STANDARD.decode(plaintext_b64)
                    .map_err(|e| ClientError::ServerError(format!("Invalid base64: {}", e)))?;
                
                // Try to convert to UTF-8 string, fallback to raw bytes if not valid UTF-8
                match String::from_utf8(plaintext_bytes.clone()) {
                    Ok(plaintext_str) => {
                        // Output as string if valid UTF-8
                        println!("{}", plaintext_str);
                    }
                    Err(_) => {
                        // Output raw bytes if not valid UTF-8
                        io::stdout().write_all(&plaintext_bytes)?;
                        io::stdout().flush()?;
                    }
                }
            }
        },
        "encrypt" => {
            info!("Starting encrypt operation");
            
            // Read plaintext
            let plaintext = read_plaintext(cli.plaintext)?;
            
            // Build Encrypt request
            let mut encrypt_params = HashMap::new();
            encrypt_params.insert("plaintext".to_string(), serde_json::Value::String(plaintext));
            
            // Key ID is optional if enclave has default key configured
            if let Some(key_id) = cli.key_id {
                encrypt_params.insert("key_id".to_string(), serde_json::Value::String(key_id));
            } else {
                info!("No key_id provided, will use enclave default if configured");
            }
            
            if let Some(context) = cli.encryption_context {
                encrypt_params.insert("encryption_context".to_string(), serde_json::Value::String(context));
            }
            
            let encrypt_request = Request {
                operation: "Encrypt".to_string(),
                params: encrypt_params,
            };
            
            info!("Sending encrypt request");
            let response = send_request(&mut stream, &encrypt_request)?;
            
            // Output ciphertext
            if let Some(ciphertext_b64) = response.ciphertext {
                println!("{}", ciphertext_b64);
            } else {
                error!("Server response missing ciphertext");
                return Err(ClientError::ServerError("Response missing ciphertext".to_string()));
            }
        },
        "generate-data-key" => {
            info!("Starting generate-data-key operation");
            
            // Build GenerateDataKey request
            let mut gen_key_params = HashMap::new();
            
            let key_id = cli.key_id
                .ok_or_else(|| {
                    error!("Missing required --key-id argument");
                    ClientError::MissingArgument
                })?;
            info!("Using key_id: {}", key_id);
            info!("Using key_spec: {}", cli.key_spec);
            
            gen_key_params.insert("key_id".to_string(), serde_json::Value::String(key_id));
            gen_key_params.insert("key_spec".to_string(), serde_json::Value::String(cli.key_spec));
            
            let gen_key_request = Request {
                operation: "GenerateDataKey".to_string(),
                params: gen_key_params,
            };
            
            info!("Sending generate data key request");
            let response = send_request(&mut stream, &gen_key_request)?;
            
            // Check if we got both plaintext and ciphertext
            if response.plaintext.is_none() {
                error!("Server response missing plaintext");
                return Err(ClientError::ServerError("Response missing plaintext".to_string()));
            }
            if response.ciphertext.is_none() {
                error!("Server response missing ciphertext");
                return Err(ClientError::ServerError("Response missing ciphertext".to_string()));
            }
            
            info!("GenerateDataKey successful");
            
            // Output based on flags
            if cli.ciphertext_only {
                // Only output ciphertext (for storage)
                if let Some(ciphertext) = response.ciphertext {
                    println!("{}", ciphertext);
                } else {
                    error!("Server response missing ciphertext");
                    return Err(ClientError::ServerError("Response missing ciphertext".to_string()));
                }
            } else if cli.plaintext_only {
                // Only output plaintext (decoded to raw bytes)
                if let Some(plaintext_b64) = response.plaintext {
                    use base64::Engine as _;
                    let plaintext_bytes = base64::engine::general_purpose::STANDARD.decode(plaintext_b64)
                        .map_err(|e| ClientError::ServerError(format!("Invalid base64: {}", e)))?;
                    
                    // Output raw key bytes (for use in encryption)
                    io::stdout().write_all(&plaintext_bytes)?;
                    io::stdout().flush()?;
                } else {
                    error!("Server response missing plaintext");
                    return Err(ClientError::ServerError("Response missing plaintext".to_string()));
                }
            } else {
                // Default: output as JSON with both plaintext and ciphertext
                let output = serde_json::json!({
                    "plaintext": response.plaintext,
                    "ciphertext": response.ciphertext,
                });
                
                println!("{}", serde_json::to_string_pretty(&output)?);
            }
        },
        _ => {
            return Err(ClientError::ServerError(format!("Unknown operation: {}", cli.operation)));
        }
    }
    
    Ok(())
}