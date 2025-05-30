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
    #[error("Server error: {0}")]
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

async fn get_aws_credentials() -> Result<(String, String, Option<String>)> {
    // Use AWS SDK's default credential chain
    // This will automatically try:
    // 1. Environment variables
    // 2. Web identity token from STS
    // 3. Credential profiles (~/.aws/credentials)
    // 4. ECS credentials provider
    // 5. EC2 Instance Metadata Service
    
    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let credentials_provider = config.credentials_provider()
        .ok_or(ClientError::CredentialsNotFound)?;
    
    let credentials = credentials_provider
        .provide_credentials()
        .await
        .map_err(|_| ClientError::CredentialsNotFound)?;
    
    Ok((
        credentials.access_key_id().to_string(),
        credentials.secret_access_key().to_string(),
        credentials.session_token().map(|s| s.to_string()),
    ))
}


fn get_region() -> Result<String> {
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
        return Err(ClientError::ServerError(error.clone()));
    }
    
    info!("Response parsed successfully");
    Ok(response)
}

#[tokio::main]
async fn main() -> Result<()> {
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
    
    // Check if we need to send SetClient based on operation and available config
    let need_set_client = match cli.operation.as_str() {
        "decrypt" => true, // Decrypt always needs SetClient for now
        "encrypt" | "generate-data-key" => {
            // For encrypt and generate-data-key, only send SetClient if we have explicit config
            cli.region.is_some() || get_region().is_ok() || cli.kms_endpoint.is_some()
        },
        _ => true,
    };
    
    if need_set_client {
        // Get AWS credentials
        info!("Fetching AWS credentials");
        let (aws_key_id, aws_secret_key, aws_session_token) = get_aws_credentials().await
            .map_err(|e| {
                error!("Failed to get AWS credentials: {}", e);
                e
            })?;
        info!("AWS credentials obtained successfully");
        
        // Get region
        info!("Getting AWS region");
        let region = cli.region
            .or_else(|| get_region().ok())
            .ok_or_else(|| {
                error!("AWS region not specified. Please provide --region or set AWS_DEFAULT_REGION/AWS_REGION environment variable");
                ClientError::MissingArgument
            })?;
        info!("Using AWS region: {}", region);
        
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
        
        if let Some(endpoint) = cli.kms_endpoint {
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
    } else {
        info!("Skipping SetClient, letting enclave auto-configure from environment");
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
                let plaintext = base64::engine::general_purpose::STANDARD.decode(plaintext_b64)
                    .map_err(|e| ClientError::ServerError(format!("Invalid base64: {}", e)))?;
                io::stdout().write_all(&plaintext)?;
                io::stdout().flush()?;
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
            
            // Output as JSON with both plaintext and ciphertext
            let output = serde_json::json!({
                "plaintext": response.plaintext,
                "ciphertext": response.ciphertext,
            });
            
            println!("{}", serde_json::to_string_pretty(&output)?);
        },
        _ => {
            return Err(ClientError::ServerError(format!("Unknown operation: {}", cli.operation)));
        }
    }
    
    Ok(())
}