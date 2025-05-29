use clap::Parser;
use nitro_enclaves_ffi::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use thiserror::Error;
use tracing::{error, info};

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
    
    /// Base64 encoded ciphertext (read from stdin if not provided)
    #[arg(long)]
    ciphertext: Option<String>,
    
    /// Encryption context as JSON string
    #[arg(long)]
    encryption_context: Option<String>,
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

fn get_aws_credentials() -> Result<(String, String, Option<String>)> {
    // Try to get credentials from environment variables
    if let (Ok(key_id), Ok(secret_key)) = (
        env::var("AWS_ACCESS_KEY_ID"),
        env::var("AWS_SECRET_ACCESS_KEY"),
    ) {
        let session_token = env::var("AWS_SESSION_TOKEN").ok();
        return Ok((key_id, secret_key, session_token));
    }
    
    // Try to get credentials from default provider chain
    // In Rust version, we'll initialize the auth library and use default provider
    unsafe {
        aws_auth_library_init(aws_default_allocator());
        
        let provider = aws_credentials_provider_new_chain_default(aws_default_allocator());
        if provider.is_null() {
            return Err(ClientError::CredentialsNotFound);
        }
        
        // This is a simplified version - in production you'd want async credential resolution
        // For now, we'll just fail if env vars aren't set
        aws_credentials_provider_release(provider);
    }
    
    Err(ClientError::CredentialsNotFound)
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

fn send_request(stream: &mut UnixStream, request: &Request) -> Result<Response> {
    // Send request
    let request_bytes = serde_json::to_vec(request)?;
    stream.write_all(&request_bytes)?;
    stream.flush()?;
    
    // Read response
    let mut response_buffer = vec![0u8; 65536];
    let n = stream.read(&mut response_buffer)?;
    
    let response: Response = serde_json::from_slice(&response_buffer[..n])?;
    
    if let Some(error) = response.error {
        return Err(ClientError::ServerError(error));
    }
    
    Ok(response)
}

fn main() -> Result<()> {
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
    let mut stream = create_vsock_stream(cid, cli.port)?;
    
    // Get AWS credentials
    let (aws_key_id, aws_secret_key, aws_session_token) = get_aws_credentials()?;
    
    // Get region
    let region = cli.region
        .or_else(|| get_region().ok())
        .ok_or(ClientError::MissingArgument)?;
    
    // Load CA bundle if specified
    let ca_bundle = cli.ca_bundle
        .map(|path| fs::read_to_string(&path))
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
        let plaintext = base64::decode(plaintext_b64)
            .map_err(|e| ClientError::ServerError(format!("Invalid base64: {}", e)))?;
        io::stdout().write_all(&plaintext)?;
        io::stdout().flush()?;
    }
    
    Ok(())
}