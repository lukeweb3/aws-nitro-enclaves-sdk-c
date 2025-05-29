use clap::{Parser, Subcommand};
use nitro_enclaves_ffi::*;
use std::env;
use std::fs;
use std::io::{self, Write};
use base64::Engine;
use thiserror::Error;
use tracing::{error, info};

#[derive(Error, Debug)]
enum CliError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Nitro Enclaves error: {0}")]
    NitroEnclaves(#[from] NitroEnclavesError),
    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Missing required environment variable: {0}")]
    MissingEnvVar(String),
    #[error("Invalid proxy port")]
    InvalidProxyPort,
}

type Result<T> = std::result::Result<T, CliError>;

#[derive(Parser)]
#[command(name = "kmstool_enclave_cli")]
#[command(about = "AWS KMS tool for Nitro Enclaves (CLI version)")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Decrypt ciphertext
    Decrypt {
        /// Ciphertext to decrypt (base64 encoded)
        ciphertext: String,
    },
    /// Generate a data key
    GenKey {
        /// Customer master key ID
        cmk: String,
        /// Key specification (AES_256 or AES_128)
        #[arg(default_value = "AES_256")]
        key_spec: String,
    },
    /// Generate random bytes
    GenRandom {
        /// Number of random bytes to generate
        #[arg(default_value = "32")]
        num_bytes: u32,
    },
}

fn get_proxy_port() -> Result<u16> {
    match env::var("VSOCK_PROXY_CID") {
        Ok(val) => {
            let parts: Vec<&str> = val.split(':').collect();
            if parts.len() == 2 {
                parts[1].parse().map_err(|_| CliError::InvalidProxyPort)
            } else {
                Ok(8000) // Default port
            }
        }
        Err(_) => Ok(8000), // Default port
    }
}

fn get_kms_region() -> Result<String> {
    env::var("AWS_DEFAULT_REGION")
        .or_else(|_| env::var("AWS_REGION"))
        .map_err(|_| CliError::MissingEnvVar("AWS_DEFAULT_REGION or AWS_REGION".into()))
}

fn get_kms_endpoint() -> Option<String> {
    env::var("KMS_ENDPOINT").ok()
}

fn get_ca_bundle() -> Option<String> {
    env::var("AWS_CA_BUNDLE").ok().and_then(|path| {
        fs::read_to_string(&path).ok()
    })
}

fn get_credentials() -> Result<(String, String, Option<String>)> {
    let access_key = env::var("AWS_ACCESS_KEY_ID")
        .map_err(|_| CliError::MissingEnvVar("AWS_ACCESS_KEY_ID".into()))?;
    let secret_key = env::var("AWS_SECRET_ACCESS_KEY")
        .map_err(|_| CliError::MissingEnvVar("AWS_SECRET_ACCESS_KEY".into()))?;
    let session_token = env::var("AWS_SESSION_TOKEN").ok();
    
    Ok((access_key, secret_key, session_token))
}

fn create_kms_client() -> Result<KmsClient> {
    let allocator = AwsAllocator::default()?;
    let region = AwsString::new(&allocator, &get_kms_region()?)?;
    let (access_key, secret_key, session_token) = get_credentials()?;
    
    let access_key_id = AwsString::new(&allocator, &access_key)?;
    let secret_access_key = AwsString::new(&allocator, &secret_key)?;
    let session_token_str = session_token.as_deref()
        .map(|s| AwsString::new(&allocator, s))
        .transpose()?;
    
    let endpoint_str = get_kms_endpoint();
    let port = get_proxy_port()?;
    
    let config = KmsClientConfig::default(
        &region,
        &access_key_id,
        &secret_access_key,
        session_token_str.as_ref(),
        endpoint_str.as_deref(),
        port,
    )?;
    
    Ok(KmsClient::new(config)?)
}

fn decrypt_command(ciphertext: &str) -> Result<()> {
    info!("Decrypting ciphertext");
    
    let allocator = AwsAllocator::default()?;
    let client = create_kms_client()?;
    
    // Decode base64 ciphertext
    let ciphertext_bytes = base64::engine::general_purpose::STANDARD.decode(ciphertext)?;
    let ciphertext_buf = AwsByteBuffer::from_slice(&allocator, &ciphertext_bytes)?;
    
    // Prepare output buffer
    let mut plaintext_buf = AwsByteBuffer::new(&allocator, 4096)?;
    
    // Perform decryption
    client.decrypt(None, None, &ciphertext_buf, &mut plaintext_buf)?;
    
    // Output plaintext
    io::stdout().write_all(plaintext_buf.as_slice())?;
    io::stdout().flush()?;
    
    Ok(())
}

fn genkey_command(cmk: &str, key_spec: &str) -> Result<()> {
    info!("Generating data key");
    
    let allocator = AwsAllocator::default()?;
    let client = create_kms_client()?;
    
    let cmk_string = AwsString::new(&allocator, cmk)?;
    let key_spec_enum = match key_spec {
        "AES_256" => aws_key_spec_AWS_KS_AES_256,
        "AES_128" => aws_key_spec_AWS_KS_AES_128,
        _ => return Err(CliError::from(NitroEnclavesError::InvalidParameter)),
    };
    
    let mut plaintext_buf = AwsByteBuffer::new(&allocator, 256)?;
    let mut ciphertext_buf = AwsByteBuffer::new(&allocator, 512)?;
    
    client.generate_data_key(&cmk_string, key_spec_enum, &mut plaintext_buf, &mut ciphertext_buf)?;
    
    // Output as JSON
    let result = serde_json::json!({
        "plaintext": base64::engine::general_purpose::STANDARD.encode(plaintext_buf.as_slice()),
        "ciphertext": base64::engine::general_purpose::STANDARD.encode(ciphertext_buf.as_slice()),
    });
    
    println!("{}", serde_json::to_string_pretty(&result)?);
    
    Ok(())
}

fn genrandom_command(num_bytes: u32) -> Result<()> {
    info!("Generating {} random bytes", num_bytes);
    
    let allocator = AwsAllocator::default()?;
    let client = create_kms_client()?;
    
    let mut random_buf = AwsByteBuffer::new(&allocator, num_bytes as usize)?;
    
    client.generate_random(num_bytes, &mut random_buf)?;
    
    // Output as hex
    println!("{}", hex::encode(random_buf.as_slice()));
    
    Ok(())
}

fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .init();
    
    // Initialize AWS SDK
    let allocator = AwsAllocator::default()
        .expect("Failed to create allocator");
    init(&allocator);
    
    // Seed entropy
    if let Err(e) = seed_entropy(256) {
        error!("Failed to seed entropy: {}", e);
    }
    
    let cli = Cli::parse();
    
    let result = match cli.command {
        Commands::Decrypt { ciphertext } => decrypt_command(&ciphertext),
        Commands::GenKey { cmk, key_spec } => genkey_command(&cmk, &key_spec),
        Commands::GenRandom { num_bytes } => genrandom_command(num_bytes),
    };
    
    // Cleanup
    cleanup();
    
    result
}