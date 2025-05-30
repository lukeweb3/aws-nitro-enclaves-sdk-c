#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use std::ffi::CString;
use std::ptr;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum NitroEnclavesError {
    #[error("FFI string conversion error")]
    StringConversion,
    #[error("AWS SDK error: {0}")]
    AwsError(i32),
    #[error("Null pointer error")]
    NullPointer,
    #[error("Invalid parameter")]
    InvalidParameter,
}

pub type Result<T> = std::result::Result<T, NitroEnclavesError>;

// Safe wrapper for AWS allocator
pub struct AwsAllocator {
    allocator: *mut aws_allocator,
}

impl AwsAllocator {
    pub fn default() -> Result<Self> {
        unsafe {
            eprintln!("AwsAllocator::default - Attempting to get nitro enclaves allocator...");
            // Use nitro enclaves allocator first like C version does
            let allocator = aws_nitro_enclaves_get_allocator();
            if !allocator.is_null() {
                eprintln!("AwsAllocator::default - Successfully using nitro enclaves allocator: {:?}", allocator);
                return Ok(Self { allocator });
            }
            
            eprintln!("AwsAllocator::default - Nitro enclaves allocator is null, trying default allocator...");
            // Fall back to default allocator if nitro enclaves allocator not available
            let allocator = aws_default_allocator();
            if allocator.is_null() {
                eprintln!("AwsAllocator::default - ERROR: Both allocators are null! Library may not be initialized.");
                return Err(NitroEnclavesError::NullPointer);
            }
            
            eprintln!("AwsAllocator::default - Using default allocator: {:?}", allocator);
            Ok(Self { allocator })
        }
    }
    
    pub fn as_ptr(&self) -> *mut aws_allocator {
        self.allocator
    }
}

// Safe wrapper for AWS string
pub struct AwsString {
    string: *mut aws_string,
    #[allow(dead_code)]
    allocator: *mut aws_allocator,
}

impl AwsString {
    pub fn new(allocator: &AwsAllocator, s: &str) -> Result<Self> {
        let c_str = CString::new(s).map_err(|_| NitroEnclavesError::StringConversion)?;
        unsafe {
            let aws_str = aws_string_new_from_c_str(allocator.as_ptr(), c_str.as_ptr());
            if aws_str.is_null() {
                return Err(NitroEnclavesError::NullPointer);
            }
            Ok(Self {
                string: aws_str,
                allocator: allocator.as_ptr(),
            })
        }
    }
    
    pub fn as_ptr(&self) -> *const aws_string {
        self.string
    }
}

impl Drop for AwsString {
    fn drop(&mut self) {
        unsafe {
            if !self.string.is_null() {
                aws_string_destroy(self.string);
            }
        }
    }
}

// Safe wrapper for AWS byte buffer
pub struct AwsByteBuffer {
    buffer: aws_byte_buf,
    #[allow(dead_code)]
    allocator: *mut aws_allocator,
}

impl AwsByteBuffer {
    pub fn new(allocator: &AwsAllocator, capacity: usize) -> Result<Self> {
        let mut buffer = unsafe { std::mem::zeroed::<aws_byte_buf>() };
        
        unsafe {
            let result = aws_byte_buf_init(&mut buffer, allocator.as_ptr(), capacity);
            if result != 0 {
                return Err(NitroEnclavesError::AwsError(result));
            }
        }
        
        Ok(Self {
            buffer,
            allocator: allocator.as_ptr(),
        })
    }
    
    pub fn from_slice(allocator: &AwsAllocator, data: &[u8]) -> Result<Self> {
        let mut buf = Self::new(allocator, data.len())?;
        buf.write(data)?;
        Ok(buf)
    }
    
    pub fn write(&mut self, data: &[u8]) -> Result<()> {
        if data.len() > self.buffer.capacity - self.buffer.len {
            return Err(NitroEnclavesError::InvalidParameter);
        }
        
        unsafe {
            ptr::copy_nonoverlapping(
                data.as_ptr(),
                self.buffer.buffer.add(self.buffer.len),
                data.len(),
            );
            self.buffer.len += data.len();
        }
        Ok(())
    }
    
    pub fn as_slice(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(self.buffer.buffer, self.buffer.len)
        }
    }
    
    pub fn as_mut_ptr(&mut self) -> *mut aws_byte_buf {
        &mut self.buffer
    }
    
    pub fn len(&self) -> usize {
        self.buffer.len
    }
}

impl Drop for AwsByteBuffer {
    fn drop(&mut self) {
        unsafe {
            aws_byte_buf_clean_up(&mut self.buffer);
        }
    }
}

// Safe wrapper for AWS credentials
pub struct AwsCredentials {
    credentials: *mut aws_credentials,
}

impl AwsCredentials {
    pub fn new(
        allocator: &AwsAllocator,
        access_key_id: &str,
        secret_access_key: &str,
        session_token: Option<&str>,
    ) -> Result<Self> {
        let access_key_cursor = aws_byte_cursor_from_str(access_key_id);
        let secret_key_cursor = aws_byte_cursor_from_str(secret_access_key);
        let session_token_cursor = session_token.map(aws_byte_cursor_from_str)
            .unwrap_or_else(|| aws_byte_cursor {
                ptr: ptr::null_mut(),
                len: 0,
            });
        
        unsafe {
            let credentials = aws_credentials_new(
                allocator.as_ptr(),
                access_key_cursor,
                secret_key_cursor,
                session_token_cursor,
                u64::MAX, // No expiration
            );
            
            if credentials.is_null() {
                return Err(NitroEnclavesError::NullPointer);
            }
            
            Ok(Self { credentials })
        }
    }
    
    pub fn as_ptr(&self) -> *const aws_credentials {
        self.credentials
    }
}

impl Drop for AwsCredentials {
    fn drop(&mut self) {
        unsafe {
            if !self.credentials.is_null() {
                aws_credentials_release(self.credentials);
            }
        }
    }
}

// KMS Client wrapper
pub struct KmsClient {
    client: *mut aws_nitro_enclaves_kms_client,
}

impl KmsClient {
    pub fn new(config: KmsClientConfig) -> Result<Self> {
        eprintln!("KmsClient::new - Creating KMS client");
        eprintln!("KmsClient::new - Config pointer: {:?}", config.config);
        
        unsafe {
            // Debug: Print config fields in detail
            if !config.config.is_null() {
                eprintln!("KmsClient::new - Detailed config inspection:");
                eprintln!("  config.allocator: {:?}", (*config.config).allocator);
                eprintln!("  config.region: {:?}", (*config.config).region);
                eprintln!("  config.endpoint: {:?}", (*config.config).endpoint);
                eprintln!("  config.domain: {}", (*config.config).domain);
                eprintln!("  config.credentials: {:?}", (*config.config).credentials);
                eprintln!("  config.credentials_provider: {:?}", (*config.config).credentials_provider);
                eprintln!("  config.host_name: {:?}", (*config.config).host_name);
                
                // Validate region string content
                if !(*config.config).region.is_null() {
                    eprintln!("KmsClient::new - Region string is valid, checking content...");
                    // Try to read region string length or content safely
                } else {
                    eprintln!("KmsClient::new - ERROR: Region string is null!");
                }
                
                // Validate credentials content
                if !(*config.config).credentials.is_null() {
                    eprintln!("KmsClient::new - Credentials object is valid");
                } else {
                    eprintln!("KmsClient::new - ERROR: Credentials object is null!");
                }
                
                // Validate endpoint content
                if !(*config.config).endpoint.is_null() {
                    let endpoint = (*config.config).endpoint;
                    eprintln!("KmsClient::new - Endpoint details:");
                    eprintln!("    address: {:?}", 
                        std::str::from_utf8(std::slice::from_raw_parts((*endpoint).address.as_ptr() as *const u8, 2)).unwrap_or("invalid"));
                    eprintln!("    port: {}", (*endpoint).port);
                } else {
                    eprintln!("KmsClient::new - ERROR: Endpoint is null!");
                }
                
                // Validate allocator
                if (*config.config).allocator.is_null() {
                    eprintln!("KmsClient::new - WARNING: Allocator is null (will use default)");
                }
            } else {
                eprintln!("KmsClient::new - ERROR: Config is null!");
                return Err(NitroEnclavesError::NullPointer);
            }
            
            eprintln!("KmsClient::new - About to call aws_nitro_enclaves_kms_client_new...");
            let client = aws_nitro_enclaves_kms_client_new(config.config);
            eprintln!("KmsClient::new - aws_nitro_enclaves_kms_client_new returned: {:?}", client);
            
            if client.is_null() {
                eprintln!("KmsClient::new - ERROR: Client is null!");
                // Try to get AWS error
                let error_code = aws_last_error();
                eprintln!("KmsClient::new - AWS last error code: {}", error_code);
                if error_code != 0 {
                    let error_str = aws_error_debug_str(error_code);
                    if !error_str.is_null() {
                        let c_str = std::ffi::CStr::from_ptr(error_str);
                        eprintln!("KmsClient::new - AWS error: {:?}", c_str);
                    } else {
                        eprintln!("KmsClient::new - AWS error string is null");
                    }
                } else {
                    eprintln!("KmsClient::new - No AWS error code set");
                }
                return Err(NitroEnclavesError::NullPointer);
            }
            
            eprintln!("KmsClient::new - Client created successfully at: {:?}", client);
            Ok(Self { client })
        }
    }
    
    pub fn decrypt(
        &self,
        key_id: Option<&AwsString>,
        encryption_algorithm: Option<&AwsString>,
        ciphertext: &AwsByteBuffer,
        plaintext: &mut AwsByteBuffer,
    ) -> Result<()> {
        eprintln!("KmsClient::decrypt - Starting decrypt operation");
        eprintln!("KmsClient::decrypt - Ciphertext size: {}", ciphertext.len());
        
        unsafe {
            let result = aws_kms_decrypt_blocking(
                self.client,
                key_id.map(|s| s.as_ptr()).unwrap_or(ptr::null()),
                encryption_algorithm.map(|s| s.as_ptr()).unwrap_or(ptr::null()),
                &ciphertext.buffer as *const _,
                plaintext.as_mut_ptr(),
            );
            
            eprintln!("KmsClient::decrypt - Result: {}", result);
            
            if result != 0 {
                eprintln!("KmsClient::decrypt - ERROR: Decrypt failed with code {}", result);
                // Try to get more error info
                let error_code = aws_last_error();
                eprintln!("KmsClient::decrypt - AWS last error code: {}", error_code);
                if error_code != 0 {
                    let error_str = aws_error_debug_str(error_code);
                    if !error_str.is_null() {
                        let c_str = std::ffi::CStr::from_ptr(error_str);
                        eprintln!("KmsClient::decrypt - AWS error: {:?}", c_str);
                    }
                }
                return Err(NitroEnclavesError::AwsError(result));
            }
            
            eprintln!("KmsClient::decrypt - Success, plaintext size: {}", plaintext.len());
            Ok(())
        }
    }
    
    pub fn decrypt_with_context(
        &self,
        key_id: Option<&AwsString>,
        encryption_algorithm: Option<&AwsString>,
        ciphertext: &AwsByteBuffer,
        encryption_context: &AwsString,
        plaintext: &mut AwsByteBuffer,
    ) -> Result<()> {
        unsafe {
            let result = aws_kms_decrypt_blocking_with_context(
                self.client,
                key_id.map(|s| s.as_ptr()).unwrap_or(ptr::null()),
                encryption_algorithm.map(|s| s.as_ptr()).unwrap_or(ptr::null()),
                &ciphertext.buffer as *const _,
                encryption_context.as_ptr(),
                plaintext.as_mut_ptr(),
            );
            
            if result != 0 {
                return Err(NitroEnclavesError::AwsError(result));
            }
            Ok(())
        }
    }
    
    pub fn generate_data_key(
        &self,
        key_id: &AwsString,
        key_spec: aws_key_spec,
        plaintext: &mut AwsByteBuffer,
        ciphertext: &mut AwsByteBuffer,
    ) -> Result<()> {
        eprintln!("KmsClient::generate_data_key - Starting generate data key operation");
        eprintln!("KmsClient::generate_data_key - Key spec: {}", key_spec);
        
        unsafe {
            eprintln!("KmsClient::generate_data_key - Calling aws_kms_generate_data_key_blocking");
            let result = aws_kms_generate_data_key_blocking(
                self.client,
                key_id.as_ptr(),
                key_spec,
                plaintext.as_mut_ptr(),
                ciphertext.as_mut_ptr(),
            );
            
            eprintln!("KmsClient::generate_data_key - Result: {}", result);
            
            if result != 0 {
                eprintln!("KmsClient::generate_data_key - ERROR: Generate data key failed with code {}", result);
                // Try to get more error info
                let error_code = aws_last_error();
                eprintln!("KmsClient::generate_data_key - AWS last error code: {}", error_code);
                if error_code != 0 {
                    let error_str = aws_error_debug_str(error_code);
                    if !error_str.is_null() {
                        let c_str = std::ffi::CStr::from_ptr(error_str);
                        eprintln!("KmsClient::generate_data_key - AWS error: {:?}", c_str);
                    }
                }
                return Err(NitroEnclavesError::AwsError(result));
            }
            
            eprintln!("KmsClient::generate_data_key - Success, plaintext size: {}, ciphertext size: {}", 
                plaintext.len(), ciphertext.len());
            Ok(())
        }
    }
    
    pub fn generate_random(&self, num_bytes: u32, output: &mut AwsByteBuffer) -> Result<()> {
        unsafe {
            let result = aws_kms_generate_random_blocking(
                self.client,
                num_bytes,
                output.as_mut_ptr(),
            );
            
            if result != 0 {
                return Err(NitroEnclavesError::AwsError(result));
            }
            Ok(())
        }
    }
}

impl Drop for KmsClient {
    fn drop(&mut self) {
        unsafe {
            if !self.client.is_null() {
                aws_nitro_enclaves_kms_client_destroy(self.client);
            }
        }
    }
}

// KMS Client Configuration wrapper
pub struct KmsClientConfig {
    config: *mut aws_nitro_enclaves_kms_client_configuration,
    // Keep references to strings to ensure they don't get dropped
    _region: Option<AwsString>,
    _access_key: Option<AwsString>,
    _secret_key: Option<AwsString>,
    _session_token: Option<AwsString>,
    // Track if we manually allocated memory
    manually_allocated: bool,
    allocator: Option<*mut aws_allocator>,
}

impl KmsClientConfig {
    pub fn default(
        region: &AwsString,
        access_key_id: &AwsString,
        secret_access_key: &AwsString,
        session_token: Option<&AwsString>,
        endpoint: Option<&str>,
        port: u16,
    ) -> Result<Self> {
        unsafe {
            // Create socket endpoint if provided
            let mut socket_endpoint = endpoint.map(|ep| {
                let mut se: aws_socket_endpoint = std::mem::zeroed();
                let ep_cstring = CString::new(ep).unwrap();
                let ep_bytes = ep_cstring.as_bytes_with_nul();
                // Copy the endpoint string to the address array
                let copy_len = ep_bytes.len().min(se.address.len());
                ptr::copy_nonoverlapping(
                    ep_bytes.as_ptr() as *const i8,
                    se.address.as_mut_ptr(),
                    copy_len
                );
                se.port = port;
                se
            });
            
            let config = aws_nitro_enclaves_kms_client_config_default(
                region.as_ptr() as *mut _,
                socket_endpoint.as_mut().map(|se| se as *mut _).unwrap_or(ptr::null_mut()),
                0, // AWS_SOCKET_IPV4
                access_key_id.as_ptr() as *mut _,
                secret_access_key.as_ptr() as *mut _,
                session_token.map(|s| s.as_ptr() as *mut _).unwrap_or(ptr::null_mut()),
            );
            
            if config.is_null() {
                return Err(NitroEnclavesError::NullPointer);
            }
            
            Ok(Self { 
                config,
                _region: None,
                _access_key: None,
                _secret_key: None,
                _session_token: None,
                manually_allocated: false,
                allocator: None,
            })
        }
    }
    
    // Create configuration like C version does - use stack allocation like C
    pub fn vsock(
        allocator: &AwsAllocator,
        region: &AwsString,
        credentials: &AwsCredentials,
        vsock_cid: &str,
        port: u16,
    ) -> Result<Self> {
        eprintln!("KmsClientConfig::vsock - Creating stack-based vsock config with CID: {}, port: {}", vsock_cid, port);
        eprintln!("KmsClientConfig::vsock - Input allocator: {:?}", allocator.as_ptr());
        eprintln!("KmsClientConfig::vsock - Input region: {:?}", region.as_ptr());
        eprintln!("KmsClientConfig::vsock - Input credentials: {:?}", credentials.as_ptr());
        
        unsafe {
            // Create endpoint on stack like C version
            let mut endpoint: aws_socket_endpoint = std::mem::zeroed();
            let cid_cstring = CString::new(vsock_cid).unwrap();
            let cid_bytes = cid_cstring.as_bytes_with_nul();
            let copy_len = cid_bytes.len().min(endpoint.address.len());
            eprintln!("KmsClientConfig::vsock - Copying CID '{}' ({} bytes) to stack endpoint", vsock_cid, copy_len);
            ptr::copy_nonoverlapping(
                cid_bytes.as_ptr() as *const i8,
                endpoint.address.as_mut_ptr(),
                copy_len
            );
            endpoint.port = port;
            
            eprintln!("KmsClientConfig::vsock - Stack endpoint configured: address={:?}, port={}", 
                std::str::from_utf8(std::slice::from_raw_parts(endpoint.address.as_ptr() as *const u8, copy_len-1)).unwrap_or("invalid"),
                endpoint.port);
            
            // Allocate persistent endpoint storage
            let endpoint_ptr = aws_mem_calloc(
                allocator.as_ptr(),
                1,
                std::mem::size_of::<aws_socket_endpoint>()
            ) as *mut aws_socket_endpoint;
            
            if endpoint_ptr.is_null() {
                eprintln!("KmsClientConfig::vsock - ERROR: Failed to allocate persistent endpoint");
                return Err(NitroEnclavesError::NullPointer);
            }
            
            // Copy stack endpoint to persistent storage
            ptr::copy_nonoverlapping(&endpoint, endpoint_ptr, 1);
            
            // Create configuration on stack like C version, then copy to heap for persistence
            let mut config: aws_nitro_enclaves_kms_client_configuration = std::mem::zeroed();
            config.allocator = allocator.as_ptr();
            config.region = region.as_ptr();
            config.endpoint = endpoint_ptr;
            config.domain = 3; // AWS_SOCKET_VSOCK
            config.credentials = credentials.as_ptr() as *mut _;
            config.credentials_provider = ptr::null_mut();
            config.host_name = ptr::null();
            
            eprintln!("KmsClientConfig::vsock - Stack configuration initialized:");
            eprintln!("  allocator: {:?}", config.allocator);
            eprintln!("  region: {:?}", config.region);
            eprintln!("  endpoint: {:?}", config.endpoint);
            eprintln!("  domain: {}", config.domain);
            eprintln!("  credentials: {:?}", config.credentials);
            eprintln!("  credentials_provider: {:?}", config.credentials_provider);
            eprintln!("  host_name: {:?}", config.host_name);
            
            // Allocate persistent config storage
            let config_ptr = aws_mem_calloc(
                allocator.as_ptr(),
                1,
                std::mem::size_of::<aws_nitro_enclaves_kms_client_configuration>()
            ) as *mut aws_nitro_enclaves_kms_client_configuration;
            
            if config_ptr.is_null() {
                eprintln!("KmsClientConfig::vsock - ERROR: Failed to allocate persistent config");
                aws_mem_release(allocator.as_ptr(), endpoint_ptr as *mut _);
                return Err(NitroEnclavesError::NullPointer);
            }
            
            // Copy stack config to persistent storage
            ptr::copy_nonoverlapping(&config, config_ptr, 1);
            
            eprintln!("KmsClientConfig::vsock - Persistent config created at: {:?}", config_ptr);
            
            // Final validation
            if (*config_ptr).region.is_null() {
                eprintln!("KmsClientConfig::vsock - ERROR: Region is null in persistent config!");
                aws_mem_release(allocator.as_ptr(), endpoint_ptr as *mut _);
                aws_mem_release(allocator.as_ptr(), config_ptr as *mut _);
                return Err(NitroEnclavesError::NullPointer);
            }
            
            if (*config_ptr).credentials.is_null() {
                eprintln!("KmsClientConfig::vsock - ERROR: Credentials is null in persistent config!");
                aws_mem_release(allocator.as_ptr(), endpoint_ptr as *mut _);
                aws_mem_release(allocator.as_ptr(), config_ptr as *mut _);
                return Err(NitroEnclavesError::NullPointer);
            }
            
            eprintln!("KmsClientConfig::vsock - Stack-based config created successfully");
            
            Ok(Self { 
                config: config_ptr,
                _region: None,
                _access_key: None,
                _secret_key: None,
                _session_token: None,
                manually_allocated: true,
                allocator: Some(allocator.as_ptr()),
            })
        }
    }
    
    // Create configuration manually like C version does
    pub fn vsock_manual(
        allocator: &AwsAllocator,
        region: &AwsString,
        credentials: &AwsCredentials,
        vsock_cid: &str,
        port: u16,
        host_name: Option<&AwsString>,
    ) -> Result<Self> {
        eprintln!("KmsClientConfig::vsock_manual - Creating manual vsock config");
        eprintln!("KmsClientConfig::vsock_manual - Allocator: {:?}", allocator.as_ptr());
        eprintln!("KmsClientConfig::vsock_manual - Region: {:?}", region.as_ptr());
        eprintln!("KmsClientConfig::vsock_manual - Credentials: {:?}", credentials.as_ptr());
        
        // Actually, let's just use the working default function but with correct domain
        // The manual approach might have memory management issues
        
        // Create copies of strings that will persist
        let region_copy = AwsString::new(allocator, &format!("{}", 
            unsafe { std::ffi::CStr::from_ptr(region.as_ptr() as *const i8).to_string_lossy() }))?;
        let access_key_copy = AwsString::new(allocator, "dummy")?; // We'll use credentials instead
        let secret_key_copy = AwsString::new(allocator, "dummy")?; // We'll use credentials instead
        
        unsafe {
            // Create vsock endpoint
            let mut socket_endpoint: aws_socket_endpoint = std::mem::zeroed();
            let cid_cstring = CString::new(vsock_cid).unwrap();
            let cid_bytes = cid_cstring.as_bytes_with_nul();
            let copy_len = cid_bytes.len().min(socket_endpoint.address.len());
            ptr::copy_nonoverlapping(
                cid_bytes.as_ptr() as *const i8,
                socket_endpoint.address.as_mut_ptr(),
                copy_len
            );
            socket_endpoint.port = port;
            
            eprintln!("KmsClientConfig::vsock_manual - Calling aws_nitro_enclaves_kms_client_config_default");
            
            // Use the default function but override some fields afterward
            let config = aws_nitro_enclaves_kms_client_config_default(
                region_copy.as_ptr() as *mut _,
                &mut socket_endpoint as *mut _,
                3, // AWS_SOCKET_VSOCK
                access_key_copy.as_ptr() as *mut _,
                secret_key_copy.as_ptr() as *mut _,
                ptr::null_mut(), // no session token
            );
            
            eprintln!("KmsClientConfig::vsock_manual - Config pointer: {:?}", config);
            
            if config.is_null() {
                eprintln!("KmsClientConfig::vsock_manual - ERROR: Config is null!");
                return Err(NitroEnclavesError::NullPointer);
            }
            
            // Override with the real credentials
            (*config).credentials = credentials.as_ptr() as *mut _;
            if let Some(hn) = host_name {
                (*config).host_name = hn.as_ptr();
            }
            
            eprintln!("KmsClientConfig::vsock_manual - Config created successfully");
            Ok(Self { 
                config,
                _region: Some(region_copy),
                _access_key: Some(access_key_copy),
                _secret_key: Some(secret_key_copy),
                _session_token: None,
                manually_allocated: false,
                allocator: None,
            })
        }
    }
}

impl Drop for KmsClientConfig {
    fn drop(&mut self) {
        unsafe {
            if !self.config.is_null() {
                if self.manually_allocated {
                    if let Some(allocator) = self.allocator {
                        // Free endpoint if it exists
                        if !(*self.config).endpoint.is_null() {
                            aws_mem_release(allocator, (*self.config).endpoint as *mut _);
                        }
                        // Free the config struct itself
                        aws_mem_release(allocator, self.config as *mut _);
                    }
                } else {
                    aws_nitro_enclaves_kms_client_config_destroy(self.config);
                }
            }
        }
    }
}

// Helper function to create aws_byte_cursor from string
fn aws_byte_cursor_from_str(s: &str) -> aws_byte_cursor {
    aws_byte_cursor {
        ptr: s.as_ptr() as *mut u8,
        len: s.len(),
    }
}

// Library initialization
pub fn init(allocator: &AwsAllocator) {
    unsafe {
        aws_nitro_enclaves_library_init(allocator.as_ptr());
    }
}

// Library initialization with NULL allocator (like C version does)
pub fn init_with_null() {
    unsafe {
        aws_nitro_enclaves_library_init(ptr::null_mut());
    }
}

pub fn cleanup() {
    unsafe {
        aws_nitro_enclaves_library_clean_up();
    }
}

pub fn seed_entropy(bytes: u64) -> Result<()> {
    unsafe {
        let result = aws_nitro_enclaves_library_seed_entropy(bytes);
        if result != 0 {
            return Err(NitroEnclavesError::AwsError(result));
        }
        Ok(())
    }
}