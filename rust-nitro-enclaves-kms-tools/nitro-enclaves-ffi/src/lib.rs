#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
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
            let allocator = aws_nitro_enclaves_get_allocator();
            if allocator.is_null() {
                return Err(NitroEnclavesError::NullPointer);
            }
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
    allocator: *mut aws_allocator,
}

impl AwsByteBuffer {
    pub fn new(allocator: &AwsAllocator, capacity: usize) -> Result<Self> {
        let mut buffer = aws_byte_buf {
            allocator: ptr::null_mut(),
            buffer: ptr::null_mut(),
            len: 0,
            capacity: 0,
            _bitfield_align_1: Default::default(),
            _bitfield_1: Default::default(),
        };
        
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
        unsafe {
            let client = aws_nitro_enclaves_kms_client_new(config.config);
            if client.is_null() {
                return Err(NitroEnclavesError::NullPointer);
            }
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
        unsafe {
            let result = aws_kms_decrypt_blocking(
                self.client,
                key_id.map(|s| s.as_ptr()).unwrap_or(ptr::null()),
                encryption_algorithm.map(|s| s.as_ptr()).unwrap_or(ptr::null()),
                ciphertext.buffer as *const _,
                plaintext.as_mut_ptr(),
            );
            
            if result != 0 {
                return Err(NitroEnclavesError::AwsError(result));
            }
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
                ciphertext.buffer as *const _,
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
        unsafe {
            let result = aws_kms_generate_data_key_blocking(
                self.client,
                key_id.as_ptr(),
                key_spec,
                plaintext.as_mut_ptr(),
                ciphertext.as_mut_ptr(),
            );
            
            if result != 0 {
                return Err(NitroEnclavesError::AwsError(result));
            }
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
}

impl KmsClientConfig {
    pub fn default(
        region: &AwsString,
        credentials: &AwsCredentials,
        endpoint: Option<&AwsString>,
        port: u16,
        ca_cert: Option<&AwsString>,
    ) -> Result<Self> {
        unsafe {
            let config = aws_nitro_enclaves_kms_client_config_default(
                region.as_ptr(),
                credentials.as_ptr(),
                endpoint.map(|s| s.as_ptr()).unwrap_or(ptr::null()),
                port,
                ca_cert.map(|s| s.as_ptr()).unwrap_or(ptr::null()),
            );
            
            if config.is_null() {
                return Err(NitroEnclavesError::NullPointer);
            }
            
            Ok(Self { config })
        }
    }
}

impl Drop for KmsClientConfig {
    fn drop(&mut self) {
        unsafe {
            if !self.config.is_null() {
                aws_nitro_enclaves_kms_client_config_destroy(self.config);
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
pub fn init() {
    unsafe {
        aws_nitro_enclaves_library_init(aws_default_allocator());
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