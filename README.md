# Rust Nitro Enclaves KMS Tools

This is a Rust implementation of the AWS Nitro Enclaves KMS tools, providing secure key management operations within AWS Nitro Enclaves.

## Components

### 1. nitro-enclaves-ffi
FFI bindings to the AWS Nitro Enclaves SDK C library. This provides safe Rust wrappers around all the C functions.

### 2. kmstool-enclave-cli
Command-line tool that runs inside the enclave for direct KMS operations:
- Decrypt ciphertext
- Generate data keys
- Generate random bytes

### 3. kmstool-enclave
Server that runs inside the enclave, listening on vsock for KMS requests from the parent instance.

### 4. kmstool-instance
Client that runs on the EC2 instance, connecting to the enclave server to perform KMS operations.

## Building

Prerequisites:
- Rust toolchain (1.70+)
- AWS Nitro Enclaves SDK C libraries installed
- Required system libraries: libnsm, aws-c-*, s2n, json-c

Build all components:
```bash
./build.sh
```

## Usage

### kmstool-enclave-cli
Inside the enclave:
```bash
# Decrypt data
kmstool_enclave_cli decrypt <base64-ciphertext>

# Generate data key
kmstool_enclave_cli genkey --cmk <key-id>

# Generate random bytes
kmstool_enclave_cli genrandom --num-bytes 32
```

### kmstool-enclave
Start the server inside the enclave:
```bash
# Default port 3000
kmstool_enclave

# Custom port
KMSTOOL_PORT=4000 kmstool_enclave
```

### kmstool-instance
From the parent EC2 instance:
```bash
# Basic usage
kmstool_instance --cid <enclave-cid> --ciphertext <base64-data>

# With encryption context
kmstool_instance --cid <enclave-cid> --ciphertext <base64-data> --encryption-context '{"key":"value"}'

# Read ciphertext from stdin
echo "<base64-ciphertext>" | kmstool_instance --cid <enclave-cid>
```

## Environment Variables

### Common
- `AWS_DEFAULT_REGION` or `AWS_REGION`: AWS region for KMS
- `AWS_ACCESS_KEY_ID`: AWS access key
- `AWS_SECRET_ACCESS_KEY`: AWS secret key
- `AWS_SESSION_TOKEN`: Optional session token
- `AWS_CA_BUNDLE`: Path to custom CA bundle

### kmstool-enclave-cli specific
- `VSOCK_PROXY_CID`: Proxy CID and port (format: "cid:port")
- `KMS_ENDPOINT`: Custom KMS endpoint

### kmstool-enclave specific
- `KMSTOOL_PORT`: Port to listen on (default: 3000)

### kmstool-instance specific
- `ENCLAVE_CID`: Default enclave CID if not provided via CLI

## Security Notes

1. All sensitive operations (decryption, key generation) happen inside the secure enclave
2. Credentials are never stored on disk within the enclave
3. Communication between instance and enclave uses vsock (virtio socket)
4. The enclave server validates all requests and maintains client state per connection

## License

Apache-2.0