#!/bin/bash
set -e

echo "Building Rust Nitro Enclaves KMS Tools..."

# Build all components
cargo build --release

# Create output directory
mkdir -p bin

# Copy binaries
cp target/release/kmstool_enclave_cli bin/
cp target/release/kmstool_enclave bin/
cp target/release/kmstool_instance bin/

echo "Build complete! Binaries are in the 'bin' directory."
echo ""
echo "Usage:"
echo "  - kmstool_enclave_cli: CLI tool for direct KMS operations in enclave"
echo "  - kmstool_enclave: Server that runs in enclave and handles KMS requests"
echo "  - kmstool_instance: Client that runs on EC2 instance and connects to enclave server"