#!/bin/bash
set -e

echo "Building Rust Nitro Enclaves KMS Tools Docker images (no cache)..."

# Build all stages with --no-cache to ensure fresh build
docker build --no-cache -f Dockerfile.al2 --target kmstool-enclave-rust -t kmstool-enclave-rust:latest .
docker build --no-cache -f Dockerfile.al2 --target kmstool-instance-rust -t kmstool-instance-rust:latest .
docker build --no-cache -f Dockerfile.al2 --target kmstool-enclave-cli-rust -t kmstool-enclave-cli-rust:latest .
docker build --no-cache -f Dockerfile.al2 --target development -t nitro-enclaves-rust-dev:latest .

echo "Build complete!"
echo ""
echo "Available images:"
echo "  - kmstool-enclave-rust:latest    (for running in enclave)"
echo "  - kmstool-instance-rust:latest   (for running on EC2 instance)"
echo "  - kmstool-enclave-cli-rust:latest (CLI tool for enclave)"
echo "  - nitro-enclaves-rust-dev:latest  (development image with all tools)"
echo ""
echo "Example usage:"
echo "  docker run --rm kmstool-enclave-rust:latest"
echo "  docker run --rm -e AWS_REGION=us-east-1 kmstool-instance-rust:latest --help"