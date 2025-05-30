# Project Restructure

This project has been restructured to make the Rust implementation the primary focus, while preserving the original C SDK as a dependency library.

## New Structure

```
/ (Root - Rust Nitro Enclaves KMS Tools)
├── Cargo.toml                    # Workspace configuration
├── build.sh                      # Build script for Rust tools
├── docker-build.sh               # Docker build script
├── Dockerfile.al2                # Docker configuration
├── README.md                     # Rust tools documentation
├── kmstool-enclave/              # Enclave server (Rust)
├── kmstool-enclave-cli/          # Enclave CLI tool (Rust)
├── kmstool-instance/             # Instance client (Rust)
├── nitro-enclaves-ffi/           # FFI bindings to C SDK
└── libs/                         # Original C SDK and tools
    ├── include/                  # C SDK headers
    ├── source/                   # C SDK source code
    ├── bin/                      # Original C tools
    ├── cmake/                    # Build configuration
    ├── docs/                     # Documentation
    └── tests/                    # C SDK tests
```

## Changes Made

### File Movements
- All original AWS Nitro Enclaves C SDK content moved to `libs/` directory
- Rust implementation moved from `rust-nitro-enclaves-kms-tools/` to root directory
- Updated all path references in build files and configurations

### Path Updates
- `nitro-enclaves-ffi/build.rs`: Updated include path from `../../include` to `../libs/include`
- `Dockerfile.al2`: Updated to copy libs separately and build Rust tools at root level
- Build scripts updated to work from root directory instead of subdirectory

### Library Initialization Fix
- Fixed critical issue where `aws_nitro_enclaves_get_allocator()` was called before library initialization
- Added `init_with_null()` function to initialize library with NULL allocator like C version
- Updated main.rs to call library initialization before getting allocator

### Enhanced Debugging
- Added comprehensive debug output throughout KMS client creation process
- Enhanced error reporting with AWS error codes and messages
- Added detailed configuration field validation and logging

## Building

The build process remains the same from the user perspective:

```bash
# Native build (requires AWS C SDK dependencies)
cargo build --release

# Docker build (recommended - includes all dependencies)  
docker build -f Dockerfile.al2 -t rust-kmstool .

# Or use the build scripts
./build.sh              # Native build
./docker-build.sh       # Docker build
```

## Compatibility

- All existing functionality preserved
- Docker builds work identically to before
- C SDK remains available in `libs/` for reference or building C tools
- FFI bindings automatically reference correct header paths

This restructure makes the project more intuitive for Rust developers while maintaining full compatibility with the original C implementation.