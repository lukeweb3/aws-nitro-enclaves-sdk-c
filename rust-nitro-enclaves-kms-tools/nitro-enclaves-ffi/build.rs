use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=wrapper.h");
    
    // Set library search paths
    println!("cargo:rustc-link-search=native=/usr/lib64");
    println!("cargo:rustc-link-search=native=/usr/lib");
    
    // Link AWS Nitro Enclaves libraries (order matters!)
    // For static libraries, dependencies must come AFTER the libraries that use them
    println!("cargo:rustc-link-lib=static=aws-nitro-enclaves-sdk-c");
    println!("cargo:rustc-link-lib=static=aws-c-auth");
    println!("cargo:rustc-link-lib=static=aws-c-http");
    println!("cargo:rustc-link-lib=static=aws-c-compression");
    println!("cargo:rustc-link-lib=static=aws-c-io");
    println!("cargo:rustc-link-lib=static=aws-c-cal");
    println!("cargo:rustc-link-lib=static=s2n");
    println!("cargo:rustc-link-lib=static=aws-c-sdkutils");
    println!("cargo:rustc-link-lib=static=aws-c-common");
    // AWS-LC is provided as libcrypto and libssl, not as libaws-lc
    println!("cargo:rustc-link-lib=static=crypto");
    println!("cargo:rustc-link-lib=static=ssl");
    println!("cargo:rustc-link-lib=static=json-c");
    println!("cargo:rustc-link-lib=nsm");
    
    // System libraries
    println!("cargo:rustc-link-lib=pthread");
    println!("cargo:rustc-link-lib=dl");
    println!("cargo:rustc-link-lib=m");
    
    // Generate bindings
    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_arg("-I../../include")
        .clang_arg("-I/usr/include")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .allowlist_function("aws_nitro_enclaves_.*")
        .allowlist_function("aws_kms_.*")
        .allowlist_function("aws_credentials_.*")
        .allowlist_function("aws_string_.*")
        .allowlist_function("aws_byte_buf_.*")
        .allowlist_function("aws_attestation_.*")
        .allowlist_function("aws_auth_library_.*")
        .allowlist_function("aws_credentials_provider_.*")
        .allowlist_function("aws_default_allocator")
        .allowlist_function("aws_last_error")
        .allowlist_function("aws_error_debug_str")
        .allowlist_function("aws_mem_calloc")
        .allowlist_function("aws_mem_release")
        .allowlist_type("aws_.*")
        .allowlist_var("AWS_.*")
        .generate()
        .expect("Unable to generate bindings");
    
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}