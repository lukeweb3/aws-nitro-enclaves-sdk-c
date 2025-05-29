use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=wrapper.h");
    
    // Link AWS Nitro Enclaves libraries
    println!("cargo:rustc-link-lib=aws-nitro-enclaves-sdk-c");
    println!("cargo:rustc-link-lib=aws-c-auth");
    println!("cargo:rustc-link-lib=aws-c-cal");
    println!("cargo:rustc-link-lib=aws-c-common");
    println!("cargo:rustc-link-lib=aws-c-compression");
    println!("cargo:rustc-link-lib=aws-c-http");
    println!("cargo:rustc-link-lib=aws-c-io");
    println!("cargo:rustc-link-lib=aws-c-sdkutils");
    println!("cargo:rustc-link-lib=s2n");
    println!("cargo:rustc-link-lib=json-c");
    println!("cargo:rustc-link-lib=nsm");
    
    // Link OpenSSL/crypto libraries
    println!("cargo:rustc-link-lib=ssl");
    println!("cargo:rustc-link-lib=crypto");
    
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
        .allowlist_type("aws_.*")
        .allowlist_var("AWS_.*")
        .generate()
        .expect("Unable to generate bindings");
    
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}