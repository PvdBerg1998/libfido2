fn main() {
    if cfg!(target_os = "windows") {
        let lib_dir = std::env::var("FIDO2_LIB_DIR")
            .expect("Please set the FIDO2_LIB_DIR environment variable");
        println!("cargo:rustc-link-search=native={}", lib_dir);
        println!("cargo:rustc-link-lib=static=fido2");
    } else if cfg!(target_os = "linux") {
        println!("cargo:rustc-link-lib=dylib=fido2");
    } else if cfg!(target_os = "macos") {
        println!("cargo:rustc-link-lib=static=fido2");
    } else {
        panic!("Unsupported platform");
    }
}
