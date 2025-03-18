fn main() {
    match pkg_config::find_library("smbclient") {
        Ok(_) => {
            if cfg!(target_os = "macos") {
                if cfg!(target_arch = "aarch64") {
                    println!("cargo:rustc-link-search=/opt/homebrew/opt/samba/lib");
                } else if cfg!(target_arch = "x86_64") {
                    println!("cargo:rustc-link-search=/usr/local/Homebrew/opt/samba/lib");
                }
                println!("cargo:rustc-link-lib=smbclient");
            } else {
                println!("cargo:rustc-link-lib=smbclient");
            }
        }
        Err(e) => {
            println!(
                "error: SMB Client library not found! Make sure libsmbclient is installed. \
                For macOS, install it via Homebrew with `brew install samba`."
            );
            panic!("{}", e);
        }
    };
}
