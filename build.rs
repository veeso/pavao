use cfg_aliases::cfg_aliases;

fn main() {
    cfg_aliases! {
        // Platforms
        aarch64: { target_arch = "aarch64" },
        android: { target_arch = "android" },
        arm: { target_arch = "arm" },
        riscv64: { target_arch = "riscv64" },
        x86_64: { target_arch = "x86_64" },
        linux: { target_os = "linux" },
        macos: { target_os = "macos" },
        // exclusive features
        linux_aarch64: { all(linux, aarch64, unix) },
        linux_riscv64: { all(linux, riscv64, unix) },
        linux_x86_64: { all(linux, x86_64, unix) },
        linux_arm: { all(linux, arm, unix) },
    }

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
