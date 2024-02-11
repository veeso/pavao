use cfg_aliases::cfg_aliases;

fn main() {
    cfg_aliases! {
        // Platforms
        aarch64: { target_arch = "aarch64" },
        riscv64: { target_arch = "riscv64" },
        x86_64: { target_arch = "x86_64" },
        macos: { target_os = "macos" },
        linux: { target_os = "linux" },
        unix: { target_family = "unix" },
        // exclusive features
        linux_aarch64: { all(linux, aarch64) },
        linux_riscv64: { all(linux, riscv64) },
        linux_x86_64: { all(linux, x86_64) }
    }

    match pkg_config::find_library("smbclient") {
        Ok(_) => {
            if cfg!(target_os = "macos") {
                println!("cargo:rustc-flags=-L /usr/local/lib -l smbclient");
            } else {
                println!("cargo:rustc-flags=-l smbclient");
            }
        }
        Err(e) => {
            println!(
                "error: SMB Client library not found! Probably libsmbclient is not installed."
            );
            panic!("{}", e);
        }
    };
}
