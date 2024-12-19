use cfg_aliases::cfg_aliases;

fn main() {
    cfg_aliases! {
        // Platforms
        arm: { target_arch = "arm" },
        aarch64: { target_arch = "aarch64" },
        riscv64: { target_arch = "riscv64" },
        x86_64: { target_arch = "x86_64" },
        linux: { target_os = "linux" },
        // exclusive features
        linux_aarch64: { all(linux, aarch64) },
        linux_riscv64: { all(linux, riscv64) },
        linux_x86_64: { all(linux, x86_64) },
        linux_arm: { all(linux, arm) },
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
