fn main() {
    #[cfg(feature = "vendored")]
    {
        build_vendored();
    }
    #[cfg(not(feature = "vendored"))]
    {
        build_normal();
    }
}

#[allow(dead_code)]
fn build_normal() {
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

#[cfg(feature = "vendored")]
fn build_vendored() {
    let mut build = pavao_src::Build::new();

    println!("building vendored samba library... this may take several minutes");
    let artifacts = build.build();
    println!("cargo:vendored=1");
    println!(
        "cargo:root={}",
        artifacts.lib_dir.parent().unwrap().display()
    );

    if !artifacts.lib_dir.exists() {
        panic!(
            "samba library does not exist: {}",
            artifacts.lib_dir.display()
        );
    }
    if !artifacts.include_dir.exists() {
        panic!(
            "samba include directory does not exist: {}",
            artifacts.include_dir.display()
        );
    }

    println!(
        "cargo:rustc-link-search=native={}",
        artifacts.lib_dir.display()
    );
    println!("cargo:include={}", artifacts.include_dir.display());
    println!("cargo:rustc-link-lib=static=smbclient");

    // add further dependencies
    println!("cargo:rustc-link-lib=z");
    println!("cargo:rustc-link-lib=ldap");
    println!("cargo:rustc-link-lib=cups");
    println!("cargo:rustc-link-lib=lber");
    println!("cargo:rustc-link-lib=jansson");
    println!("cargo:rustc-link-lib=icui18n");
    println!("cargo:rustc-link-lib=icuuc");
    println!("cargo:rustc-link-lib=gnutls");
    println!("cargo:rustc-link-lib=cap");
    println!("cargo:rustc-link-lib=bsd");
    println!("cargo:rustc-link-lib=resolv");
    println!("cargo:rustc-link-lib=keyutils");
}
