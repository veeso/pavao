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

#[allow(dead_code)]
fn build_vendored() {
    #[cfg(feature = "vendored")]
    build_samba();

    // add further dependencies
    add_library("z", "zlib");
    add_library("ldap", "openldap");
    add_library("cups", "cups");
    add_library("lber", "openldap");
    add_library("jansson", "jansson");
    add_library("icui18n", "icu4c");
    add_library("icuuc", "icu4c");
    add_library("gnutls", "gnutls");
    add_library("bsd", "libbsd");
    add_library("resolv", "libresolv");

    // linux only
    if cfg!(target_os = "linux") {
        add_library("cap", "cap");
        add_library("keyutils", "keyutils");
    }

    // macOS only
    if cfg!(target_os = "macos") {
        add_library("gmp", "gmp");
        add_library("intl", "gettext");
        add_library("unistring", "libunistring");
    }
}

#[cfg(feature = "vendored")]
fn build_samba() {
    let mut build = pavao_src::Build::new();
    #[cfg(target_os = "macos")]
    {
        let gnutls_includes = get_includes("gnutls");
        build.gnutls(gnutls_includes);
    }

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
}

fn add_library(lib: &str, brew_name: &str) {
    // search lib with pkg-config and try static

    match pkg_config::Config::new()
        .statik(true)
        .cargo_metadata(true)
        .probe(lib)
    {
        Ok(_) => {
            if cfg!(target_os = "macos") {
                if cfg!(target_arch = "aarch64") {
                    println!("cargo:rustc-link-search=/opt/homebrew/opt/{brew_name}/lib");
                } else if cfg!(target_arch = "x86_64") {
                    println!("cargo:rustc-link-search=/usr/local/Homebrew/opt/{brew_name}/lib");
                }
                println!("cargo:rustc-link-lib={lib}");
            }
        }
        Err(_) => {
            println!("{lib} was not found with pkg_config; trying with LD_LIBRARY_PATH; but you may need to install it manually");
            // cross-finger and try dylib
            if cfg!(target_arch = "aarch64") {
                println!("cargo:rustc-link-search=/opt/homebrew/opt/{brew_name}/lib");
            } else if cfg!(target_arch = "x86_64") {
                println!("cargo:rustc-link-search=/usr/local/Homebrew/opt/{brew_name}/lib");
            }
            println!("cargo:rustc-link-lib={lib}");
        }
    };
}

#[cfg(all(target_os = "macos", feature = "vendored"))]
fn get_includes(lib_name: &str) -> Vec<std::path::PathBuf> {
    let lib = pkg_config::Config::new()
        .env_metadata(false)
        .cargo_metadata(false)
        .print_system_cflags(false)
        .print_system_libs(false)
        .probe(lib_name)
        .map_err(|e| format!("pkg_config probe {lib_name}: {e}"))
        .expect("Unable to get pkg-config for library");

    // PKG_CONFIG_PATH must be set to find gnutls on macOS homebrew installs
    if std::env::var_os("PKG_CONFIG_PATH").is_none() {
        panic!("PKG_CONFIG_PATH is not set");
    }

    // check if empty
    if lib.include_paths.is_empty() {
        panic!("no include paths found for {lib_name}");
    }

    // check if exist
    for path in &lib.include_paths {
        if !path.exists() {
            panic!(
                "include path {} for {lib_name} does not exist",
                path.display()
            );
        }
    }

    lib.include_paths
}
