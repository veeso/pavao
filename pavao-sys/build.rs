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
    let required_version = if cfg!(feature = "abi-0-8") {
        "0.8.0"
    } else if cfg!(feature = "abi-0-6") {
        "0.6.0"
    } else {
        "0.5.0"
    };

    match pkg_config::Config::new()
        .atleast_version(required_version)
        .probe("smbclient")
    {
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
                "error: libsmbclient ABI {required_version} or newer not found! \
                Pavão requires `smbc_setOptionProtocols`. Install libsmbclient and its \
                development files; on macOS run `brew install samba`."
            );
            panic!("{e}");
        }
    };
}

#[allow(dead_code)]
fn build_vendored() {
    #[cfg(feature = "vendored")]
    build_samba();

    // add further dependencies
    //
    // Only libraries the trimmed Samba `configure` in `pavao_src::Build` actually
    // links against belong here. `--without-ldap`, `--disable-cups`,
    // `--without-json`, `--disable-spotlight`, `--without-kernel-keyring`, and the
    // other feature flags mean libldap/lber, cups, jansson, icu, and keyutils are
    // never part of the static archive; libbsd and libcap are optional compat
    // shims Samba falls back away from when absent. Force-linking any of them
    // here would require them again for no reason.
    add_library("z", "zlib");
    add_library("gnutls", "gnutls");
    add_library("resolv", "libresolv");

    // Samba's `lib/util/charset/wscript_configure` probes `icu-i18n`/`icu-uc`
    // with no `./configure` flag to force it off: if both are present on the
    // build host, Samba compiles ICU-based UTF-8 normalisation into iconv.c
    // and this vendored build's static archive references ICU symbols whether
    // we like it or not. Mirror that same pkg-config probe here so linking
    // ICU stays in sync with whatever Samba's own configure decided, instead
    // of guessing based on what we assume is installed.
    if icu_available() {
        add_library("icui18n", "icu4c");
        add_library("icuuc", "icu4c");
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

/// Reports whether both `icu-i18n` and `icu-uc` are available, matching the
/// combined `pkg-config icu-i18n icu-uc` probe Samba's own configure runs.
fn icu_available() -> bool {
    ["icu-i18n", "icu-uc"].into_iter().all(|lib| {
        pkg_config::Config::new()
            .cargo_metadata(false)
            .probe(lib)
            .is_ok()
    })
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
            println!(
                "{lib} was not found with pkg_config; trying with LD_LIBRARY_PATH; but you may need to install it manually"
            );
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
