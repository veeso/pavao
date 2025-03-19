use std::collections::HashSet;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::{env, fs};

const LIBSMBCLIENT_SRC_FILES: &[&str] = &[
    "libsmb_cache.c",
    "libsmb_compat.c",
    "libsmb_context.c",
    "libsmb_dir.c",
    "libsmb_file.c",
    "libsmb_misc.c",
    "libsmb_path.c",
    "libsmb_printjob.c",
    "libsmb_server.c",
    "libsmb_stat.c",
    "libsmb_xattr.c",
    "libsmb_setget.c",
];

const LIBSMB_SRC_FILES: &[&str] = &[
    "clientgen.c",
    "clifile.c",
    "clirap.c",
    "clierror.c",
    "climessage.c",
    "clireadwrite.c",
    "clilist.c",
    "cliprint.c",
    "clitrans.c",
    "clisecdesc.c",
    "cliquota.c",
    "clifsinfo.c",
    "clidfs.c",
    "clioplock.c",
    "async_smb.c",
    "clisymlink.c",
    "smbsock_connect.c",
    "cli_smb2_fnum.c",
];

const RPC_CLIENT_SRC_FILES: &[&str] = &[
    "cli_lsarpc.c",
    "init_lsa.c",
    "cli_pipe.c",
    "rpc_transport_np.c",
    "rpc_transport_sock.c",
    "rpc_transport_tstream.c",
    "local_np.c",
];

const LIBGENNDR_SRC_FILES: &[&str] = &["ndr_lsa_c.c"];

const SMBCONF_SRC_FILES: &[&str] = &["smbconf_init.c", "smbconf_reg.c"];

const LIBSMBCONF_SRC_FILES: &[&str] = &["smbconf.c", "smbconf_txt.c", "smbconf_util.c"];

const TALLOC_SRC_FILES: &[&str] = &["talloc.c"];

const SAMBA_UTILS_SRC_FILES: &[&str] = &[
    "base64.c",
    "dprintf.c",
    "dns_cmp.c",
    "fsusage.c",
    "genrand_util.c",
    "getpass.c",
    "idtree_random.c",
    "memcache.c",
    "params.c",
    "rbtree.c",
    "rfc1738.c",
    "server_id.c",
    "smb_threads.c",
    "system.c",
    "talloc_keep_secret.c",
    "talloc_stack.c",
    "tevent_debug.c",
    "tfork.c",
    "tftw.c",
    "unix_match.c",
    "util_id.c",
    "util_net.c",
    "util_paths.c",
    "util_str.c",
    "util_str_common.c",
    "util_strlist_v3.c",
    "util_str_hex.c",
    "stable_sort.c",
];

const GNUTLS_HELPERS_SRC_FILES: &[&str] = &[
    "gnutls_error.c",
    "gnutls_aead_aes_256_cbc_hmac_sha512.c",
    "gnutls_arcfour_confounded_md5.c",
    "gnutls_weak_crypto.c",
    "gnutls_sp800_108.c",
];

const SAMBA_ERROR_SRC_FILES: &[&str] = &[
    "doserr.c",
    "errormap.c",
    "nterr.c",
    "errmap_unix.c",
    "hresult.c",
];

const LIBRPC_RPC_SRC_FILES: &[&str] = &["dcerpc_helpers.c"];

const NDR_SRC_FILES: &[&str] = &[
    "ndr_string.c",
    "ndr_basic.c",
    "uuid.c",
    "ndr.c",
    "ndr_misc.c",
    "util.c",
    "ndr_sec_helper.c",
    "ndr_netlogon.c",
    "ndr_svcctl.c",
    "ndr_dns.c",
    "ndr_dns_utils.c",
    "ndr_dnsp.c",
];

const GEN_NDR_SRC_FILES: &[&str] = &[
    "ndr_misc.c",
    "ndr_security.c",
    "ndr_lsa.c",
    "ndr_samr.c",
    "ndr_netlogon.c",
    "ndr_eventlog.c",
    "ndr_eventlog6.c",
    "ndr_dfs.c",
    "ndr_ntsvcs.c",
    "ndr_svcctl.c",
    "ndr_initshutdown.c",
    "ndr_wkssvc.c",
    "ndr_srvsvc.c",
    "ndr_winreg.c",
    "ndr_echo.c",
    "ndr_dns.c",
    "ndr_dnsp.c",
    "ndr_atsvc.c",
    "ndr_spoolss.c",
    "ndr_dssetup.c",
    "ndr_server_id.c",
    "ndr_notify.c",
    "ndr_conditional_ace.c",
];

const SAMBA_SECURITY_SRC_FILES: &[&str] = &[
    "dom_sid.c",
    "display_sec.c",
    "secace.c",
    "secacl.c",
    "security_descriptor.c",
    "sddl.c",
    "privileges.c",
    "security_token.c",
    "access_check.c",
    "object_tree.c",
    "create_descriptor.c",
    "util_sid.c",
    "session.c",
    "secdesc.c",
    "conditional_ace.c",
    "sddl_conditional_ace.c",
    "claims-conversions.c",
];

const UTIL_CHARSET_SRC_FILES: &[&str] = &[
    "weird.c",
    "charset_macosxfs.c",
    "iconv.c",
    "util_str.c",
    "util_unistr.c",
    "util_unistr_w.c",
    "pull_push.c",
    "convert_string.c",
    "codepoints.c",
];

const AUTH_SRC_FILES: &[&str] = &[
    "cliauth.empty.c",
    "msrpc_parse.c",
    "smbdes.c",
    "ntlm_check.c",
    "pam_errors.c",
    "session.c",
    "schannel_state_tdb.c",
    "smbencrypt.c",
    "credentials.c",
    "spnego_parse.c",
    "netlogon_creds_cli.c",
];

const LIBCLI_SMB_SRC_FILES: &[&str] = &["smbXcli_base.c.4"];

/// Artifacts produced by the build process.
pub struct Artifacts {
    pub lib_dir: PathBuf,
    pub include_dir: PathBuf,
}

/// Source dir
pub fn source_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("samba")
}

/// samba version
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Build configuration
pub struct Build {
    out_dir: Option<PathBuf>,
    target: Option<String>,
    host: Option<String>,
    samba_dir: Option<PathBuf>,
}

impl Build {
    /// Init a new [`Build`] configuration.
    pub fn new() -> Build {
        Build {
            out_dir: env::var_os("OUT_DIR").map(|s| PathBuf::from(s).join("samba-build")),
            target: env::var("TARGET").ok(),
            host: env::var("HOST").ok(),
            samba_dir: Some(PathBuf::from("/usr/local/samba")),
        }
    }

    pub fn out_dir<P: AsRef<Path>>(&mut self, path: P) -> &mut Build {
        self.out_dir = Some(path.as_ref().to_path_buf());
        self
    }

    pub fn target(&mut self, target: &str) -> &mut Build {
        self.target = Some(target.to_string());
        self
    }

    pub fn host(&mut self, host: &str) -> &mut Build {
        self.host = Some(host.to_string());
        self
    }

    pub fn samba_dir<P: AsRef<Path>>(&mut self, path: P) -> &mut Build {
        self.samba_dir = Some(path.as_ref().to_path_buf());
        self
    }

    fn cmd_make(&self) -> Result<Command, &'static str> {
        let host = &self.host.as_ref().ok_or("HOST dir not set")?[..];
        Ok(
            if host.contains("dragonfly")
                || host.contains("freebsd")
                || host.contains("openbsd")
                || host.contains("solaris")
                || host.contains("illumos")
            {
                Command::new("gmake")
            } else {
                Command::new("make")
            },
        )
    }

    /// Build the samba library. Print cargo:warning=... if the build fails.
    pub fn build(&mut self) -> Artifacts {
        match self.try_build() {
            Ok(a) => a,
            Err(e) => {
                println!("cargo:warning=pavao-src: failed to build samba from source");
                eprintln!("\n\n\n{e}\n\n\n");
                std::process::exit(1);
            }
        }
    }

    /// Try to build the samba library.
    pub fn try_build(&mut self) -> Result<Artifacts, String> {
        let target = &self.target.as_ref().ok_or("TARGET dir not set")?[..];
        let host = &self.host.as_ref().ok_or("HOST dir not set")?[..];
        let os = Self::os(target)?;
        let out_dir = self.out_dir.as_ref().ok_or("OUT_DIR not set")?;
        let build_dir = out_dir.join("build");

        if build_dir.exists() {
            fs::remove_dir_all(&build_dir).map_err(|e| format!("build_dir: {e}"))?;
        }

        let inner_dir = build_dir.join("src");
        fs::create_dir_all(&inner_dir).map_err(|e| format!("{}: {e}", inner_dir.display()))?;
        copy_r(&source_dir(), &inner_dir)?;

        // init cc
        let mut cc = cc::Build::new();
        cc.target(target).host(host).warnings(false).opt_level(2);
        let compiler = cc.get_compiler();
        let mut cc_env = compiler.cc_env();
        if cc_env.is_empty() {
            cc_env = compiler.path().to_path_buf().into_os_string();
        }

        // get ar
        let ar = cc.get_archiver();

        // configure
        let mut configure = Command::new("sh");
        configure.arg("./configure");
        configure.arg("--disable-python");
        configure.arg("--without-systemd");
        configure.arg("--without-ldb-lmdb");
        configure.arg("--without-ad-dc");
        configure.arg("--bundled-libraries=ALL");
        configure.env("CC", cc_env);
        configure.env("AR", ar.get_program());

        let ranlib = cc.get_ranlib();
        let mut args = vec![ranlib.get_program()];
        args.extend(ranlib.get_args());
        configure.env("RANLIB", args.join(OsStr::new(" ")));

        let mut skip_next = false;
        let mut is_isysroot = false;
        let mut ios_isysroot = None;
        for arg in compiler.args() {
            // For whatever reason `-static` on MUSL seems to cause
            // issues...
            if target.contains("musl") && arg == "-static" {
                continue;
            }

            // cc includes an `-arch` flag for Apple platforms, but we've
            // already selected an arch implicitly via the target above, and
            // OpenSSL contains about the conflict if both are specified.
            if target.contains("apple") {
                if arg == "-arch" {
                    skip_next = true;
                    continue;
                }
            }

            // cargo-lipo specifies this but OpenSSL complains
            if target.contains("apple-ios") {
                if arg == "-isysroot" {
                    is_isysroot = true;
                    continue;
                }

                if is_isysroot {
                    is_isysroot = false;
                    ios_isysroot = Some(arg.to_str().ok_or("isysroot arg")?.to_string());
                    continue;
                }
            }

            if skip_next {
                skip_next = false;
                continue;
            }
        }

        if os.contains("iossimulator") {
            if let Some(ref isysr) = ios_isysroot {
                configure.env(
                    "CC",
                    &format!(
                        "xcrun -sdk iphonesimulator cc -isysroot {}",
                        Path::new(isysr).display()
                    ),
                );
            }
        }

        configure.current_dir(&inner_dir);
        // run configure
        self.run_command(configure, "configuring samba build")?;

        // run make
        let mut build = self.cmd_make()?;
        build.current_dir(&inner_dir);
        if let Some(s) = env::var_os("CARGO_MAKEFLAGS") {
            build.env("MAKEFLAGS", s);
        }
        if let Some(ref isysr) = ios_isysroot {
            let components: Vec<&str> = isysr.split("/SDKs/").collect();
            build.env("CROSS_TOP", components[0]);
            build.env("CROSS_SDK", components[1]);
        }
        self.run_command(build, "building samba")?;

        // build static library -> bin/default/source3/libsmb
        let lib_dir = inner_dir.join("bin").join("default");

        let mut build_static = cc.get_archiver();
        build_static.arg("rcs");
        build_static.arg("libsmbclient.a");
        build_static.current_dir(&lib_dir);

        // get object files for smbclient
        let smbclient_build_dir = lib_dir.join("source3").join("libsmb");
        Self::find_objects(
            &mut build_static,
            &smbclient_build_dir,
            LIBSMBCLIENT_SRC_FILES,
        )?;

        // get object files for smb
        let smb_build_dir = lib_dir.join("source3").join("libsmb");
        Self::find_objects(&mut build_static, &smb_build_dir, LIBSMB_SRC_FILES)?;

        // smbconf
        let smbconf_build_dir = lib_dir.join("source3").join("lib").join("smbconf");
        Self::find_objects(&mut build_static, &smbconf_build_dir, SMBCONF_SRC_FILES)?;

        // libsmbconf
        let libsmbconf_build_dir = lib_dir.join("lib").join("smbconf");
        Self::find_objects(
            &mut build_static,
            &libsmbconf_build_dir,
            LIBSMBCONF_SRC_FILES,
        )?;

        // push talloc
        let talloc_build_dir = lib_dir.join("lib").join("talloc");
        Self::find_objects(&mut build_static, &talloc_build_dir, TALLOC_SRC_FILES)?;

        // push libcli_lsarpc
        let libcli_lsarpc_build_dir = lib_dir.join("source3").join("rpc_client");
        Self::find_objects(
            &mut build_static,
            &libcli_lsarpc_build_dir,
            RPC_CLIENT_SRC_FILES,
        )?;

        // push libndr_lsa_c
        let libndr_lsa_c_build_dir = lib_dir.join("librpc").join("gen_ndr");
        Self::find_objects(
            &mut build_static,
            &libndr_lsa_c_build_dir,
            LIBGENNDR_SRC_FILES,
        )?;

        // push utils
        let samba_utils_build_dir = lib_dir.join("lib").join("util");
        Self::find_objects(
            &mut build_static,
            &samba_utils_build_dir,
            SAMBA_UTILS_SRC_FILES,
        )?;

        // push gnutls_helpers
        let gnutls_helpers_build_dir = lib_dir.join("lib").join("crypto");
        Self::find_objects(
            &mut build_static,
            &gnutls_helpers_build_dir,
            GNUTLS_HELPERS_SRC_FILES,
        )?;

        // samba error
        let samba_error_build_dir = lib_dir.join("libcli").join("util");
        Self::find_objects(
            &mut build_static,
            &samba_error_build_dir,
            SAMBA_ERROR_SRC_FILES,
        )?;

        // librpc_rpc
        let librpc_rpc_build_dir = lib_dir.join("source3").join("librpc").join("rpc");
        Self::find_objects(
            &mut build_static,
            &librpc_rpc_build_dir,
            LIBRPC_RPC_SRC_FILES,
        )?;

        // ndr
        let ndr_build_dir = lib_dir.join("librpc").join("ndr");
        Self::find_objects(&mut build_static, &ndr_build_dir, NDR_SRC_FILES)?;

        // ndr gen
        let gen_ndr_build_dir = lib_dir.join("librpc").join("gen_ndr");
        Self::find_objects(&mut build_static, &gen_ndr_build_dir, GEN_NDR_SRC_FILES)?;

        // samba security
        let samba_security_build_dir = lib_dir.join("libcli").join("security");
        Self::find_objects(
            &mut build_static,
            &samba_security_build_dir,
            SAMBA_SECURITY_SRC_FILES,
        )?;

        // charset
        let charset_build_dir = lib_dir.join("lib").join("util").join("charset");
        Self::find_objects(
            &mut build_static,
            &charset_build_dir,
            UTIL_CHARSET_SRC_FILES,
        )?;

        // auth
        let auth_build_dir = lib_dir.join("libcli").join("auth");
        Self::find_objects(&mut build_static, &auth_build_dir, AUTH_SRC_FILES)?;

        // libcli smb
        let libcli_smb = lib_dir.join("libcli").join("smb");
        Self::find_objects(&mut build_static, &libcli_smb, LIBCLI_SMB_SRC_FILES)?;

        // run ar
        self.run_command(build_static, "building static library")?;

        // include_dir -> bin/default/include/public/
        let include_dir = inner_dir
            .join("bin")
            .join("default")
            .join("include")
            .join("public");

        Ok(Artifacts {
            lib_dir,
            include_dir,
        })
    }

    /// Find objects starting with `files` in `path` and add them to `command`.
    fn find_objects(command: &mut Command, path: &Path, files: &[&str]) -> Result<(), String> {
        let mut count = 0;
        let mut files_to_find = HashSet::with_capacity(files.len());
        for f in files {
            files_to_find.insert(f.to_string());
        }

        for entry in fs::read_dir(&path).map_err(|e| format!("{}: {e}", path.display()))? {
            let entry = entry.map_err(|e| e.to_string())?;
            let path = entry.path();

            // if not .o file, skip
            if path.extension().map_or(false, |e| e != "o") {
                continue;
            }

            let file_name = path
                .file_name()
                .ok_or("file_name")?
                .to_string_lossy()
                .to_string();

            let mut n = None;
            for f in &files_to_find {
                if file_name.contains(f) {
                    command.arg(path);
                    count += 1;
                    n = Some(f.clone());
                    break;
                }
            }
            if let Some(f) = n {
                files_to_find.remove(&f);
            }

            if files_to_find.is_empty() {
                break;
            }
        }

        if count != files.len() {
            return Err(format!(
                "expected to find {} object files in {}, but found {}. Files not found: {:?}",
                files.len(),
                path.display(),
                count,
                files_to_find
            ));
        }

        Ok(())
    }

    #[track_caller]
    fn run_command(&self, mut command: Command, desc: &str) -> Result<(), String> {
        println!("running {:?}", command);
        let status = command.status();

        let verbose_error = match status {
            Ok(status) if status.success() => return Ok(()),
            Ok(status) => format!(
                "'{exe}' reported failure with {status}",
                exe = command.get_program().to_string_lossy()
            ),
            Err(failed) => match failed.kind() {
                std::io::ErrorKind::NotFound => format!(
                    "Command '{exe}' not found. Is {exe} installed?",
                    exe = command.get_program().to_string_lossy()
                ),
                _ => format!(
                    "Could not run '{exe}', because {failed}",
                    exe = command.get_program().to_string_lossy()
                ),
            },
        };
        println!("cargo:warning={desc}: {verbose_error}");
        Err(format!(
            "Error {desc}:
    {verbose_error}
    Command failed: {command:?}"
        ))
    }

    fn os(target: &str) -> Result<&'static str, String> {
        let os = match target {
            "aarch64-apple-darwin" => "darwin64-arm64-cc",
            "aarch64-linux-android" => "linux-aarch64",
            "aarch64-unknown-freebsd" => "BSD-generic64",
            "aarch64-unknown-openbsd" => "BSD-generic64",
            "aarch64-unknown-linux-gnu" => "linux-aarch64",
            "aarch64-unknown-linux-musl" => "linux-aarch64",
            "aarch64-alpine-linux-musl" => "linux-aarch64",
            "aarch64-chimera-linux-musl" => "linux-aarch64",
            "aarch64-unknown-netbsd" => "BSD-generic64",
            "aarch64_be-unknown-netbsd" => "BSD-generic64",
            "aarch64-pc-windows-msvc" => "VC-WIN64-ARM",
            "aarch64-uwp-windows-msvc" => "VC-WIN64-ARM-UWP",
            "arm-linux-androideabi" => "linux-armv4",
            "armv7-linux-androideabi" => "linux-armv4",
            "arm-unknown-linux-gnueabi" => "linux-armv4",
            "arm-unknown-linux-gnueabihf" => "linux-armv4",
            "arm-unknown-linux-musleabi" => "linux-armv4",
            "arm-unknown-linux-musleabihf" => "linux-armv4",
            "arm-chimera-linux-musleabihf" => "linux-armv4",
            "armv5te-unknown-linux-gnueabi" => "linux-armv4",
            "armv5te-unknown-linux-musleabi" => "linux-armv4",
            "armv6-unknown-freebsd" => "BSD-generic32",
            "armv6-alpine-linux-musleabihf" => "linux-armv6",
            "armv7-unknown-freebsd" => "BSD-armv4",
            "armv7-unknown-linux-gnueabi" => "linux-armv4",
            "armv7-unknown-linux-musleabi" => "linux-armv4",
            "armv7-unknown-linux-gnueabihf" => "linux-armv4",
            "armv7-unknown-linux-musleabihf" => "linux-armv4",
            "armv7-alpine-linux-musleabihf" => "linux-armv4",
            "armv7-chimera-linux-musleabihf" => "linux-armv4",
            "armv7-unknown-netbsd-eabihf" => "BSD-generic32",
            "asmjs-unknown-emscripten" => "gcc",
            "i586-unknown-linux-gnu" => "linux-elf",
            "i586-unknown-linux-musl" => "linux-elf",
            "i586-alpine-linux-musl" => "linux-elf",
            "i586-unknown-netbsd" => "BSD-x86-elf",
            "i686-apple-darwin" => "darwin-i386-cc",
            "i686-linux-android" => "linux-elf",
            "i686-pc-windows-gnu" => "mingw",
            "i686-pc-windows-msvc" => "VC-WIN32",
            "i686-win7-windows-msvc" => "VC-WIN32",
            "i686-unknown-freebsd" => "BSD-x86-elf",
            "i686-unknown-haiku" => "haiku-x86",
            "i686-unknown-linux-gnu" => "linux-elf",
            "i686-unknown-linux-musl" => "linux-elf",
            "i686-unknown-netbsd" => "BSD-x86-elf",
            "i686-uwp-windows-msvc" => "VC-WIN32-UWP",
            "loongarch64-unknown-linux-gnu" => "linux-generic64",
            "loongarch64-unknown-linux-musl" => "linux-generic64",
            "mips-unknown-linux-gnu" => "linux-mips32",
            "mips-unknown-linux-musl" => "linux-mips32",
            "mips64-unknown-linux-gnuabi64" => "linux64-mips64",
            "mips64-unknown-linux-muslabi64" => "linux64-mips64",
            "mips64el-unknown-linux-gnuabi64" => "linux64-mips64",
            "mips64el-unknown-linux-muslabi64" => "linux64-mips64",
            "mipsel-unknown-linux-gnu" => "linux-mips32",
            "mipsel-unknown-linux-musl" => "linux-mips32",
            "powerpc-unknown-freebsd" => "BSD-ppc",
            "powerpc-unknown-linux-gnu" => "linux-ppc",
            "powerpc-unknown-linux-gnuspe" => "linux-ppc",
            "powerpc-chimera-linux-musl" => "linux-ppc",
            "powerpc-unknown-netbsd" => "BSD-generic32",
            "powerpc64-unknown-freebsd" => "BSD-ppc64",
            "powerpc64-unknown-linux-gnu" => "linux-ppc64",
            "powerpc64-unknown-linux-musl" => "linux-ppc64",
            "powerpc64-chimera-linux-musl" => "linux-ppc64",
            "powerpc64le-unknown-freebsd" => "BSD-ppc64le",
            "powerpc64le-unknown-linux-gnu" => "linux-ppc64le",
            "powerpc64le-unknown-linux-musl" => "linux-ppc64le",
            "powerpc64le-alpine-linux-musl" => "linux-ppc64le",
            "powerpc64le-chimera-linux-musl" => "linux-ppc64le",
            "riscv64gc-unknown-freebsd" => "BSD-riscv64",
            "riscv64gc-unknown-linux-gnu" => "linux64-riscv64",
            "riscv64gc-unknown-linux-musl" => "linux64-riscv64",
            "riscv64-alpine-linux-musl" => "linux64-riscv64",
            "riscv64-chimera-linux-musl" => "linux64-riscv64",
            "riscv64gc-unknown-netbsd" => "BSD-generic64",
            "s390x-unknown-linux-gnu" => "linux64-s390x",
            "sparc64-unknown-netbsd" => "BSD-generic64",
            "s390x-unknown-linux-musl" => "linux64-s390x",
            "s390x-alpine-linux-musl" => "linux64-s390x",
            "sparcv9-sun-solaris" => "solaris64-sparcv9-gcc",
            "thumbv7a-uwp-windows-msvc" => "VC-WIN32-ARM-UWP",
            "x86_64-apple-darwin" => "darwin64-x86_64-cc",
            "x86_64-linux-android" => "linux-x86_64",
            "x86_64-linux" => "linux-x86_64",
            "x86_64-pc-windows-gnu" => "mingw64",
            "x86_64-pc-windows-gnullvm" => "mingw64",
            "x86_64-pc-windows-msvc" => "VC-WIN64A",
            "x86_64-win7-windows-msvc" => "VC-WIN64A",
            "x86_64-unknown-freebsd" => "BSD-x86_64",
            "x86_64-unknown-dragonfly" => "BSD-x86_64",
            "x86_64-unknown-haiku" => "haiku-x86_64",
            "x86_64-unknown-illumos" => "solaris64-x86_64-gcc",
            "x86_64-unknown-linux-gnu" => "linux-x86_64",
            "x86_64-unknown-linux-musl" => "linux-x86_64",
            "x86_64-alpine-linux-musl" => "linux-x86_64",
            "x86_64-chimera-linux-musl" => "linux-x86_64",
            "x86_64-unknown-openbsd" => "BSD-x86_64",
            "x86_64-unknown-netbsd" => "BSD-x86_64",
            "x86_64-uwp-windows-msvc" => "VC-WIN64A-UWP",
            "x86_64-pc-solaris" => "solaris64-x86_64-gcc",
            "wasm32-unknown-emscripten" => "gcc",
            "wasm32-unknown-unknown" => "gcc",
            "wasm32-wasi" => "gcc",
            "aarch64-apple-ios" => "ios64-cross",
            "x86_64-apple-ios" => "iossimulator-xcrun",
            "aarch64-apple-ios-sim" => "iossimulator-xcrun",
            "aarch64-unknown-linux-ohos" => "linux-aarch64",
            "armv7-unknown-linux-ohos" => "linux-generic32",
            "x86_64-unknown-linux-ohos" => "linux-x86_64",
            _ => {
                return Err(format!(
                    "don't know how to configure OpenSSL for {}",
                    target
                ))
            }
        };

        Ok(os)
    }
}

/// Copy recursively from src to dst.
fn copy_r(src: &Path, dst: &Path) -> Result<(), String> {
    for f in fs::read_dir(src).map_err(|e| format!("{}: {e}", src.display()))? {
        let f = match f {
            Ok(f) => f,
            _ => continue,
        };
        let path = f.path();
        let name = path
            .file_name()
            .ok_or_else(|| format!("bad dir {}", src.display()))?;

        // Skip git metadata as it's been known to cause issues (#26) and
        // otherwise shouldn't be required
        if name.to_str() == Some(".git") {
            continue;
        }

        let dst = dst.join(name);
        let ty = f.file_type().map_err(|e| e.to_string())?;
        if ty.is_dir() {
            fs::create_dir_all(&dst).map_err(|e| e.to_string())?;
            copy_r(&path, &dst)?;
        } else if ty.is_symlink() {
            // not needed to build
            continue;
        } else {
            let _ = fs::remove_file(&dst);
            if let Err(e) = fs::copy(&path, &dst) {
                return Err(format!(
                    "failed to copy '{}' to '{}': {e}",
                    path.display(),
                    dst.display()
                ));
            }
        }
    }
    Ok(())
}
