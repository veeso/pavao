use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::{env, fs};

/// Artifacts produced by the build process.
pub struct Artifacts {
    pub lib_dir: PathBuf,
    pub include_dir: PathBuf,
    pub libsmbclient: PathBuf,
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

impl Default for Build {
    fn default() -> Self {
        Self::new()
    }
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
            if target.contains("apple") && arg == "-arch" {
                skip_next = true;
                continue;
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
                    format!(
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

        // built shared library -> bin/default/source3/libsmb
        let lib_dir = inner_dir
            .join("bin")
            .join("default")
            .join("source3")
            .join("libsmb");

        // built shared library -> bin/default/source3/libsmb/libsmbclient.so
        let libsmbclient = lib_dir.join("libsmbclient.so");

        // include_dir -> bin/default/include/public/
        let include_dir = inner_dir
            .join("bin")
            .join("default")
            .join("include")
            .join("public");

        Ok(Artifacts {
            lib_dir,
            include_dir,
            libsmbclient,
        })
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
