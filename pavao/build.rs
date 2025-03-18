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
}
