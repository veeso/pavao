use std::borrow::Cow;

use testcontainers::core::{ContainerPort, WaitFor};
use testcontainers::{Container, Image};

#[derive(Debug, Default, Clone)]
struct SambaImage {
    globals: Vec<String>,
}

impl Image for SambaImage {
    fn name(&self) -> &str {
        "dperson/samba"
    }

    fn tag(&self) -> &str {
        "latest"
    }

    fn ready_conditions(&self) -> Vec<WaitFor> {
        vec![WaitFor::message_on_stdout("daemon_ready")]
    }

    fn cmd(&self) -> impl IntoIterator<Item = impl Into<Cow<'_, str>>> {
        let mut cmd: Vec<Cow<'_, str>> = vec![
            "samba.sh".into(),
            "-u".into(),
            "test;test".into(),
            "-p".into(),
            "-s".into(),
            "temp;/mnt/tmp;yes;no;yes;test;test".into(),
            "-w".into(),
            "pavao".into(),
        ];
        for global in &self.globals {
            cmd.push("-g".into());
            cmd.push(Cow::Owned(global.clone()));
        }
        cmd
    }

    fn expose_ports(&self) -> &[testcontainers::core::ContainerPort] {
        &[ContainerPort::Tcp(139), ContainerPort::Tcp(445)]
    }
}

pub struct SambaContainer {
    container: Container<SambaImage>,
}

impl SambaContainer {
    #[expect(
        dead_code,
        reason = "default test contexts delegate through configurable startup"
    )]
    pub fn start() -> Self {
        Self::start_with_globals(&[])
    }

    /// Starts a Samba container with extra `smb.conf` global parameters.
    pub fn start_with_globals(globals: &[&str]) -> Self {
        use testcontainers::runners::SyncRunner;
        let image = SambaImage {
            globals: globals.iter().map(|global| global.to_string()).collect(),
        };
        let container = image.start().expect("failed to start container");

        Self { container }
    }

    pub fn get_smb_port(&self) -> u16 {
        self.container.get_host_port_ipv4(445).expect("no port")
    }
}
