use std::borrow::Cow;

use testcontainers::core::{ContainerPort, WaitFor};
use testcontainers::{Container, Image};

#[derive(Debug, Default, Clone)]
struct SambaImage;

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
        vec![
            "samba.sh",
            "-u",
            "test;test",
            "-p",
            "-s",
            "temp;/mnt/tmp;yes;no;yes;test;test",
            "-w",
            "pavao",
        ]
        .into_iter()
    }

    fn expose_ports(&self) -> &[testcontainers::core::ContainerPort] {
        &[ContainerPort::Tcp(139), ContainerPort::Tcp(445)]
    }
}

pub struct SambaContainer {
    container: Container<SambaImage>,
}

impl SambaContainer {
    pub fn start() -> Self {
        use testcontainers::runners::SyncRunner;
        let container = SambaImage::default()
            .start()
            .expect("failed to start container");

        Self { container }
    }

    pub fn get_smb_port(&self) -> u16 {
        self.container.get_host_port_ipv4(445).expect("no port")
    }
}
