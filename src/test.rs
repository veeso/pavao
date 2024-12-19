mod container;

use container::SambaContainer;

use crate::{SmbClient, SmbCredentials, SmbMode, SmbOptions};

pub struct TestCtx {
    pub client: SmbClient,
    _container: SambaContainer,
}

impl Default for TestCtx {
    fn default() -> Self {
        let _ = env_logger::builder()
            .is_test(true)
            .filter_level(log::LevelFilter::Debug)
            .try_init();

        let container = SambaContainer::start();

        let port = container.get_smb_port();
        let url = format!("smb://localhost:{}", port);

        let client = SmbClient::new(
            SmbCredentials::default()
                .server(&url)
                .share("/temp")
                .username("test")
                .password("test")
                .workgroup("pavao"),
            SmbOptions::default()
                .case_sensitive(true)
                .one_share_per_server(true),
        )
        .expect("failed to create client");

        // create /cargo-test
        client
            .mkdir("/cargo-test", SmbMode::from(0o777))
            .expect("failed to create test dir");

        TestCtx {
            client,
            _container: container,
        }
    }
}
