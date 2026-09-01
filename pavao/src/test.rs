mod container;

pub use container::SambaContainer;
use pavao_sys::{smbc_free_context, smbc_new_context, smbc_setOptionProtocols};

use crate::{SmbClient, SmbCredentials, SmbMode, SmbOptions};

pub struct TestCtx {
    pub client: SmbClient,
    url: String,
    _container: SambaContainer,
}

impl TestCtx {
    /// Returns the `smb://` URL of the test container.
    pub fn server_url(&self) -> &str {
        &self.url
    }

    /// Starts a Samba container with `server_globals` and connects a client using `options`.
    pub fn with_config(server_globals: &[&str], options: SmbOptions) -> Self {
        let _ = env_logger::builder()
            .is_test(true)
            .filter_level(log::LevelFilter::Debug)
            .try_init();

        if options.min_protocol.is_none() && options.max_protocol.is_none() {
            reset_protocols();
        }

        let container = if server_globals.is_empty() {
            SambaContainer::start()
        } else {
            SambaContainer::start_with_globals(server_globals)
        };

        let port = container.get_smb_port();
        let url = format!("smb://localhost:{port}");

        let client = SmbClient::new(
            SmbCredentials::default()
                .server(&url)
                .share("/temp")
                .username("test")
                .password("test")
                .workgroup("pavao"),
            options,
        )
        .expect("failed to create client");

        // create /cargo-test
        client
            .mkdir("/cargo-test", SmbMode::from(0o777))
            .expect("failed to create test dir");

        TestCtx {
            client,
            url,
            _container: container,
        }
    }
}

fn reset_protocols() {
    // This test-only raw FFI boundary runs only from serial client tests. The Samba test image
    // defaults to these bounds, but libsmbclient retains a prior explicit policy after teardown.
    unsafe {
        let ctx = smbc_new_context();
        assert!(!ctx.is_null(), "failed to create protocol reset context");
        assert_ne!(
            smbc_setOptionProtocols(ctx, c"SMB2_02".as_ptr(), c"SMB3_11".as_ptr()),
            0,
            "failed to reset protocol bounds"
        );
        smbc_free_context(ctx, 1_i32);
    }
}

impl Default for TestCtx {
    fn default() -> Self {
        Self::with_config(
            &[],
            SmbOptions::default()
                .case_sensitive(true)
                .one_share_per_server(true),
        )
    }
}
