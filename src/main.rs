use pavao::{SmbClient, SmbCredentials, SmbMode, SmbOptions};

fn main() {
    let client = SmbClient::new(
        SmbCredentials::default()
            .server("smb://localhost:3139")
            .share("/temp")
            .username("test")
            .password("test")
            .workgroup("pavao"),
        SmbOptions::default()
            .case_sensitive(true)
            .one_share_per_server(true),
    )
    .unwrap();
    // make test dir
    println!("{:?}", client.mkdir("/test", SmbMode::from(0o644)));
}
