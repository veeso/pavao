use argh::FromArgs;
use env_logger;
use pavao::{SmbClient, SmbCredentials, SmbOpenOptions, SmbOptions};
use std::fs::File;
use std::io;
use std::path::Path;

#[derive(FromArgs)]
#[argh(description = "
where positional can be: [smb://address[:port]]

Please, report issues to <https://github.com/veeso/pavao>
Please, consider supporting the author <https://ko-fi.com/veeso>")]
struct Args {
    #[argh(option, short = 'P', description = "specify password")]
    password: Option<String>,
    #[argh(option, short = 'u', description = "specify username")]
    username: String,
    #[argh(option, short = 'i', description = "specify input path")]
    input: String,
    #[argh(option, short = 'w', description = "specify workgroup")]
    workgroup: String,
    #[argh(option, short = 's', description = "specify share")]
    share: String,
    #[argh(option, short = 'o', description = "specify destination output")]
    output: String,
    #[argh(positional, description = "smb://address[:port]")]
    server: String,
}

fn main() {
    assert!(env_logger::builder().try_init().is_ok());
    let args: Args = argh::from_env();
    let password = match args.password {
        Some(p) => p,
        None => read_secret_from_tty("Password: ").ok().unwrap(),
    };
    // setup server
    let client = SmbClient::new(
        SmbCredentials::default()
            .server(args.server)
            .share(args.share)
            .password(password)
            .username(args.username)
            .workgroup(args.workgroup),
        SmbOptions::default().one_share_per_server(true),
    )
    .unwrap();
    // Open file to read
    let mut reader = File::open(Path::new(args.input.as_str())).unwrap();
    // Open file to write
    let mut writer = client
        .open_with(
            args.output,
            SmbOpenOptions::default().create(true).write(true),
        )
        .unwrap();
    assert!(io::copy(&mut reader, &mut writer).is_ok());
}

/// Read a secret from tty with customisable prompt
fn read_secret_from_tty(prompt: &str) -> std::io::Result<String> {
    match rpassword::read_password_from_tty(Some(prompt)) {
        Ok(p) => Ok(p),
        Err(err) => Err(err),
    }
}
