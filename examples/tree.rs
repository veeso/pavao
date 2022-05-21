use argh::FromArgs;
use env_logger;
use pavao::{SmbClient, SmbCredentials, SmbDirent, SmbDirentType, SmbOptions, SmbStat};
use std::path::PathBuf;

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
    #[argh(option, short = 'w', description = "specify workgroup")]
    workgroup: String,
    #[argh(option, short = 's', description = "specify share")]
    share: String,
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
    tree(&client, "/pavao", 0);
}

/// Read a secret from tty with customisable prompt
fn read_secret_from_tty(prompt: &str) -> std::io::Result<String> {
    match rpassword::read_password_from_tty(Some(prompt)) {
        Ok(p) => Ok(p),
        Err(err) => Err(err),
    }
}

fn tree(client: &SmbClient, uri: &str, depth: usize) {
    // scan dir
    for entity in client.list_dir(uri).unwrap().into_iter() {
        // stat file
        let entity_uri = entity_uri(&entity, uri);
        let stat = client.stat(entity_uri.as_str()).unwrap();
        print_entry(&entity, &stat, depth);
        // if is dir, iter directory
        if entity.get_type() == SmbDirentType::Dir {
            tree(client, entity_uri.as_str(), depth + 1);
        }
    }
}

fn entity_uri(entity: &SmbDirent, path: &str) -> String {
    let mut p = PathBuf::from(path);
    p.push(PathBuf::from(entity.name()));
    p.as_path().to_string_lossy().to_string()
}

fn print_entry(entity: &SmbDirent, stat: &SmbStat, depth: usize) {
    println!(
        "{}{:32}\t{}\t{}\t{}",
        fmt_depth(depth),
        entity.name(),
        stat.uid,
        stat.gid,
        stat.size
    );
}

fn fmt_depth(depth: usize) -> String {
    " ".repeat(depth * 2)
}
