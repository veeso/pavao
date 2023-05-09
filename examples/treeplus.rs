use argh::FromArgs;
use env_logger;
use pavao::{
    SmbClient, SmbCredentials, SmbDirent, SmbDirentInfo, SmbDirentType, SmbOptions, SmbStat,
};
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
    //setup server
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
    treeplus(&client, "/DCIM", 0);
}

/// Read a secret from tty with customisable prompt
fn read_secret_from_tty(prompt: &str) -> std::io::Result<String> {
    match rpassword::read_password_from_tty(Some(prompt)) {
        Ok(p) => Ok(p),
        Err(err) => Err(err),
    }
}


fn treeplus(client: &SmbClient, uri: &str, depth: usize) {
    let vec = client.list_dirplus(uri).unwrap();
    for entityplus in vec.into_iter() {
        let entityplus_uri = entityplus_uri(&entityplus, uri);
        print_entry_plus(&entityplus,depth);
        // if is dir, iter directory
        if entityplus.get_type() == SmbDirentType::Dir {
            treeplus(client, &entityplus_uri.as_str(), depth + 1)
        }
    }
}


fn entityplus_uri(entity: &SmbDirentInfo, path: &str) -> String {
    let mut p = PathBuf::from(path);
    p.push(PathBuf::from(entity.name()));
    p.as_path().to_string_lossy().to_string()
}

fn print_entry_plus(entityplus: &SmbDirentInfo, depth: usize) {
    println!(
        "{}{:32}\t{}\t{:x}\t{:?}",
        fmt_depth(depth),
        entityplus.name(),
        entityplus.size,
        entityplus.attrs,
        entityplus.get_type(),
    )
}

fn fmt_depth(depth: usize) -> String {
    " ".repeat(depth * 4)
}
