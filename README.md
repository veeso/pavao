# Pavão

<p align="center">
  <img src="docs/images/pavao.png" alt="pavao logo" width="128" height="128" />
</p>

<p align="center">~ A Rust client library for SMB ~</p>
<p align="center">
  <a href="#get-started-">Get started</a>
  ·
  <a href="https://crates.io/crates/pavao" target="_blank">Crates.io</a>
  ·
  <a href="https://docs.rs/pavao" target="_blank">Documentation</a>
</p>
<p align="center">Developed by <a href="https://veeso.github.io/" target="_blank">@veeso</a></p>
<p align="center">Current version: 0.2.8 (19/12/2024)</p>

<p align="center">
  <a href="https://www.gnu.org/licenses/gpl-3.0"
    ><img
      src="https://img.shields.io/badge/License-GPLv3-blue.svg"
      alt="License-GPLv3"
  /></a>
  <a href="https://github.com/veeso/pavao/stargazers"
    ><img
      src="https://img.shields.io/github/stars/veeso/pavao.svg?style=plain"
      alt="Repo stars"
  /></a>
  <a href="https://crates.io/crates/pavao"
    ><img
      src="https://img.shields.io/crates/d/pavao.svg"
      alt="Downloads counter"
  /></a>
  <a href="https://crates.io/crates/pavao"
    ><img
      src="https://img.shields.io/crates/v/pavao.svg"
      alt="Latest version"
  /></a>
  <a href="https://ko-fi.com/veeso">
    <img
      src="https://img.shields.io/badge/donate-ko--fi-red"
      alt="Ko-fi"
  /></a>
</p>
<p align="center">
  <a href="https://github.com/veeso/pavao/actions"
    ><img
      src="https://github.com/veeso/pavao/workflows/Linux/badge.svg"
      alt="Linux CI"
  /></a>
  <a href="https://github.com/veeso/pavao/actions"
    ><img
      src="https://github.com/veeso/pavao/workflows/MacOS/badge.svg"
      alt="MacOS CI"
  /></a>
  <a href="https://coveralls.io/github/veeso/pavao"
    ><img
      src="https://coveralls.io/repos/github/veeso/pavao/badge.svg"
      alt="Coveralls"
  /></a>
   <a href="https://docs.rs/pavao"
    ><img
      src="https://docs.rs/pavao/badge.svg"
      alt="Docs"
  /></a>
</p>

---

- [Pavão](#pavão)
  - [About Pavão 🦚](#about-pavão-)
    - [SMB Rust client for Windows](#smb-rust-client-for-windows)
  - [Get started 🏁](#get-started-)
    - [Add pavao to your Cargo.toml 🦀](#add-pavao-to-your-cargotoml-)
    - [Install pavao C dependencies on your system 🖥️](#install-pavao-c-dependencies-on-your-system-️)
      - [MacOS 🍎](#macos-)
      - [Debian based systems 🐧](#debian-based-systems-)
      - [RedHat based systems 🐧](#redhat-based-systems-)
      - [OpenBSD 🐡](#openbsd-)
      - [Build from sources 📁](#build-from-sources-)
    - [Create a pavao application](#create-a-pavao-application)
    - [Run examples](#run-examples)
  - [Documentation 📚](#documentation-)
  - [Support the developer ☕](#support-the-developer-)
  - [Contributing and issues 🤝🏻](#contributing-and-issues-)
  - [Changelog ⏳](#changelog-)
  - [License 📃](#license-)

---

## About Pavão 🦚

Pavão (/pɐ.ˈvɐ̃w̃/) is a Rust client library for SMB version 2 and 3 which exposes type-safe functions to interact with the C libsmbclient.

> Pavão |> Pavé |> Animal Crossing |> Carnival |> Rio De Janeiro |> Samba |> SMB

### SMB Rust client for Windows

SMB is natively supported on Windows by the fs module. If you're looking on how to use SMB on Windows with Rust, please check out this article <https://blog.veeso.dev/blog/en/how-to-access-an-smb-share-with-rust-on-windows/> or consider adopting [remotefs-smb](https://github.com/veeso/remotefs-rs-smb).

---

## Get started 🏁

### Add pavao to your Cargo.toml 🦀

```toml
pavao = "0.2"
```

### Install pavao C dependencies on your system 🖥️

#### MacOS 🍎

Install samba with brew:

```sh
brew install samba
```

#### Debian based systems 🐧

Install libsmbclient with apt:

```sh
apt install -y libsmbclient-dev libsmbclient
```

⚠️ `libsmbclient-dev` is required only on the machine where you build the application

#### RedHat based systems 🐧

Install libsmbclient with dnf:

```sh
dnf install libsmbclient-devel libsmbclient
```

⚠️ `libsmbclient-devel` is required only on the machine where you build the application

#### OpenBSD 🐡

Install samba with pkg_add:

```sh
pkg_add samba
```

#### Build from sources 📁

Install libsmbclient building from sources:

```sh
wget -O samba.tar.gz https://github.com/samba-team/samba/archive/refs/tags/samba-4.16.1.tar.gz
mkdir -p samba/
tar  xzvf samba.tar.gz -C samba/ --strip-components=1
rm samba.tar.gz
cd samba/
./configure
make
make install
cd ..
rm -rf samba/
```

### Create a pavao application

```rust
use pavao::{SmbClient, SmbCredentials, SmbOptions, SmbOpenOptions};

// Initialize a new client
let client = SmbClient::new(
    SmbCredentials::default()
        .server(server)
        .share(share)
        .password(password)
        .username(username)
        .workgroup(workgroup),
    SmbOptions::default().one_share_per_server(true),
)
.unwrap();
// do anything you want here with client
let mut file = client.open_with("/abc/test.txt", SmbOpenOptions::default().read(true)).unwrap();
// read file...
drop(file);
// disconnect from server
drop(client);

```

### Run examples

Two examples are provided along with this repository and can be found under the `examples/` directory.

The `tree` example can be used to get a fs tree of the smb share and can be run with:

```sh
cargo run --example tree -- -u <username> -w <workspace> -s <share> -P <password> smb://<hostname>
```

while the `transfer` example shows how to write a file to the remote host and can be run with:

```sh
cargo run --example transfer -- -i <file_on_local> -o <file_to_write> -u <username> -w <workspace> -s <share> -P <password> smb://<hostname>
```

---

## Documentation 📚

The developer documentation can be found on Rust Docs at <https://docs.rs/pavao>

---

## Support the developer ☕

If you like Pavão and you're grateful for the work I've done, please consider a little donation 🥳

You can make a donation with one of these platforms:

[![ko-fi](https://img.shields.io/badge/Ko--fi-F16061?style=for-the-badge&logo=ko-fi&logoColor=white)](https://ko-fi.com/veeso)
[![PayPal](https://img.shields.io/badge/PayPal-00457C?style=for-the-badge&logo=paypal&logoColor=white)](https://www.paypal.me/chrisintin)

---

## Contributing and issues 🤝🏻

Contributions, bug reports, new features and questions are welcome! 😉
If you have any question or concern, or you want to suggest a new feature, or you want just want to improve pavao, feel free to open an issue or a PR.

Please follow [our contributing guidelines](CONTRIBUTING.md)

---

## Changelog ⏳

View Pavão's changelog [HERE](CHANGELOG.md)

---

## License 📃

Pavão is licensed under the GPLv3 license.

You can read the entire license [HERE](LICENSE)
