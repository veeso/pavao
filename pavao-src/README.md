# pavao-src

Contains the source code to build the libsmbclient statically to vendor it into the pavao-sys crate.

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
  <a href="https://crates.io/crates/pavao-src"
    ><img
      src="https://img.shields.io/crates/d/pavao-src.svg"
      alt="Downloads counter"
  /></a>
  <a href="https://crates.io/crates/pavao-src"
    ><img
      src="https://img.shields.io/crates/v/pavao-src.svg"
      alt="Latest version"
  /></a>
  <a href="https://ko-fi.com/veeso">
    <img
      src="https://img.shields.io/badge/donate-ko--fi-red"
      alt="Ko-fi"
  /></a>
</p>
</p>

## Requirements

Building the bundled Samba source configures it with most optional server,
directory-service, and printing features disabled (`--without-ad-dc`,
`--without-ldap`, `--disable-cups`, `--without-json`, `--disable-spotlight`,
and others), since only the static `libsmbclient` archive is produced. This
keeps the dependency list well below what a full Samba build requires.

**these packages should be necessary on Linux**:

- bison
- build-essential
- flex
- libgnutls28-dev
- libparse-yapp-perl
- libssl-dev
- libunistring-dev
- make
- pkg-config
- python3
- zlib1g-dev

and these on **MacOS**:

- bison
- cpanminus (plus `cpanm Parse::Yapp::Driver`)
- flex
- gettext
- gmp
- gnutls
- libunistring
- openssl
- pkg-config
- zlib

## License 📃

Pavão-src is licensed under the GPLv3 license.

You can read the entire license [HERE](LICENSE)
