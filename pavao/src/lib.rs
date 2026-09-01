#![warn(missing_docs)]

//! A safe SMB 2/3 client built on Samba's `libsmbclient`.
//!
//! Pavão provides typed APIs for connecting to SMB shares, browsing directories,
//! inspecting metadata, and reading or writing remote files.
//!
//! ## Installation
//!
//! ```toml
//! pavao = "0.2"
//! ```
//!
//! ## Examples
//!
//! ```no_run
//! use pavao::{SmbClient, SmbCredentials, SmbOptions};
//!
//! let _client = SmbClient::new(
//!     SmbCredentials::default()
//!         .server("smb://server.example")
//!         .share("/documents")
//!         .username("alice")
//!         .password("secret")
//!         .workgroup("WORKGROUP"),
//!     SmbOptions::default(),
//! )?;
//! # Ok::<(), pavao::SmbError>(())
//! ```
//!
//! See the repository's `examples` directory for directory-tree and file-transfer programs.
//!
//! ## Feature flags
//!
//! | name       | description                                           | default |
//! |------------|-------------------------------------------------------|---------|
//! | `debug`    | Forward verbose native Samba diagnostics to standard error. |         |
//! | `no-log`   | Disable `log` records from this crate at compile time. |         |
//! | `vendored` | Build the bundled Samba source instead of using the system library. |         |
//!

#![doc(html_playground_url = "https://play.rust-lang.org")]
#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/veeso/pavao/main/docs/images/pavao.png"
)]
#![doc(html_logo_url = "https://raw.githubusercontent.com/veeso/pavao/main/docs/images/pavao.png")]

#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;

// -- mod
mod error;
mod smb;
#[cfg(test)]
mod test;
pub(crate) mod utils;

// -- exports
#[doc(inline)]
pub use error::{SmbError, SmbResult};
#[doc(inline)]
pub use smb::{
    SmbClient, SmbCredentials, SmbDirent, SmbDirentInfo, SmbDirentType, SmbEncryptionLevel,
    SmbFile, SmbMode, SmbModeClass, SmbOpenOptions, SmbOptions, SmbShareMode, SmbStat, SmbStatVfs,
};

// -- mock
#[cfg(test)]
pub(crate) mod mock;
