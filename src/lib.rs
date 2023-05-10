//! # Pavão
//!
//! [Pavão](https://github.com/veeso/pavao) is a Rust client library for SMB2/SMB3
//! which exposes type-safe functions to interact with the C libsmbclient
//!
//! ## Get Started
//!
//! ### Adding `pavao` to your cargo toml dependencies:
//!
//! ```toml
//! pavao = "0.2"
//! ```
//!
//! ## Example
//!
//!
//! ```rust
//! use pavao::{SmbClient, SmbCredentials, SmbOptions};
//!
//! let client = SmbClient::new(
//!     SmbCredentials::default()
//!         .server("smb://localhost:3445")
//!         .share("/temp")
//!         .username("test")
//!         .password("test")
//!         .workgroup("pavao"),
//!     SmbOptions::default()
//!         .case_sensitive(true)
//!         .one_share_per_server(true),
//!     )
//!     .unwrap();
//!
//! // drop connection
//! drop(client);
//! ```
//!
//! Further examples can be found under the `examples/` directory in the Github repository
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
mod libsmbclient;
mod smb;
pub(crate) mod utils;

// -- exports
pub use error::{SmbError, SmbResult};
pub use smb::{
    SmbClient, SmbCredentials, SmbDirent, SmbDirentInfo, SmbDirentType, SmbEncryptionLevel,
    SmbFile, SmbMode, SmbModeClass, SmbOpenOptions, SmbOptions, SmbShareMode, SmbStat,
};

// -- mock
#[cfg(test)]
pub(crate) mod mock;
