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
//! pavao = "0.1.0"
//! ```
//!

#![doc(html_playground_url = "https://play.rust-lang.org")]
#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/veeso/pavao/main/docs/images/cargo/pavao-128.png"
)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/veeso/pavao/main/docs/images/cargo/pavao-512.png"
)]

#[macro_use]
extern crate log;

// -- mod
mod error;
mod smb;
pub(crate) mod utils;

// -- exports
pub use error::{SmbError, SmbResult};
pub use smb::{
    SmbClient, SmbCredentials, SmbDirent, SmbDirentType, SmbEncryptionLevel, SmbFile, SmbMode,
    SmbModeClass, SmbOpenOptions, SmbOptions, SmbShareMode, SmbStat,
};
