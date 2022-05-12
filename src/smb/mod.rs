//! # Smb
//!
//! module which exposes the smb types and client

mod client;
mod types;

pub use client::SmbClient;
pub use types::*;
