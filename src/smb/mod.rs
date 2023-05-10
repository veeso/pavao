//! # Smb
//!
//! module which exposes the smb types and client

mod auth_service;
mod client;
mod types;

// -- priv
use auth_service::AuthService;
pub use client::SmbClient;
pub use types::*;
