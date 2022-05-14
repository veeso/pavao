//! # Smb
//!
//! module which exposes the smb types and client

mod auth_service;
mod client;
mod types;

pub use client::SmbClient;
pub use types::*;

// -- priv
use auth_service::AuthService;
