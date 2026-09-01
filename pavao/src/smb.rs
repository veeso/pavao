//! SMB client and value types.

mod auth_service;
mod client;
mod types;

// -- priv
use auth_service::AuthService;
#[doc(inline)]
pub use client::SmbClient;
#[doc(inline)]
pub use types::*;
