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

/**
 *
 * 	Copyright (C) 2022 Christian Visintin - <christian.visintin1997@gmail.com>
 *
 * 	This file is part of "Pavão"
 *
 *   Pavão is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   Pavão is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Pavão. If not, see <http://www.gnu.org/licenses/>.
 *
 */

#[macro_use]
extern crate log;

// -- mod
mod error;
mod smb;
pub(crate) mod utils;

// -- exports
pub use error::{SmbError, SmbResult};
pub use smb::{options, SmbClient, SmbCredentials, SmbDirent, SmbDirentType, SmbOptions};
