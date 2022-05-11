//! # Error
//!
//! result and error types

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
use std::ffi::NulError;
use std::io::Error as IoError;
use thiserror::Error;

/// Result returned by the Smb client
pub type SmbResult<T> = Result<T, SmbError>;

/// Smb protocol error
#[derive(Debug, Error)]
pub enum SmbError {
    #[error("server returned with a bad value")]
    BadValue,
    #[error("IO Error: {0}")]
    Io(IoError),
    #[error("bad path: {0}")]
    NulInPath(NulError),
}

impl From<IoError> for SmbError {
    fn from(e: IoError) -> Self {
        Self::Io(e)
    }
}

impl From<NulError> for SmbError {
    fn from(e: NulError) -> Self {
        Self::NulInPath(e)
    }
}
