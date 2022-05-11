//! # Error
//!
//! result and error types

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
