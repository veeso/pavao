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
    #[error("server returned a bad file descriptor")]
    BadFileDescriptor,
    #[error("server returned with a bad value")]
    BadValue,
    #[error("IO Error: {0}")]
    Io(IoError),
    #[error("bad path: {0}")]
    NulInPath(NulError),
    #[error("mutex error")]
    Mutex,
}

impl PartialEq for SmbError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::BadFileDescriptor, Self::BadFileDescriptor) => true,
            (Self::BadValue, Self::BadValue) => true,
            (Self::Io(io), Self::Io(io2)) => io.kind() == io2.kind(),
            (Self::NulInPath(e), Self::NulInPath(e2)) => e == e2,
            (_, _) => false,
        }
    }
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
