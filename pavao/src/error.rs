//! Errors returned by the SMB client.

use std::ffi::NulError;
use std::io::Error as IoError;

use thiserror::Error;

use crate::SmbDialect;

/// A result returned by Pavão operations.
pub type SmbResult<T> = Result<T, SmbError>;

/// An error produced while configuring or using an SMB client.
#[derive(Debug, Error)]
pub enum SmbError {
    /// The server or native library returned an invalid file descriptor.
    #[error("server returned a bad file descriptor")]
    BadFileDescriptor,
    /// The native library returned a value Pavão cannot interpret.
    #[error("server returned with a bad value")]
    BadValue,
    /// The requested minimum SMB dialect is newer than the requested maximum dialect.
    #[error("invalid protocol range: minimum dialect {min} exceeds maximum dialect {max}")]
    InvalidProtocolRange {
        /// The requested minimum dialect.
        min: SmbDialect,
        /// The requested maximum dialect.
        max: SmbDialect,
    },
    /// An operating-system or native I/O operation failed.
    #[error("IO Error: {0}")]
    Io(IoError),
    /// A path or configuration string contained an interior NUL byte.
    #[error("bad path: {0}")]
    NulInPath(NulError),
    /// The native library rejected the requested protocol dialect bounds.
    #[error("native library rejected the requested protocol dialects")]
    ProtocolConfiguration,
    /// Shared client state could not be accessed because its mutex was poisoned.
    #[error("mutex error")]
    Mutex,
}

impl PartialEq for SmbError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::BadFileDescriptor, Self::BadFileDescriptor) => true,
            (Self::BadValue, Self::BadValue) => true,
            (
                Self::InvalidProtocolRange { min, max },
                Self::InvalidProtocolRange {
                    min: min2,
                    max: max2,
                },
            ) => min == min2 && max == max2,
            (Self::Io(io), Self::Io(io2)) => io.kind() == io2.kind(),
            (Self::NulInPath(e), Self::NulInPath(e2)) => e == e2,
            (Self::ProtocolConfiguration, Self::ProtocolConfiguration) => true,
            (Self::Mutex, Self::Mutex) => true,
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

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::io::{self, ErrorKind};

    use super::SmbError;

    #[test]
    fn mutex_error_equals_itself() {
        assert_eq!(SmbError::Mutex, SmbError::Mutex);
    }

    #[test]
    fn errors_compare_by_variant_and_details() {
        assert_eq!(SmbError::BadFileDescriptor, SmbError::BadFileDescriptor);
        assert_eq!(SmbError::BadValue, SmbError::BadValue);
        assert_eq!(
            SmbError::Io(io::Error::from(ErrorKind::NotFound)),
            SmbError::Io(io::Error::from(ErrorKind::NotFound))
        );

        let left = CString::new("nul\0path").unwrap_err();
        let right = CString::new("nul\0path").unwrap_err();
        assert_eq!(SmbError::NulInPath(left), SmbError::NulInPath(right));
        assert_ne!(SmbError::BadValue, SmbError::BadFileDescriptor);
    }

    #[test]
    fn protocol_errors_compare_by_variant_and_details() {
        use crate::SmbDialect;

        assert_eq!(
            SmbError::InvalidProtocolRange {
                min: SmbDialect::Smb311,
                max: SmbDialect::Nt1
            },
            SmbError::InvalidProtocolRange {
                min: SmbDialect::Smb311,
                max: SmbDialect::Nt1
            }
        );
        assert_ne!(
            SmbError::InvalidProtocolRange {
                min: SmbDialect::Smb311,
                max: SmbDialect::Nt1
            },
            SmbError::ProtocolConfiguration
        );
        assert_eq!(
            SmbError::ProtocolConfiguration,
            SmbError::ProtocolConfiguration
        );
        assert_eq!(
            SmbError::InvalidProtocolRange {
                min: SmbDialect::Smb311,
                max: SmbDialect::Nt1
            }
            .to_string(),
            "invalid protocol range: minimum dialect SMB3_11 exceeds maximum dialect NT1"
        );
    }

    #[test]
    fn standard_errors_convert_to_smb_errors() {
        let io_error = io::Error::from(ErrorKind::PermissionDenied);
        assert_eq!(
            SmbError::from(io_error),
            SmbError::Io(io::Error::from(ErrorKind::PermissionDenied))
        );

        let nul_error = CString::new("nul\0path").unwrap_err();
        assert_eq!(
            SmbError::from(nul_error),
            SmbError::NulInPath(CString::new("nul\0path").unwrap_err())
        );
    }
}
