//! SMB protocol dialects used to bound negotiation.

use std::ffi::CStr;
use std::fmt;

/// An SMB protocol dialect offered during negotiation.
///
/// Variants are ordered from oldest to newest, so [`Ord`] comparisons follow protocol age.
/// [`Nt1`](SmbDialect::Nt1) is the deprecated SMB1/CIFS dialect and should be requested only
/// for legacy devices that cannot speak SMB2 or SMB3.
///
/// # Examples
///
/// ```
/// use pavao::SmbDialect;
///
/// let dialect = SmbDialect::Smb311;
/// assert_eq!(dialect.to_string(), "SMB3_11");
/// assert!(SmbDialect::Smb202 < dialect);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SmbDialect {
    /// The SMB1/CIFS `NT1` dialect. Deprecated and insecure; use only for legacy devices.
    Nt1,
    /// The SMB 2.0.2 dialect.
    Smb202,
    /// The SMB 2.1 dialect.
    Smb210,
    /// The SMB 3.0 dialect.
    Smb300,
    /// The SMB 3.0.2 dialect.
    Smb302,
    /// The SMB 3.1.1 dialect.
    Smb311,
}

impl SmbDialect {
    /// Returns the static Samba protocol name for this dialect.
    pub(crate) fn as_cstr(self) -> &'static CStr {
        match self {
            Self::Nt1 => c"NT1",
            Self::Smb202 => c"SMB2_02",
            Self::Smb210 => c"SMB2_10",
            Self::Smb300 => c"SMB3_00",
            Self::Smb302 => c"SMB3_02",
            Self::Smb311 => c"SMB3_11",
        }
    }
}

impl fmt::Display for SmbDialect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{name}",
            name = self.as_cstr().to_str().expect("dialect names are ASCII")
        )
    }
}

#[cfg(test)]
mod test {

    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn should_map_each_dialect_to_the_samba_protocol_string() {
        assert_eq!(SmbDialect::Nt1.as_cstr(), c"NT1");
        assert_eq!(SmbDialect::Smb202.as_cstr(), c"SMB2_02");
        assert_eq!(SmbDialect::Smb210.as_cstr(), c"SMB2_10");
        assert_eq!(SmbDialect::Smb300.as_cstr(), c"SMB3_00");
        assert_eq!(SmbDialect::Smb302.as_cstr(), c"SMB3_02");
        assert_eq!(SmbDialect::Smb311.as_cstr(), c"SMB3_11");
    }

    #[test]
    fn should_order_dialects_from_oldest_to_newest() {
        assert!(SmbDialect::Nt1 < SmbDialect::Smb202);
        assert!(SmbDialect::Smb202 < SmbDialect::Smb210);
        assert!(SmbDialect::Smb210 < SmbDialect::Smb300);
        assert!(SmbDialect::Smb300 < SmbDialect::Smb302);
        assert!(SmbDialect::Smb302 < SmbDialect::Smb311);
    }

    #[test]
    fn should_display_the_samba_protocol_name() {
        assert_eq!(SmbDialect::Nt1.to_string(), "NT1");
        assert_eq!(SmbDialect::Smb311.to_string(), "SMB3_11");
    }
}
