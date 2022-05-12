//! # mode
//!
//! provides types for POSIX file mode

use libc::mode_t;

/// Describes the permissions on POSIX system.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct SmbMode(SmbModeClass, SmbModeClass, SmbModeClass);

impl SmbMode {
    /// Create a new `SmbMode`
    pub fn new(user: SmbModeClass, group: SmbModeClass, others: SmbModeClass) -> Self {
        Self(user, group, others)
    }

    /// Returns unix permissions class for `user`
    pub fn user(&self) -> SmbModeClass {
        self.0
    }

    /// Returns unix permissions class for `group`
    pub fn group(&self) -> SmbModeClass {
        self.1
    }

    /// Returns unix permissions class for `others`
    pub fn others(&self) -> SmbModeClass {
        self.2
    }
}

impl From<SmbMode> for mode_t {
    fn from(pex: SmbMode) -> Self {
        (mode_t::from(pex.0) << 6) + (mode_t::from(pex.1) << 3) + mode_t::from(pex.2)
    }
}

impl From<mode_t> for SmbMode {
    fn from(x: mode_t) -> Self {
        SmbMode::new(
            SmbModeClass::from(((x >> 6) & 0x7) as mode_t),
            SmbModeClass::from(((x >> 3) & 0x7) as mode_t),
            SmbModeClass::from((x & 0x7) as mode_t),
        )
    }
}

/// Describes the permissions on POSIX system for a user class
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct SmbModeClass {
    read: bool,
    write: bool,
    execute: bool,
}

impl SmbModeClass {
    /// Instantiates a new `SmbMode`
    pub fn new(read: bool, write: bool, execute: bool) -> Self {
        Self {
            read,
            write,
            execute,
        }
    }

    /// Returns whether user can read
    pub fn read(&self) -> bool {
        self.read
    }

    /// Returns whether user can write
    pub fn write(&self) -> bool {
        self.write
    }

    /// Returns whether user can execute
    pub fn execute(&self) -> bool {
        self.execute
    }

    /// Convert permission to byte as on POSIX systems
    pub fn as_byte(&self) -> mode_t {
        ((self.read as mode_t) << 2) + ((self.write as mode_t) << 1) + (self.execute as mode_t)
    }
}

impl From<mode_t> for SmbModeClass {
    fn from(bits: mode_t) -> Self {
        Self {
            read: ((bits >> 2) & 0x01) != 0,
            write: ((bits >> 1) & 0x01) != 0,
            execute: (bits & 0x01) != 0,
        }
    }
}

impl From<SmbModeClass> for mode_t {
    fn from(pex: SmbModeClass) -> Self {
        ((pex.read as mode_t) << 2) + ((pex.write as mode_t) << 1) + (pex.execute as mode_t)
    }
}

#[cfg(test)]
mod test {

    use super::*;

    use pretty_assertions::assert_eq;

    #[test]
    fn should_create_unix_pex_class() {
        let pex: SmbModeClass = SmbModeClass::from(4);
        assert_eq!(pex.read(), true);
        assert_eq!(pex.write(), false);
        assert_eq!(pex.execute(), false);
        let pex: SmbModeClass = SmbModeClass::from(0);
        assert_eq!(pex.read(), false);
        assert_eq!(pex.write(), false);
        assert_eq!(pex.execute(), false);
        let pex: SmbModeClass = SmbModeClass::from(3);
        assert_eq!(pex.read(), false);
        assert_eq!(pex.write(), true);
        assert_eq!(pex.execute(), true);
        let pex: SmbModeClass = SmbModeClass::from(7);
        assert_eq!(pex.read(), true);
        assert_eq!(pex.write(), true);
        assert_eq!(pex.execute(), true);
        let pex: SmbModeClass = SmbModeClass::from(3);
        assert_eq!(pex.as_byte(), 3);
        let pex: SmbModeClass = SmbModeClass::from(7);
        assert_eq!(pex.as_byte(), 7);
    }

    #[test]
    fn should_create_unix_pex() {
        let pex = SmbMode::new(
            SmbModeClass::from(6),
            SmbModeClass::from(4),
            SmbModeClass::from(0),
        );
        assert_eq!(pex.user().as_byte(), 6);
        assert_eq!(pex.group().as_byte(), 4);
        assert_eq!(pex.others().as_byte(), 0);
    }

    #[test]
    fn should_convert_unix_pex_to_byte() {
        let pex = SmbMode::new(
            SmbModeClass::from(6),
            SmbModeClass::from(4),
            SmbModeClass::from(2),
        );
        assert_eq!(mode_t::from(pex), 0o642);
        let pex = SmbMode::new(
            SmbModeClass::from(7),
            SmbModeClass::from(5),
            SmbModeClass::from(5),
        );
        assert_eq!(mode_t::from(pex), 0o755);
    }

    #[test]
    fn should_convert_u32_to_unix_pex() {
        assert_eq!(
            SmbMode::from(0o754),
            SmbMode::new(
                SmbModeClass::from(7),
                SmbModeClass::from(5),
                SmbModeClass::from(4),
            )
        );
    }
}
