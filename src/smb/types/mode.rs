//! # mode
//!
//! provides types for POSIX file mode

use libc::{mode_t, S_IFDIR, S_IFSOCK, S_IFLNK, S_IFREG, S_IFBLK, S_IFCHR, S_IFIFO, S_IFMT};

/// Describes the permissions on POSIX system.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct SmbMode {
    type_: SmbFileType,
    mode: (SmbModeClass, SmbModeClass, SmbModeClass),
}

impl SmbMode {

    /// Returns the mode represents a regular file
    pub fn is_file(&self) -> bool {
        self.type_ == SmbFileType::RegularFile
    }

    /// Returns the mode represents a directory
    pub fn is_dir(&self) -> bool {
        self.type_ == SmbFileType::Directory
    }

    /// Returns the mode represents a block
    pub fn is_block(&self) -> bool {
        self.type_ == SmbFileType::Block
    }

    /// Returns the mode represents a character
    pub fn is_character(&self) -> bool {
        self.type_ == SmbFileType::Character
    }
    
    /// Returns the mode represents a pipe
    pub fn is_pipe(&self) -> bool {
        self.type_ == SmbFileType::Pipe
    }

    /// Returns the mode represents a socket
    pub fn is_socket(&self) -> bool {
        self.type_ == SmbFileType::Socket
    }

    /// Returns the mode represents a symlink
    pub fn is_symlink(&self) -> bool {
        self.type_ == SmbFileType::Symlink
    }

    /// Returns unix permissions class for `user`
    pub fn user(&self) -> SmbModeClass {
        self.mode.0
    }

    /// Returns unix permissions class for `group`
    pub fn group(&self) -> SmbModeClass {
        self.mode.1
    }

    /// Returns unix permissions class for `others`
    pub fn others(&self) -> SmbModeClass {
        self.mode.2
    }
}

impl From<SmbMode> for mode_t {
    fn from(pex: SmbMode) -> Self {
        (mode_t::from(pex.mode.0) << 6) + (mode_t::from(pex.mode.1) << 3) + mode_t::from(pex.mode.2)
    }
}

impl From<mode_t> for SmbMode {
    fn from(x: mode_t) -> Self {
        Self {
            type_: SmbFileType::from(x),
            mode: (
                SmbModeClass::from(((x >> 6) & 0x7) as mode_t),
            SmbModeClass::from(((x >> 3) & 0x7) as mode_t),
            SmbModeClass::from((x & 0x7) as mode_t)
            )
        }
    }
}

/// Describes the kind of file
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
enum SmbFileType {
    Block,
    Character,
    Directory,
    Pipe,
    RegularFile,
    Socket,
    Symlink,
}

impl From<mode_t> for SmbFileType {
    fn from(mode: mode_t) -> Self {
        let type_ = mode & S_IFMT;
        if type_ == S_IFSOCK {
            Self::Socket
        } else if type_ == S_IFLNK {
            Self::Symlink
        } else if type_ == S_IFREG {
            Self::RegularFile
        } else if type_  == S_IFBLK {
            Self::Block
        } else if type_ == S_IFDIR {
            Self::Directory
        } else if type_ == S_IFCHR {
            Self::Character
        } else if type_ == S_IFIFO {
            Self::Pipe
        } else {
            Self::RegularFile
        }
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
        let pex = SmbMode::from(0o640);
        assert_eq!(pex.user().as_byte(), 6);
        assert_eq!(pex.group().as_byte(), 4);
        assert_eq!(pex.others().as_byte(), 0);
    }

    #[test]
    fn should_convert_unix_pex_to_byte() {
        let pex = SmbMode::from(0o642);
        assert_eq!(mode_t::from(pex), 0o642);
        let pex = SmbMode::from(0o755);
        assert_eq!(mode_t::from(pex), 0o755);
    }

    #[test]
    fn should_convert_u32_to_unix_pex() {
        let _ = SmbMode::from(0o754);
    }
}
