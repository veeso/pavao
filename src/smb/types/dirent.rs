//! # Directory entry
//!
//! module which exposes the smb dir entry

use crate::SmbError;

use libc::c_uint;

/// Smb directory entity
#[derive(Debug, Clone)]
pub struct SmbDirent {
    /// Directory entity type
    type_: SmbDirentType,
    comment: String,
    name: String,
}

impl SmbDirent {
    pub(crate) fn new<S: AsRef<str>>(type_: SmbDirentType, comment: S, name: S) -> Self {
        Self {
            type_,
            comment: comment.as_ref().to_string(),
            name: name.as_ref().to_string(),
        }
    }

    /// Get directory entity type
    pub fn get_type(&self) -> SmbDirentType {
        self.type_
    }

    /// Get comment
    pub fn comment(&self) -> &str {
        self.comment.as_str()
    }

    /// Get name
    pub fn name(&self) -> &str {
        self.name.as_str()
    }
}

/// Type of directory entity in the smb protocol
#[derive(Debug, Clone, Copy)]
pub enum SmbDirentType {
    Workgroup,
    Server,
    FileShare,
    PrinterShare,
    CommsShare,
    IpcShare,
    Dir,
    File,
    Link,
}

impl From<SmbDirentType> for c_uint {
    fn from(type_: SmbDirentType) -> Self {
        match type_ {
            SmbDirentType::Workgroup => 1,
            SmbDirentType::Server => 2,
            SmbDirentType::FileShare => 3,
            SmbDirentType::PrinterShare => 4,
            SmbDirentType::CommsShare => 5,
            SmbDirentType::IpcShare => 6,
            SmbDirentType::Dir => 7,
            SmbDirentType::File => 8,
            SmbDirentType::Link => 9,
        }
    }
}

impl TryFrom<c_uint> for SmbDirentType {
    type Error = SmbError;

    fn try_from(value: c_uint) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Workgroup),
            2 => Ok(Self::Server),
            3 => Ok(Self::FileShare),
            4 => Ok(Self::PrinterShare),
            5 => Ok(Self::CommsShare),
            6 => Ok(Self::IpcShare),
            7 => Ok(Self::Dir),
            8 => Ok(Self::File),
            9 => Ok(Self::Link),
            _ => Err(Self::Error::BadValue),
        }
    }
}

#[cfg(test)]
mod test {

    use super::*;

    use pretty_assertions::assert_eq;

    #[test]
    fn should_initialize_dirent() {
        todo!();
    }

    #[test]
    fn should_convert_dirent_type_to_uint() {
        todo!();
    }

    #[test]
    fn should_convert_uint_to_dirent_type() {
        todo!();
    }
}
