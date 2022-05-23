//! # Directory entry
//!
//! module which exposes the smb dir entry

use crate::utils::char_ptr_to_string;
use crate::SmbError;

use crate::libsmbclient::smbc_dirent;
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

impl TryFrom<smbc_dirent> for SmbDirent {
    type Error = SmbError;

    fn try_from(d: smbc_dirent) -> Result<Self, Self::Error> {
        let comment = char_ptr_to_string(d.comment)?;
        let name = char_ptr_to_string(d.name.as_slice().as_ptr())?;
        Ok(Self {
            type_: SmbDirentType::try_from(d.smbc_type)?,
            comment,
            name,
        })
    }
}

/// Type of directory entity in the smb protocol
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
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
    use crate::utils;

    use pretty_assertions::assert_eq;

    #[test]
    fn should_convert_dirent_type_to_uint() {
        assert_eq!(c_uint::from(SmbDirentType::Workgroup), 1);
        assert_eq!(c_uint::from(SmbDirentType::Server), 2);
        assert_eq!(c_uint::from(SmbDirentType::FileShare), 3);
        assert_eq!(c_uint::from(SmbDirentType::PrinterShare), 4);
        assert_eq!(c_uint::from(SmbDirentType::CommsShare), 5);
        assert_eq!(c_uint::from(SmbDirentType::IpcShare), 6);
        assert_eq!(c_uint::from(SmbDirentType::Dir), 7);
        assert_eq!(c_uint::from(SmbDirentType::File), 8);
        assert_eq!(c_uint::from(SmbDirentType::Link), 9);
    }

    #[test]
    fn should_convert_uint_to_dirent_type() {
        assert_eq!(
            SmbDirentType::try_from(1).unwrap(),
            SmbDirentType::Workgroup
        );
        assert_eq!(SmbDirentType::try_from(2).unwrap(), SmbDirentType::Server);
        assert_eq!(
            SmbDirentType::try_from(3).unwrap(),
            SmbDirentType::FileShare
        );
        assert_eq!(
            SmbDirentType::try_from(4).unwrap(),
            SmbDirentType::PrinterShare
        );
        assert_eq!(
            SmbDirentType::try_from(5).unwrap(),
            SmbDirentType::CommsShare
        );
        assert_eq!(SmbDirentType::try_from(6).unwrap(), SmbDirentType::IpcShare);
        assert_eq!(SmbDirentType::try_from(7).unwrap(), SmbDirentType::Dir);
        assert_eq!(SmbDirentType::try_from(8).unwrap(), SmbDirentType::File);
        assert_eq!(SmbDirentType::try_from(9).unwrap(), SmbDirentType::Link);
    }

    #[test]
    fn should_not_convert_bad_dirent_type() {
        assert!(SmbDirentType::try_from(100).is_err());
    }

    #[test]
    fn should_convert_dirent_to_smb_dirent() {
        let mut dirent = smbc_dirent::default();
        let comment = String::from("test");
        let comment_ptr = utils::str_to_cstring(comment).unwrap();
        dirent.smbc_type = 8;
        dirent.comment = comment_ptr.into_raw();
        dirent.commentlen = 5;
        dirent.name = [0; 1024];
        dirent.namelen = 1;
        dirent.name[0] = 'h' as i8;
        dirent.name[1] = 'e' as i8;
        dirent.name[2] = 'l' as i8;
        dirent.name[3] = 'l' as i8;
        dirent.name[4] = 'o' as i8;
        let dirent = SmbDirent::try_from(dirent).unwrap();
        assert_eq!(dirent.get_type(), SmbDirentType::File);
        assert_eq!(dirent.name(), "hello");
        assert_eq!(dirent.comment(), "test");
    }

    #[test]
    fn should_fail_conversion_from_smbc_dirent() {
        assert!(SmbDirent::try_from(smbc_dirent::default()).is_err());
    }
}
