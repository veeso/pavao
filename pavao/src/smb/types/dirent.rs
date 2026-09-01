//! Directory entries returned by SMB browse operations.

use libc::c_uint;
use pavao_sys::smbc_dirent;

use crate::SmbError;
use crate::utils::char_ptr_to_string;

/// A directory entry returned by [`SmbClient::list_dir`](crate::SmbClient::list_dir).
#[derive(Debug, Clone)]
pub struct SmbDirent {
    /// The kind of resource represented by this entry.
    type_: SmbDirentType,
    comment: String,
    name: String,
}

impl SmbDirent {
    /// Returns the resource type reported by the SMB server.
    pub fn get_type(&self) -> SmbDirentType {
        self.type_
    }

    /// Returns the server-provided comment for this entry.
    pub fn comment(&self) -> &str {
        self.comment.as_str()
    }

    /// Returns the entry name.
    pub fn name(&self) -> &str {
        self.name.as_str()
    }
}

impl TryFrom<&smbc_dirent> for SmbDirent {
    type Error = SmbError;

    fn try_from(d: &smbc_dirent) -> Result<Self, Self::Error> {
        let comment = char_ptr_to_string(d.comment)?;
        let name = unsafe {
            // `dirlen` includes the flexible name storage returned by `libsmbclient`.
            let bytes =
                std::slice::from_raw_parts(d.name.as_ptr().cast::<u8>(), d.namelen as usize + 1);
            std::ffi::CStr::from_bytes_with_nul(bytes)
                .map_err(|_| SmbError::BadValue)?
                .to_str()
                .map_err(|_| SmbError::BadValue)?
                .to_owned()
        };
        Ok(Self {
            type_: SmbDirentType::try_from(d.smbc_type)?,
            comment,
            name,
        })
    }
}

/// The resource category reported for an SMB directory entry.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SmbDirentType {
    /// A Windows workgroup or domain.
    Workgroup,
    /// An SMB server.
    Server,
    /// A shared filesystem.
    FileShare,
    /// A shared printer.
    PrinterShare,
    /// A shared communications device.
    CommsShare,
    /// An inter-process communication share.
    IpcShare,
    /// A directory.
    Dir,
    /// A regular file.
    File,
    /// A symbolic link.
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

    use libc::c_char;
    use pretty_assertions::assert_eq;

    use super::*;

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

    #[repr(C)]
    struct ShortDirent {
        smbc_type: c_uint,
        dirlen: c_uint,
        commentlen: c_uint,
        comment: *mut c_char,
        namelen: c_uint,
        name: [c_char; 4],
    }

    #[repr(C)]
    struct LongDirent {
        smbc_type: c_uint,
        dirlen: c_uint,
        commentlen: c_uint,
        comment: *mut c_char,
        namelen: c_uint,
        name: [c_char; 6],
    }

    #[test]
    fn converts_variable_length_dirent_without_overread() {
        let raw = ShortDirent {
            smbc_type: 8,
            dirlen: std::mem::size_of::<ShortDirent>() as c_uint,
            commentlen: 7,
            comment: c"comment".as_ptr().cast_mut(),
            namelen: 3,
            name: [b'a' as c_char, b'b' as c_char, b'c' as c_char, 0],
        };
        let entry = unsafe { &*std::ptr::from_ref(&raw).cast::<smbc_dirent>() };
        let converted = SmbDirent::try_from(entry).unwrap();

        assert_eq!(converted.name(), "abc");
        assert_eq!(converted.comment(), "comment");
    }

    #[test]
    fn should_convert_dirent_to_smb_dirent() {
        let raw = LongDirent {
            smbc_type: 8,
            dirlen: std::mem::size_of::<LongDirent>() as c_uint,
            commentlen: 4,
            comment: c"test".as_ptr().cast_mut(),
            namelen: 5,
            name: [
                b'h' as c_char,
                b'e' as c_char,
                b'l' as c_char,
                b'l' as c_char,
                b'o' as c_char,
                0,
            ],
        };
        let dirent = unsafe { &*std::ptr::from_ref(&raw).cast::<smbc_dirent>() };
        let dirent = SmbDirent::try_from(dirent).unwrap();
        assert_eq!(dirent.get_type(), SmbDirentType::File);
        assert_eq!(dirent.name(), "hello");
        assert_eq!(dirent.comment(), "test");
    }

    #[test]
    fn should_fail_conversion_from_smbc_dirent() {
        let raw = ShortDirent {
            smbc_type: 0,
            dirlen: std::mem::size_of::<ShortDirent>() as c_uint,
            commentlen: 0,
            comment: std::ptr::null_mut(),
            namelen: 3,
            name: [0; 4],
        };
        let dirent = unsafe { &*std::ptr::from_ref(&raw).cast::<smbc_dirent>() };
        assert!(SmbDirent::try_from(dirent).is_err());
    }
}
