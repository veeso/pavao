//! # Stat
//!
//! file stat type

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use libc::{stat, time_t};

use super::SmbMode;
use crate::libsmbclient::libsmb_file_info;
use crate::utils::char_ptr_to_string;
use crate::{SmbDirentType, SmbError};

/// DOS Attribute mask for DIRECTORY
const FILE_ATTRIBUTE_DIRECTORY: u16 = 0x0010;

/// Smb stat type
#[derive(Debug, Clone)]
pub struct SmbStat {
    /// Last access time
    pub accessed: SystemTime,
    /// Blocks occupied by file
    pub blocks: i64,
    /// Block size
    pub blksize: i64,
    /// Creation time
    pub created: SystemTime,
    /// Device
    pub dev: i32,
    /// Group id
    pub gid: u32,
    /// Unix permissions
    pub mode: SmbMode,
    /// Modify time
    pub modified: SystemTime,
    /// Link associated to file
    pub nlink: u64,
    pub rdev: u64,
    /// File size in bytes
    pub size: u64,
    /// User id
    pub uid: u32,
}

impl From<stat> for SmbStat {
    fn from(s: stat) -> Self {
        Self {
            accessed: time_t_to_system_time(s.st_atime),
            blocks: s.st_blocks,
            #[cfg(target_os = "macos")]
            blksize: s.st_blksize as i64,
            #[cfg(not(target_os = "macos"))]
            blksize: s.st_blksize,
            created: time_t_to_system_time(s.st_ctime),
            #[cfg(target_os = "macos")]
            dev: s.st_dev,
            #[cfg(not(target_os = "macos"))]
            dev: s.st_dev as i32,
            gid: s.st_gid,
            mode: SmbMode::from(s.st_mode),
            modified: time_t_to_system_time(s.st_mtime),
            #[cfg(target_os = "macos")]
            nlink: s.st_nlink as u64,
            #[cfg(not(target_os = "macos"))]
            nlink: s.st_nlink,
            #[cfg(target_os = "macos")]
            rdev: s.st_rdev as u64,
            #[cfg(not(target_os = "macos"))]
            rdev: s.st_rdev,
            size: s.st_size as u64,
            uid: s.st_uid,
        }
    }
}

/// SMB directory entity with metadata
#[derive(Debug, Clone)]
pub struct SmbDirentInfo {
    /// Name of file
    pub name: String,
    /// Short name of file
    pub short_name: String,
    /// Size of file
    pub size: u64,
    /// DOS attributes of file
    pub attrs: u16,
    /// Change time for the file
    pub ctime: SystemTime,
    /// Birth/Create time of file (if not supported, it will be 0)
    pub btime: SystemTime,
    /// Modified time for the file
    pub mtime: SystemTime,
    /// Access time for the file
    pub atime: SystemTime,
    /// Group ID of file
    pub uid: u32,
    /// User ID of file
    pub gid: u32,
}

impl SmbDirentInfo {
    /// Get directory entity type
    pub fn get_type(&self) -> SmbDirentType {
        if self.attrs & FILE_ATTRIBUTE_DIRECTORY != 0 {
            SmbDirentType::Dir
        } else {
            SmbDirentType::File
        }
    }

    /// Get name
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// Get short name
    pub fn short_name(&self) -> &str {
        self.short_name.as_str()
    }
}

impl TryFrom<libsmb_file_info> for SmbDirentInfo {
    type Error = SmbError;

    fn try_from(di: libsmb_file_info) -> Result<Self, Self::Error> {
        let name = char_ptr_to_string(di.name)?;
        let short_name = char_ptr_to_string(di.short_name)?;

        Ok(Self {
            name,
            short_name,
            size: di.size,
            ctime: time_t_to_system_time(di.ctime_ts.tv_sec),
            btime: time_t_to_system_time(di.btime_ts.tv_sec),
            mtime: time_t_to_system_time(di.mtime_ts.tv_sec),
            atime: time_t_to_system_time(di.atime_ts.tv_sec),
            uid: di.uid,
            gid: di.gid,
            attrs: di.attrs,
        })
    }
}

fn time_t_to_system_time(t: time_t) -> SystemTime {
    UNIX_EPOCH
        .checked_add(Duration::from_secs(t as u64))
        .unwrap_or(UNIX_EPOCH)
}

#[cfg(test)]
mod test {

    use pretty_assertions::assert_ne;

    use super::*;

    #[test]
    fn should_convert_time_t_into_system_time() {
        assert_ne!(time_t_to_system_time(1000), UNIX_EPOCH);
    }
}
