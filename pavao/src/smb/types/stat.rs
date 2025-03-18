//! # Stat
//!
//! file stat type
#![allow(clippy::unnecessary_cast)]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use libc::{stat, statvfs, time_t};

use super::SmbMode;
use crate::libsmbclient::libsmb_file_info;
use crate::utils::char_ptr_to_string;
use crate::{SmbDirentType, SmbError};

/// DOS Attribute mask for DIRECTORY
const FILE_ATTRIBUTE_DIRECTORY: u16 = 0x0010;

/// Smb statvfs type
#[derive(Debug, Clone)]
pub struct SmbStatVfs {
    /// File system block size
    pub bsize: u64,
    /// Fragment size
    pub frsize: u64,
    /// Size of fs in f_frsize units
    pub blocks: u64,
    /// Number of free blocks
    pub bfree: u64,
    /// Number of free blocks for unprivileged users
    pub bavail: u64,
    /// Number of inodes
    pub files: u64,
    /// Number of free inodes
    pub ffree: u64,
    /// Number of free inodes for unprivileged users
    pub favail: u64,
    /// Filesystem ID
    pub fsid: u64,
    /// Mount flags
    pub flag: u64,
    /// Maximum filename length
    pub namemax: u64,
}

impl From<statvfs> for SmbStatVfs {
    fn from(s: statvfs) -> Self {
        Self {
            bsize: s.f_bsize as u64,
            frsize: s.f_frsize as u64,
            #[cfg(target_os = "android")]
            blocks: s.f_blocks,
            #[cfg(target_os = "macos")]
            blocks: s.f_blocks as u64,
            #[cfg(linux_x86_64)]
            blocks: s.f_blocks,
            #[cfg(linux_aarch64)]
            blocks: s.f_blocks,
            #[cfg(linux_arm)]
            blocks: s.f_blocks as u64,
            #[cfg(linux_riscv64)]
            blocks: s.f_blocks,
            #[cfg(target_os = "openbsd")]
            blocks: s.f_blocks,
            #[cfg(target_os = "android")]
            bfree: s.f_bfree,
            #[cfg(target_os = "macos")]
            bfree: s.f_bfree as u64,
            #[cfg(linux_x86_64)]
            bfree: s.f_bfree,
            #[cfg(linux_aarch64)]
            bfree: s.f_bfree,
            #[cfg(linux_arm)]
            bfree: s.f_bfree as u64,
            #[cfg(linux_riscv64)]
            bfree: s.f_bfree,
            #[cfg(target_os = "openbsd")]
            bfree: s.f_bfree,
            #[cfg(target_os = "android")]
            bavail: s.f_bavail,
            #[cfg(target_os = "macos")]
            bavail: s.f_bavail as u64,
            #[cfg(linux_x86_64)]
            bavail: s.f_bavail,
            #[cfg(linux_aarch64)]
            bavail: s.f_bavail,
            #[cfg(linux_arm)]
            bavail: s.f_bavail as u64,
            #[cfg(linux_riscv64)]
            bavail: s.f_bavail,
            #[cfg(target_os = "openbsd")]
            bavail: s.f_bavail,
            #[cfg(target_os = "android")]
            files: s.f_files,
            #[cfg(target_os = "macos")]
            files: s.f_files as u64,
            #[cfg(linux_x86_64)]
            files: s.f_files,
            #[cfg(linux_aarch64)]
            files: s.f_files,
            #[cfg(linux_arm)]
            files: s.f_files as u64,
            #[cfg(linux_riscv64)]
            files: s.f_files,
            #[cfg(target_os = "openbsd")]
            files: s.f_files,
            #[cfg(target_os = "android")]
            ffree: s.f_ffree,
            #[cfg(target_os = "macos")]
            ffree: s.f_ffree as u64,
            #[cfg(linux_x86_64)]
            ffree: s.f_ffree,
            #[cfg(linux_aarch64)]
            ffree: s.f_ffree,
            #[cfg(linux_arm)]
            ffree: s.f_ffree as u64,
            #[cfg(linux_riscv64)]
            ffree: s.f_ffree,
            #[cfg(target_os = "openbsd")]
            ffree: s.f_ffree,
            #[cfg(target_os = "android")]
            favail: s.f_favail,
            #[cfg(target_os = "macos")]
            favail: s.f_favail as u64,
            #[cfg(linux_x86_64)]
            favail: s.f_favail,
            #[cfg(linux_aarch64)]
            favail: s.f_favail,
            #[cfg(linux_arm)]
            favail: s.f_favail as u64,
            #[cfg(linux_riscv64)]
            favail: s.f_favail,
            #[cfg(target_os = "openbsd")]
            favail: s.f_favail,
            fsid: s.f_fsid as u64,
            flag: s.f_flag as u64,
            namemax: s.f_namemax as u64,
        }
    }
}

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
            blocks: s.st_blocks as i64,
            #[cfg(target_os = "android")]
            blksize: s.st_blksize as i64,
            #[cfg(target_os = "macos")]
            blksize: s.st_blksize as i64,
            #[cfg(linux_x86_64)]
            blksize: s.st_blksize,
            #[cfg(linux_aarch64)]
            blksize: s.st_blksize as i64,
            #[cfg(linux_arm)]
            blksize: s.st_blksize as i64,
            #[cfg(linux_riscv64)]
            blksize: s.st_blksize as i64,
            created: time_t_to_system_time(s.st_ctime),
            #[cfg(target_os = "openbsd")]
            blksize: s.st_blksize as i64,
            #[cfg(target_os = "android")]
            dev: s.st_dev as i32,
            #[cfg(target_os = "macos")]
            dev: s.st_dev,
            #[cfg(linux_x86_64)]
            dev: s.st_dev as i32,
            #[cfg(linux_aarch64)]
            dev: s.st_dev as i32,
            #[cfg(linux_arm)]
            dev: s.st_dev as i32,
            #[cfg(linux_riscv64)]
            dev: s.st_dev as i32,
            gid: s.st_gid,
            mode: SmbMode::from(s.st_mode),
            modified: time_t_to_system_time(s.st_mtime),
            #[cfg(target_os = "openbsd")]
            dev: s.st_dev as i32,
            #[cfg(target_os = "android")]
            nlink: s.st_nlink as u64,
            #[cfg(target_os = "macos")]
            nlink: s.st_nlink as u64,
            #[cfg(linux_x86_64)]
            nlink: s.st_nlink,
            #[cfg(linux_aarch64)]
            nlink: s.st_nlink as u64,
            #[cfg(linux_arm)]
            nlink: s.st_nlink as u64,
            #[cfg(linux_riscv64)]
            nlink: s.st_nlink as u64,
            #[cfg(target_os = "openbsd")]
            nlink: s.st_nlink as u64,
            #[cfg(target_os = "android")]
            rdev: s.st_rdev as u64,
            #[cfg(target_os = "macos")]
            rdev: s.st_rdev as u64,
            #[cfg(linux_x86_64)]
            rdev: s.st_rdev,
            #[cfg(linux_aarch64)]
            rdev: s.st_rdev as u64,
            #[cfg(linux_arm)]
            rdev: s.st_rdev as u64,
            #[cfg(linux_riscv64)]
            rdev: s.st_rdev as u64,
            #[cfg(target_os = "openbsd")]
            rdev: s.st_rdev as u64,
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
            size: di.size as u64,
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
