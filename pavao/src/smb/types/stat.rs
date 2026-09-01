//! Filesystem and directory-entry metadata returned by SMB servers.
#![allow(clippy::unnecessary_cast)]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use libc::{stat, statvfs, time_t};
use pavao_sys::libsmb_file_info;

use super::SmbMode;
use crate::utils::char_ptr_to_string;
use crate::{SmbDirentType, SmbError};

/// DOS directory attribute bit.
const FILE_ATTRIBUTE_DIRECTORY: u16 = 0x0010;

/// Filesystem statistics returned by [`SmbClient::statvfs`](crate::SmbClient::statvfs).
#[derive(Debug, Clone)]
pub struct SmbStatVfs {
    /// Filesystem block size in bytes.
    pub bsize: u64,
    /// Fundamental allocation unit in bytes.
    pub frsize: u64,
    /// Total filesystem size in `frsize` units.
    pub blocks: u64,
    /// Total number of free blocks.
    pub bfree: u64,
    /// Number of free blocks available to unprivileged users.
    pub bavail: u64,
    /// Total number of file nodes.
    pub files: u64,
    /// Total number of free file nodes.
    pub ffree: u64,
    /// Number of free file nodes available to unprivileged users.
    pub favail: u64,
    /// Filesystem identifier.
    pub fsid: u64,
    /// Filesystem mount flags.
    pub flag: u64,
    /// Maximum filename length in bytes.
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

/// POSIX-style metadata for a remote file or directory.
#[derive(Debug, Clone)]
pub struct SmbStat {
    /// Last access time.
    pub accessed: SystemTime,
    /// Number of blocks allocated to the entry.
    pub blocks: i64,
    /// Preferred block size for I/O.
    pub blksize: i64,
    /// Metadata-change time reported by `stat`.
    pub created: SystemTime,
    /// Device identifier.
    pub dev: i32,
    /// Owning group identifier.
    pub gid: u32,
    /// File type and POSIX permissions.
    pub mode: SmbMode,
    /// Last content-modification time.
    pub modified: SystemTime,
    /// Number of hard links to the entry.
    pub nlink: u64,
    /// Device identifier represented by a special file.
    pub rdev: u64,
    /// File size in bytes.
    pub size: u64,
    /// Owning user identifier.
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

/// A directory entry with metadata returned by an extended listing.
#[derive(Debug, Clone)]
pub struct SmbDirentInfo {
    /// Entry name.
    pub name: String,
    /// DOS-compatible short name, when available.
    pub short_name: String,
    /// File size in bytes.
    pub size: u64,
    /// DOS attribute bitmask.
    pub attrs: u16,
    /// Last metadata-change time.
    pub ctime: SystemTime,
    /// Creation time, or the Unix epoch when unsupported.
    pub btime: SystemTime,
    /// Last content-modification time.
    pub mtime: SystemTime,
    /// Last access time.
    pub atime: SystemTime,
    /// Owning user identifier.
    pub uid: u32,
    /// Owning group identifier.
    pub gid: u32,
}

impl SmbDirentInfo {
    /// Infers whether this entry is a file or directory from its DOS attributes.
    pub fn get_type(&self) -> SmbDirentType {
        if self.attrs & FILE_ATTRIBUTE_DIRECTORY != 0 {
            SmbDirentType::Dir
        } else {
            SmbDirentType::File
        }
    }

    /// Returns the entry name.
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// Returns the DOS-compatible short name.
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
