//! # Stat
//!
//! file stat type

use super::SmbMode;

use libc::{stat, time_t};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
            accessed: i64_to_system_time(s.st_atime),
            blocks: s.st_blocks as i64,
            blksize: s.st_blksize as i64,
            created: i64_to_system_time(s.st_ctime),
            dev: s.st_dev as i32,
            gid: s.st_gid as u32,
            mode: SmbMode::from(s.st_mode),
            modified: i64_to_system_time(s.st_mtime),
            nlink: s.st_nlink as u64,
            rdev: s.st_rdev as u64,
            size: s.st_size as u64,
            uid: s.st_uid as u32,
        }
    }
}

fn i64_to_system_time(t: time_t) -> SystemTime {
    UNIX_EPOCH
        .checked_add(Duration::from_secs(t as u64))
        .unwrap_or(UNIX_EPOCH)
}

#[cfg(test)]
mod test {

    use super::*;

    use pretty_assertions::assert_eq;

    #[test]
    fn should_convert_libc_stat_into_smbstat() {
        todo!()
    }
}
