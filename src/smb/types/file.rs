//! # File
//!
//! file type returned by open functions on server

use crate::utils;
use crate::SmbClient;

use libc::{c_int, c_void, mode_t, off_t};
use smbclient_sys::*;
use std::io::{self, Read, Seek, SeekFrom, Write};

pub struct SmbFile<'a> {
    smbc: &'a SmbClient,
    fd: *mut SMBCFILE,
}

impl<'a> SmbFile<'a> {
    pub(crate) fn new(smbc: &'a SmbClient, fd: *mut SMBCFILE) -> Self {
        Self { smbc, fd }
    }
}

impl<'a> Read for SmbFile<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        trace!("reading file to buf [{:?};{}]", buf.as_ptr(), buf.len());
        let read_fn = self.smbc.get_fn(smbc_getFunctionRead)?;
        let bytes_read = utils::to_result_with_le(read_fn(
            self.smbc.ctx,
            self.fd,
            buf.as_mut_ptr() as *mut c_void,
            buf.len() as _,
        ))?;
        Ok(bytes_read as usize)
    }
}

impl<'a> Write for SmbFile<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        trace!("writing buf [{:?};{}] to file", buf.as_ptr(), buf.len());
        let write_fn = self.smbc.get_fn(smbc_getFunctionWrite)?;
        let bytes_wrote = utils::to_result_with_le(write_fn(
            self.smbc.ctx,
            self.fd,
            buf.as_ptr() as *const c_void,
            buf.len() as _,
        ))?;
        Ok(bytes_wrote as usize)
    }

    fn flush(&mut self) -> io::Result<()> {
        trace!("flush is not supported on SmbFile");
        Ok(())
    }
}

impl<'a> Seek for SmbFile<'a> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        trace!("seeking file at {:?}", pos);
        let lseek_fn = self.smbc.get_fn(smbc_getFunctionLseek)?;
        let (whence, off) = match pos {
            SeekFrom::Start(p) => (libc::SEEK_SET, p as off_t),
            SeekFrom::End(p) => (libc::SEEK_END, p as off_t),
            SeekFrom::Current(p) => (libc::SEEK_CUR, p as off_t),
        };
        let res = lseek_fn(self.smbc.ctx, self.fd, off, whence);
        let res = utils::to_result_with_errno(res, libc::EINVAL)?;
        Ok(res as u64)
    }
}

impl<'a> Drop for SmbFile<'a> {
    fn drop(&mut self) {
        trace!("closing file");
        if let Ok(close_fn) = self.smbc.get_fn(smbc_getFunctionClose) {
            close_fn(self.smbc.ctx, self.fd);
        }
    }
}

/// Describes options for opening file
#[derive(Clone, Copy, Debug)]
pub struct SmbOpenOptions {
    /// is *bitwise OR* of `O_CREAT`, `O_EXCL` and `O_TRUNC`
    flags: c_int,
    /// if readable
    read: bool,
    /// if writable
    write: bool,
    /// for posix file mode
    pub(crate) mode: mode_t,
}

impl Default for SmbOpenOptions {
    fn default() -> Self {
        Self {
            flags: 0,
            read: false,
            write: false,
            mode: 0o644,
        }
    }
}

impl SmbOpenOptions {
    /// Allows reading file
    pub fn read(mut self, read: bool) -> Self {
        self.read = read;
        self
    }

    /// Allows writing to file.
    pub fn write(mut self, write: bool) -> Self {
        self.write = write;
        self
    }

    /// Allows appending to file.
    pub fn append(mut self, append: bool) -> Self {
        self.flag(libc::O_APPEND, append);
        self
    }

    /// Allows creating file if it doesn't exists.
    ///
    /// Opening file will fail in case file exists if
    /// `exclusive` is also set.
    pub fn create(mut self, create: bool) -> Self {
        self.flag(libc::O_CREAT, create);
        self
    }

    /// File will be truncated if it's already exists.
    pub fn truncate(mut self, truncate: bool) -> Self {
        self.flag(libc::O_TRUNC, truncate);
        self
    }

    /// `open_*` will fail if file already exists (when used with `create` also set).
    pub fn exclusive(mut self, exclusive: bool) -> Self {
        self.flag(libc::O_EXCL, exclusive);
        self
    }

    /// Set POSIX file mode
    pub fn mode(mut self, mode: mode_t) -> Self {
        self.mode = mode;
        self
    }

    /// Naive impl, rewrite to check for incompatible flags
    pub(crate) fn to_flags(self) -> c_int {
        let base_mode = match (self.read, self.write) {
            // defaults to read only
            (false, false) | (true, false) => libc::O_RDONLY,
            (false, true) => libc::O_WRONLY,
            (true, true) => libc::O_RDWR,
        };
        base_mode | self.flags
    }

    /// flags value
    fn flag(&mut self, flag: c_int, on: bool) {
        if on {
            self.flags |= flag;
        } else {
            self.flags &= !flag;
        }
    }
}

#[cfg(test)]
mod test {

    use super::*;

    use pretty_assertions::assert_eq;

    #[test]
    fn should_initialize_open_options() {
        let open_opts = SmbOpenOptions::default();
        assert_eq!(open_opts.read, false);
        assert_eq!(open_opts.write, false);
        assert_eq!(open_opts.mode, 0o644);
        assert_eq!(open_opts.to_flags(), 0);
    }

    #[test]
    fn should_set_open_options() {
        let open_opts = SmbOpenOptions::default()
            .read(true)
            .write(true)
            .append(true)
            .exclusive(true)
            .create(true)
            .truncate(true)
            .mode(0o755);
        assert_eq!(open_opts.read, true);
        assert_eq!(open_opts.write, true);
        assert_eq!(open_opts.mode, 0o755);
        assert_eq!(
            open_opts.to_flags(),
            libc::O_RDWR | libc::O_TRUNC | libc::O_APPEND | libc::O_EXCL | libc::O_CREAT
        );
    }
}
