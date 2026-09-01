//! Remote files and file-opening options.

use std::io::{self, Read, Seek, SeekFrom, Write};

use libc::{c_int, c_void, mode_t, off_t};
use pavao_sys::{
    SMBCFILE, smbc_getFunctionClose, smbc_getFunctionLseek, smbc_getFunctionRead,
    smbc_getFunctionWrite,
};

use crate::{SmbClient, utils};

#[derive(Debug)]
/// An open remote file owned by an [`SmbClient`].
///
/// `SmbFile` implements [`Read`], [`Write`], and [`Seek`]. Dropping it attempts to close the native
/// file handle; closure is skipped if the close callback is unavailable.
/// [`Write::flush`] is a no-op because `libsmbclient` exposes no flush operation.
///
/// Every native file operation is serialized with all other Pavão SMB operations in the process.
/// A blocking read, write, seek, or close delays operations on every client.
pub struct SmbFile<'a> {
    smbc: &'a SmbClient,
    fd: *mut SMBCFILE,
}

impl<'a> SmbFile<'a> {
    pub(crate) fn new(smbc: &'a SmbClient, fd: *mut SMBCFILE) -> Self {
        Self { smbc, fd }
    }
}

impl Read for SmbFile<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        trace!(
            "reading file to buf [{pointer:?};{length}]",
            pointer = buf.as_ptr(),
            length = buf.len()
        );
        self.smbc.with_context_io(|ctx| {
            let read_fn = self.smbc.get_fn(ctx, smbc_getFunctionRead)?;
            let bytes_read = utils::to_result_with_le(read_fn(
                ctx,
                self.fd,
                buf.as_mut_ptr() as *mut c_void,
                buf.len() as _,
            ))?;
            Ok(bytes_read as usize)
        })
    }
}

impl Write for SmbFile<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        trace!(
            "writing buf [{pointer:?};{length}] to file",
            pointer = buf.as_ptr(),
            length = buf.len()
        );
        self.smbc.with_context_io(|ctx| {
            let write_fn = self.smbc.get_fn(ctx, smbc_getFunctionWrite)?;
            let bytes_wrote = utils::to_result_with_le(write_fn(
                ctx,
                self.fd,
                buf.as_ptr() as *const c_void,
                buf.len() as _,
            ))?;
            Ok(bytes_wrote as usize)
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        trace!("flush is not supported on SmbFile");
        Ok(())
    }
}

impl Seek for SmbFile<'_> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        trace!("seeking file at {pos:?}");
        let (whence, off) = match pos {
            SeekFrom::Start(p) => (libc::SEEK_SET, p as off_t),
            SeekFrom::End(p) => (libc::SEEK_END, p as off_t),
            SeekFrom::Current(p) => (libc::SEEK_CUR, p as off_t),
        };
        self.smbc.with_context_io(|ctx| {
            let lseek_fn = self.smbc.get_fn(ctx, smbc_getFunctionLseek)?;
            let res = lseek_fn(ctx, self.fd, off, whence);
            let res = utils::to_result_with_errno(res, libc::EINVAL)?;
            Ok(res as u64)
        })
    }
}

impl Drop for SmbFile<'_> {
    fn drop(&mut self) {
        trace!("closing file");
        let _ = self.smbc.with_context_io(|ctx| {
            let close_fn = self.smbc.get_fn(ctx, smbc_getFunctionClose)?;
            close_fn(ctx, self.fd);
            Ok(())
        });
    }
}

/// Options controlling how a remote file is opened.
///
/// The default configuration opens an existing file for reading with mode `0o644`.
///
/// # Examples
///
/// ```
/// use pavao::SmbOpenOptions;
///
/// let options = SmbOpenOptions::default()
///     .read(true)
///     .write(true)
///     .create(true)
///     .truncate(true)
///     .mode(0o640);
/// ```
#[derive(Clone, Copy, Debug)]
pub struct SmbOpenOptions {
    /// Bitwise combination of the requested creation and append flags.
    flags: c_int,
    /// Whether the handle permits reading.
    read: bool,
    /// Whether the handle permits writing.
    write: bool,
    /// POSIX mode used when a file is created.
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
    /// Controls whether the opened file permits reading.
    pub fn read(mut self, read: bool) -> Self {
        self.read = read;
        self
    }

    /// Controls whether the opened file permits writing.
    pub fn write(mut self, write: bool) -> Self {
        self.write = write;
        self
    }

    /// Controls whether writes append to the end of the file.
    pub fn append(mut self, append: bool) -> Self {
        self.flag(libc::O_APPEND, append);
        self
    }

    /// Controls whether the file is created when it does not exist.
    ///
    /// Opening fails if the file exists when [`Self::exclusive`] is also enabled.
    pub fn create(mut self, create: bool) -> Self {
        self.flag(libc::O_CREAT, create);
        self
    }

    /// Controls whether an existing file is truncated when opened.
    pub fn truncate(mut self, truncate: bool) -> Self {
        self.flag(libc::O_TRUNC, truncate);
        self
    }

    /// Controls whether creation fails when the file already exists.
    ///
    /// This option takes effect when [`Self::create`] is also enabled.
    pub fn exclusive(mut self, exclusive: bool) -> Self {
        self.flag(libc::O_EXCL, exclusive);
        self
    }

    /// Sets the POSIX permission mode used when creating a file.
    pub fn mode(mut self, mode: mode_t) -> Self {
        self.mode = mode;
        self
    }

    // Converts the configured access options to native `open` flags.
    pub(crate) fn to_flags(self) -> c_int {
        let base_mode = match (self.read, self.write) {
            // defaults to read only
            (false, false) | (true, false) => libc::O_RDONLY,
            (false, true) => libc::O_WRONLY,
            (true, true) => libc::O_RDWR,
        };
        base_mode | self.flags
    }

    // Enables or disables one native `open` flag.
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

    use pretty_assertions::assert_eq;

    use super::*;

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
