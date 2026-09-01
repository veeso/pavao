#![warn(missing_docs)]

//! Raw Rust bindings to Samba's `libsmbclient` library.
//!
//! This crate mirrors the native C types and functions. Most callers should use the safe
//! [`pavao`](https://docs.rs/pavao) crate instead.
//!
//! # Safety
//!
//! The bindings do not validate pointers, lifetimes, buffer lengths, context state, or native
//! return values. Callers must uphold the corresponding `libsmbclient` C API contracts.
//!
//! # Callback contracts
//!
//! Unless an alias says otherwise, callbacks require a live, initialized context; every file or
//! directory handle must be live and belong to that context; C strings must be NUL-terminated and
//! readable for the call; and buffers must be valid for the supplied size. File and directory
//! operation callbacks generally return `-1` or null with `errno` set on failure. Server-cache
//! callbacks instead return one on failure and do not promise an `errno` value. Callback
//! implementations must not unwind across the C ABI boundary.
//!
//! Directory-entry pointers are borrowed from `libsmbclient`. They may be invalidated by the next
//! read on the same directory or when the directory is closed, so callers must copy needed data.
//!
//! # Feature flags
//!
//! | name       | description                                         | default |
//! |------------|-----------------------------------------------------|---------|
//! | `vendored` | Build the bundled Samba source instead of using the system library. |         |
//!

#![doc(html_playground_url = "https://play.rust-lang.org")]
#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/veeso/pavao/main/docs/images/pavao.png"
)]
#![doc(html_logo_url = "https://raw.githubusercontent.com/veeso/pavao/main/docs/images/pavao.png")]
#![allow(non_camel_case_types)]
#![allow(clippy::upper_case_acronyms)]
use std::{clone, default, mem, option};

use libc::{
    c_char, c_int, c_uint, c_ulong, c_ushort, c_void, mode_t, off_t, size_t, ssize_t, stat,
    statvfs, time_t, timespec, timeval,
};

#[repr(C)]
#[derive(Copy)]
/// A directory entry returned by `libsmbclient`.
pub struct smbc_dirent {
    /// Native entry type discriminator.
    ///
    /// Values 1 through 9 represent workgroups, servers, file shares, printer shares,
    /// communications shares, IPC shares, directories, files, and links, respectively.
    pub smbc_type: c_uint,
    /// Total size of this directory-entry structure in bytes.
    pub dirlen: c_uint,
    /// Length of `comment` in bytes, excluding its terminating NUL byte.
    pub commentlen: c_uint,
    /// Pointer to the NUL-terminated entry comment.
    pub comment: *mut c_char,
    /// Length of `name` in bytes, excluding its terminating NUL byte.
    pub namelen: c_uint,
    /// Fixed-size buffer containing the NUL-terminated entry name.
    pub name: [c_char; 1024usize],
}

impl clone::Clone for smbc_dirent {
    fn clone(&self) -> Self {
        *self
    }
}

impl default::Default for smbc_dirent {
    fn default() -> Self {
        unsafe { mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Copy)]
/// Extended directory-entry metadata returned by `libsmbclient`.
pub struct libsmb_file_info {
    /// File size in bytes.
    pub size: c_ulong,
    /// DOS attribute bitmask.
    pub attrs: c_ushort,
    /// Owning user identifier.
    pub uid: c_uint,
    /// Owning group identifier.
    pub gid: c_uint,
    /// Creation time, or zero when unsupported by the server.
    pub btime_ts: timespec,
    /// Last content-modification time.
    pub mtime_ts: timespec,
    /// Last access time.
    pub atime_ts: timespec,
    /// Last metadata-change time.
    pub ctime_ts: timespec,
    /// Pointer to the NUL-terminated entry name.
    pub name: *mut c_char,
    /// Pointer to the NUL-terminated DOS-compatible short name.
    pub short_name: *mut c_char,
}

impl clone::Clone for libsmb_file_info {
    fn clone(&self) -> Self {
        *self
    }
}

impl default::Default for libsmb_file_info {
    fn default() -> Self {
        unsafe { mem::zeroed() }
    }
}

/// Native value for the `open_share_mode` option.
pub type smbc_share_mode = c_uint;

/// Native value for the SMB transport encryption policy.
pub type smbc_smb_encrypt_level = c_uint;

/// Native Boolean represented as a C integer.
pub type smbc_bool = c_int;

#[repr(C)]
#[derive(Copy)]
/// Information about a queued SMB print job.
pub struct print_job_info {
    /// Numeric print-job identifier.
    pub id: c_ushort,
    /// Print priority, where lower values indicate higher priority.
    pub priority: c_ushort,
    /// Print-job size in bytes.
    pub size: size_t,
    /// NUL-terminated name of the user that owns the job.
    pub user: [c_char; 128usize],
    /// NUL-terminated job name, empty for an anonymous printer file.
    pub name: [c_char; 128usize],
    /// Time at which the job was spooled.
    pub t: time_t,
}

impl clone::Clone for print_job_info {
    fn clone(&self) -> Self {
        *self
    }
}

impl default::Default for print_job_info {
    fn default() -> Self {
        unsafe { mem::zeroed() }
    }
}

/// Opaque native SMB server handle.
pub enum _SMBCSRV {}
/// Native SMB server handle.
pub type SMBCSRV = _SMBCSRV;
/// Opaque native SMB file or directory handle.
pub enum _SMBCFILE {}
/// Native SMB file or directory handle.
pub type SMBCFILE = _SMBCFILE;
/// Native `libsmbclient` context.
pub type SMBCCTX = _SMBCCTX;

/// Optional callback that supplies authentication strings.
///
/// `srv` and `shr` are borrowed NUL-terminated strings. The callback must write NUL-terminated
/// workgroup, username, and password values without exceeding `wglen`, `unlen`, and `pwlen`.
pub type smbc_get_auth_data_fn = option::Option<
    extern "C" fn(
        srv: *const c_char,
        shr: *const c_char,
        wg: *mut c_char,
        wglen: c_int,
        un: *mut c_char,
        unlen: c_int,
        pw: *mut c_char,
        pwlen: c_int,
    ),
>;
/// Optional context-aware callback that supplies authentication strings.
///
/// `c` must be live, `srv` and `shr` are borrowed NUL-terminated strings, and each output buffer
/// must receive a NUL-terminated value without exceeding its corresponding length.
pub type smbc_get_auth_data_with_context_fn = Option<
    extern "C" fn(
        c: *mut SMBCCTX,
        srv: *const c_char,
        shr: *const c_char,
        wg: *mut c_char,
        wglen: c_int,
        un: *mut c_char,
        unlen: c_int,
        pw: *mut c_char,
        pwlen: c_int,
    ),
>;
/// Optional callback invoked for each print job in a queue.
///
/// `i` is borrowed for the callback invocation and must not be retained or freed.
pub type smbc_list_print_job_fn = option::Option<extern "C" fn(i: *mut print_job_info)>;
/// Optional callback that checks whether a cached server is still available.
///
/// `srv` must be a live server handle associated with `c`. Returns zero on success or one on
/// failure.
pub type smbc_check_server_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, srv: *mut SMBCSRV) -> c_int>;
/// Optional callback that removes an unused cached server.
///
/// `srv` must be a live server handle associated with `c`. Returns zero on success or one on
/// failure.
pub type smbc_remove_unused_server_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, srv: *mut SMBCSRV) -> c_int>;
/// Optional callback that inserts a server into the connection cache.
///
/// `srv` must be live, and all name pointers must reference NUL-terminated strings for the call.
/// Returns zero on success or one on failure.
pub type smbc_add_cached_srv_fn = option::Option<
    extern "C" fn(
        c: *mut SMBCCTX,
        srv: *mut SMBCSRV,
        server: *const c_char,
        share: *const c_char,
        workgroup: *const c_char,
        username: *const c_char,
    ) -> c_int,
>;
/// Optional callback that looks up a server in the connection cache.
///
/// All name pointers must reference NUL-terminated strings for the call. A non-null result is a
/// borrowed cache entry owned by `c`; null indicates no match or failure.
pub type smbc_get_cached_srv_fn = option::Option<
    extern "C" fn(
        c: *mut SMBCCTX,
        server: *const c_char,
        share: *const c_char,
        workgroup: *const c_char,
        username: *const c_char,
    ) -> *mut SMBCSRV,
>;
/// Optional callback that removes a server from the connection cache.
///
/// `srv` must be a live server handle associated with `c`. Returns zero on success or one on
/// failure.
pub type smbc_remove_cached_srv_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, srv: *mut SMBCSRV) -> c_int>;
/// Optional callback that purges the connection cache.
///
/// Returns zero on success or one when cached servers remain in use.
pub type smbc_purge_cached_fn = option::Option<extern "C" fn(c: *mut SMBCCTX) -> c_int>;

/// Optional callback that opens a remote file.
///
/// `fname` must be a NUL-terminated SMB URL and `flags` must be valid native open flags. Returns a
/// live file handle owned by `c`, or null with `errno` set on failure.
pub type smbc_open_fn = option::Option<
    extern "C" fn(
        c: *mut SMBCCTX,
        fname: *const c_char,
        flags: c_int,
        mode: mode_t,
    ) -> *mut SMBCFILE,
>;
/// Optional callback that creates a remote file.
///
/// `path` must be a NUL-terminated SMB URL. Returns a live file handle owned by `c`, or null with
/// `errno` set on failure.
pub type smbc_creat_fn = option::Option<
    extern "C" fn(c: *mut SMBCCTX, path: *const c_char, mode: mode_t) -> *mut SMBCFILE,
>;
/// Optional callback that reads bytes from an open remote file.
///
/// `file` must be live and belong to `c`; `buf` must be writable for `count` bytes. Returns the
/// number of bytes read, zero at end of file, or `-1` with `errno` set on failure.
pub type smbc_read_fn = option::Option<
    extern "C" fn(c: *mut SMBCCTX, file: *mut SMBCFILE, buf: *mut c_void, count: size_t) -> ssize_t,
>;
/// Optional callback that writes bytes to an open remote file.
///
/// `file` must be live and belong to `c`; `buf` must be readable for `count` bytes. Returns the
/// number of bytes written, or `-1` with `errno` set on failure.
pub type smbc_write_fn = option::Option<
    extern "C" fn(
        c: *mut SMBCCTX,
        file: *mut SMBCFILE,
        buf: *const c_void,
        count: size_t,
    ) -> ssize_t,
>;
/// Optional callback that removes a remote file.
///
/// `fname` must be a NUL-terminated SMB URL. Returns zero on success or `-1` with `errno` set.
pub type smbc_unlink_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, fname: *const c_char) -> c_int>;
/// Optional callback that renames or moves a remote entry.
///
/// Both contexts must be live and both name pointers must be NUL-terminated SMB URLs. Returns zero
/// on success or `-1` with `errno` set on failure.
pub type smbc_rename_fn = option::Option<
    extern "C" fn(
        ocontext: *mut SMBCCTX,
        oname: *const c_char,
        ncontext: *mut SMBCCTX,
        nname: *const c_char,
    ) -> c_int,
>;
/// Optional callback that changes an open file's offset.
///
/// `file` must be live and belong to `c`; `whence` must be a valid `SEEK_*` value. Returns the new
/// offset or `-1` with `errno` set on failure.
pub type smbc_lseek_fn = option::Option<
    extern "C" fn(c: *mut SMBCCTX, file: *mut SMBCFILE, offset: off_t, whence: c_int) -> off_t,
>;
/// Optional callback that reads metadata for a remote path.
///
/// `fname` must be a NUL-terminated SMB URL and `st` must be writable for one `stat`. Returns zero
/// on success or `-1` with `errno` set on failure.
pub type smbc_stat_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, fname: *const c_char, st: *mut stat) -> c_int>;
/// Optional callback that reads filesystem statistics for a remote path.
///
/// `fname` must be a NUL-terminated SMB URL and `st` must be writable for one `statvfs`. Returns
/// zero on success or `-1` with `errno` set on failure.
pub type smbc_statvfs_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, fname: *const c_char, st: *mut statvfs) -> c_int>;
/// Optional callback that reads metadata from an open file handle.
///
/// `file` must be live and belong to `c`; `st` must be writable for one `stat`. Returns zero on
/// success or `-1` with `errno` set on failure.
pub type smbc_fstat_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, file: *mut SMBCFILE, st: *mut stat) -> c_int>;
/// Optional callback that closes an open file handle.
///
/// `file` must be live and belong to `c`. A successful zero return invalidates the handle; `-1`
/// indicates failure with `errno` set.
pub type smbc_close_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, file: *mut SMBCFILE) -> c_int>;
/// Optional callback that opens a remote directory.
///
/// `fname` must be a NUL-terminated SMB URL. Returns a live directory handle owned by `c`, or null
/// with `errno` set on failure.
pub type smbc_opendir_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, fname: *const c_char) -> *mut SMBCFILE>;
/// Optional callback that closes an open directory handle.
///
/// `dir` must be live and belong to `c`. A successful zero return invalidates the handle; `-1`
/// indicates failure with `errno` set.
pub type smbc_closedir_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, dir: *mut SMBCFILE) -> c_int>;
/// Optional callback that reads the next directory entry.
///
/// `dir` must be live and belong to `c`. The returned entry is borrowed until the next read or
/// directory close. Null means end-of-directory or failure; inspect `errno` to distinguish them.
pub type smbc_readdir_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, dir: *mut SMBCFILE) -> *mut smbc_dirent>;
/// Optional callback that reads the next directory entry with metadata.
///
/// `dir` must be live and belong to `c`. The returned metadata is read-only and borrowed until the
/// next read or directory close. Null means end-of-directory or failure.
pub type smbc_readdirplus_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, dir: *mut SMBCFILE) -> *mut libsmb_file_info>;
/// Optional callback that reads multiple directory entries into a buffer.
///
/// `dir` must be live and `dirp` must be writable for `count` bytes. Returns bytes written, zero at
/// end-of-directory, or `-1` with `errno` set on failure.
pub type smbc_getdents_fn = option::Option<
    extern "C" fn(
        c: *mut SMBCCTX,
        dir: *mut SMBCFILE,
        dirp: *mut smbc_dirent,
        count: c_int,
    ) -> c_int,
>;
/// Optional callback that creates a remote directory.
///
/// `fname` must be a NUL-terminated SMB URL. Returns zero on success or `-1` with `errno` set.
pub type smbc_mkdir_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, fname: *const c_char, mode: mode_t) -> c_int>;
/// Optional callback that removes a remote directory.
///
/// `fname` must be a NUL-terminated SMB URL. Returns zero on success or `-1` with `errno` set.
pub type smbc_rmdir_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, fname: *const c_char) -> c_int>;
/// Optional callback that returns the current directory-stream offset.
///
/// `dir` must be live and belong to `c`. Returns the current offset or `-1` with `errno` set.
pub type smbc_telldir_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, dir: *mut SMBCFILE) -> off_t>;
/// Optional callback that changes a directory-stream offset.
///
/// `dir` must be live and belong to `c`, and `offset` must come from the same stream. Returns zero
/// on success or `-1` with `errno` set on failure.
pub type smbc_lseekdir_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, dir: *mut SMBCFILE, offset: off_t) -> c_int>;
/// Optional callback that reads metadata from an open directory handle.
///
/// `dir` must be live and belong to `c`; `st` must be writable for one `stat`. Returns zero on
/// success or `-1` with `errno` set on failure.
pub type smbc_fstatdir_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, dir: *mut SMBCFILE, st: *mut stat) -> c_int>;
/// Optional callback that changes a remote entry's POSIX mode.
///
/// `fname` must be a NUL-terminated SMB URL. Returns zero on success or `-1` with `errno` set.
pub type smbc_chmod_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, fname: *const c_char, mode: mode_t) -> c_int>;
/// Optional callback that changes a remote entry's access and modification times.
///
/// `fname` must be a NUL-terminated SMB URL and `tbuf` must reference two valid `timeval` values.
/// Returns zero on success or `-1` with `errno` set on failure.
pub type smbc_utimes_fn = option::Option<
    extern "C" fn(c: *mut SMBCCTX, fname: *const c_char, tbuf: *mut timeval) -> c_int,
>;
/// Optional callback that writes a remote entry's extended attribute.
///
/// `fname` and `name` must be NUL-terminated; `value` must be readable for `size` bytes. Returns
/// zero on success or `-1` with `errno` set on failure.
pub type smbc_setxattr_fn = option::Option<
    extern "C" fn(
        context: *mut SMBCCTX,
        fname: *const c_char,
        name: *const c_char,
        value: *const c_void,
        size: size_t,
        flags: c_int,
    ) -> c_int,
>;
/// Optional callback that reads a remote entry's extended attribute.
///
/// `fname` and `name` must be NUL-terminated. When `size` is nonzero, `value` must reference a
/// writable buffer of that size; a zero size queries the required length. Returns the value size
/// or `-1` with `errno` set on failure.
pub type smbc_getxattr_fn = option::Option<
    extern "C" fn(
        context: *mut SMBCCTX,
        fname: *const c_char,
        name: *const c_char,
        value: *const c_void,
        size: size_t,
    ) -> c_int,
>;
/// Optional callback that removes a remote entry's extended attribute.
///
/// `fname` and `name` must be NUL-terminated. Returns zero on success or `-1` with `errno` set.
pub type smbc_removexattr_fn = option::Option<
    extern "C" fn(context: *mut SMBCCTX, fname: *const c_char, name: *const c_char) -> c_int,
>;
/// Optional callback that lists a remote entry's extended attributes.
///
/// `fname` must be NUL-terminated. When `size` is nonzero, `list` must be writable for that many
/// bytes; a zero size queries the required length. Returns the list size or `-1` on failure.
pub type smbc_listxattr_fn = option::Option<
    extern "C" fn(
        context: *mut SMBCCTX,
        fname: *const c_char,
        list: *mut c_char,
        size: size_t,
    ) -> c_int,
>;
/// Optional callback that submits a remote file to a print queue.
///
/// Both contexts must be live and both string pointers must be NUL-terminated SMB URLs. Returns
/// zero on success or `-1` with `errno` set on failure.
pub type smbc_print_file_fn = option::Option<
    extern "C" fn(
        c_file: *mut SMBCCTX,
        fname: *const c_char,
        c_print: *mut SMBCCTX,
        printq: *const c_char,
    ) -> c_int,
>;
/// Optional callback that opens a new print job.
///
/// `fname` must be a NUL-terminated print-queue URL. Returns a live print handle owned by `c`, or
/// null with `errno` set on failure.
pub type smbc_open_print_job_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, fname: *const c_char) -> *mut SMBCFILE>;
/// Optional callback that enumerates jobs in a print queue.
///
/// `fname` must be a NUL-terminated queue URL and `_fn` must remain callable throughout the
/// operation. Returns zero on success or `-1` with `errno` set on failure.
pub type smbc_list_print_jobs_fn = option::Option<
    extern "C" fn(c: *mut SMBCCTX, fname: *const c_char, _fn: smbc_list_print_job_fn) -> c_int,
>;
/// Optional callback that removes a job from a print queue.
///
/// `fname` must be a NUL-terminated queue URL. Returns zero on success or `-1` with `errno` set.
pub type smbc_unlink_print_job_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, fname: *const c_char, id: c_int) -> c_int>;

/// Opaque internal data owned by `libsmbclient`.
pub enum SMBC_internal_data {}
#[repr(C)]
#[derive(Copy)]
/// Native `libsmbclient` context layout.
///
/// Applications should prefer the native accessor functions over direct field access.
pub struct _SMBCCTX {
    /// Native debug verbosity.
    pub debug: c_int,
    /// Pointer to the configured NUL-terminated NetBIOS name.
    pub netbios_name: *mut c_char,
    /// Pointer to the configured NUL-terminated workgroup.
    pub workgroup: *mut c_char,
    /// Pointer to the configured NUL-terminated username.
    pub user: *mut c_char,
    /// Operation timeout in milliseconds.
    pub timeout: c_int,
    /// File-open callback.
    pub open: smbc_open_fn,
    /// File-creation callback.
    pub creat: smbc_creat_fn,
    /// File-read callback.
    pub read: smbc_read_fn,
    /// File-write callback.
    pub write: smbc_write_fn,
    /// File-removal callback.
    pub unlink: smbc_unlink_fn,
    /// Entry-rename callback.
    pub rename: smbc_rename_fn,
    /// File-seek callback.
    pub lseek: smbc_lseek_fn,
    /// Path-metadata callback.
    pub stat: smbc_stat_fn,
    /// Handle-metadata callback.
    pub fstat: smbc_fstat_fn,
    /// File-close callback.
    pub close_fn: smbc_close_fn,
    /// Directory-open callback.
    pub opendir: smbc_opendir_fn,
    /// Directory-close callback.
    pub closedir: smbc_closedir_fn,
    /// Directory-read callback.
    pub readdir: smbc_readdir_fn,
    /// Batched directory-read callback.
    pub getdents: smbc_getdents_fn,
    /// Directory-creation callback.
    pub mkdir: smbc_mkdir_fn,
    /// Directory-removal callback.
    pub rmdir: smbc_rmdir_fn,
    /// Directory-position callback.
    pub telldir: smbc_telldir_fn,
    /// Directory-seek callback.
    pub lseekdir: smbc_lseekdir_fn,
    /// Directory-metadata callback.
    pub fstatdir: smbc_fstatdir_fn,
    /// Mode-change callback.
    pub chmod: smbc_chmod_fn,
    /// Timestamp-change callback.
    pub utimes: smbc_utimes_fn,
    /// Extended-attribute write callback.
    pub setxattr: smbc_setxattr_fn,
    /// Extended-attribute read callback.
    pub getxattr: smbc_getxattr_fn,
    /// Extended-attribute removal callback.
    pub removexattr: smbc_removexattr_fn,
    /// Extended-attribute listing callback.
    pub listxattr: smbc_listxattr_fn,
    /// File-printing callback.
    pub print_file: smbc_print_file_fn,
    /// Print-job creation callback.
    pub open_print_job: smbc_open_print_job_fn,
    /// Print-job listing callback.
    pub list_print_jobs: smbc_list_print_jobs_fn,
    /// Print-job removal callback.
    pub unlink_print_job: smbc_unlink_print_job_fn,
    /// Cache and authentication callback table.
    pub callbacks: _smbc_callbacks,
    /// Reserved native extension pointer.
    pub reserved: *mut c_void,
    /// Native context flags.
    pub flags: c_int,
    /// Stored native options.
    pub options: _smbc_options,
    /// Pointer to opaque native context state.
    pub internal: *mut SMBC_internal_data,
}

impl clone::Clone for _SMBCCTX {
    fn clone(&self) -> Self {
        *self
    }
}

impl default::Default for _SMBCCTX {
    fn default() -> Self {
        unsafe { mem::zeroed() }
    }
}

#[repr(C)]
#[derive(Copy)]
/// Callback table used by a native SMB context.
pub struct _smbc_callbacks {
    /// Authentication callback without a context parameter.
    pub auth_fn: smbc_get_auth_data_fn,
    /// Cached-server health-check callback.
    pub check_server_fn: smbc_check_server_fn,
    /// Unused-server removal callback.
    pub remove_unused_server_fn: smbc_remove_unused_server_fn,
    /// Cached-server insertion callback.
    pub add_cached_srv_fn: smbc_add_cached_srv_fn,
    /// Cached-server lookup callback.
    pub get_cached_srv_fn: smbc_get_cached_srv_fn,
    /// Cached-server removal callback.
    pub remove_cached_srv_fn: smbc_remove_cached_srv_fn,
    /// Cache-purge callback.
    pub purge_cached_fn: smbc_purge_cached_fn,
}

impl clone::Clone for _smbc_callbacks {
    fn clone(&self) -> Self {
        *self
    }
}

impl default::Default for _smbc_callbacks {
    fn default() -> Self {
        unsafe { mem::zeroed() }
    }
}

#[repr(C)]
#[derive(Copy)]
/// Options stored directly in a native SMB context.
pub struct _smbc_options {
    /// Maximum number of local master browsers queried while browsing.
    pub browse_max_lmb_count: c_int,
    /// Whether directory-entry names are URL encoded.
    pub urlencode_readdir_entries: c_int,
    /// Whether one server connection is restricted to one share.
    pub one_share_per_server: c_int,
}
impl clone::Clone for _smbc_options {
    fn clone(&self) -> Self {
        *self
    }
}
impl default::Default for _smbc_options {
    fn default() -> Self {
        unsafe { mem::zeroed() }
    }
}

#[link(name = "smbclient")]
unsafe extern "C" {
    /// Sets the native debug verbosity for `c`.
    ///
    /// # Safety
    ///
    /// `c` must be a valid native context pointer.
    pub fn smbc_setDebug(c: *mut SMBCCTX, debug: c_int);
    /// Returns the NetBIOS name configured for `c`.
    ///
    /// # Safety
    ///
    /// `c` must be valid. The returned pointer must not be modified or freed and is invalidated by
    /// changing the name or destroying `c`.
    pub fn smbc_getNetbiosName(c: *mut SMBCCTX) -> *mut c_char;
    /// Sets the NetBIOS name configured for `c`.
    ///
    /// # Safety
    ///
    /// `c` must be valid and `netbios_name` must point to a valid NUL-terminated string.
    pub fn smbc_setNetbiosName(c: *mut SMBCCTX, netbios_name: *mut c_char);
    /// Returns the workgroup configured for `c`.
    ///
    /// # Safety
    ///
    /// `c` must be valid. The returned pointer must not be modified or freed and is invalidated by
    /// changing the workgroup or destroying `c`.
    pub fn smbc_getWorkgroup(c: *mut SMBCCTX) -> *mut c_char;
    /// Sets the workgroup configured for `c`.
    ///
    /// # Safety
    ///
    /// `c` must be valid and `workgroup` must point to a valid NUL-terminated string.
    pub fn smbc_setWorkgroup(c: *mut SMBCCTX, workgroup: *mut c_char);
    /// Returns the username configured for `c`.
    ///
    /// # Safety
    ///
    /// `c` must be valid. The returned pointer must not be modified or freed and is invalidated by
    /// changing the username or destroying `c`.
    pub fn smbc_getUser(c: *mut SMBCCTX) -> *mut c_char;
    /// Sets the username configured for `c`.
    ///
    /// # Safety
    ///
    /// `c` must be valid and `user` must point to a valid NUL-terminated string.
    pub fn smbc_setUser(c: *mut SMBCCTX, user: *mut c_char);
    /// Returns the timeout configured for `c` in milliseconds.
    ///
    /// # Safety
    ///
    /// `c` must be a valid native context pointer.
    pub fn smbc_getTimeout(c: *mut SMBCCTX) -> c_int;
    /// Sets the timeout for `c` in milliseconds.
    ///
    /// # Safety
    ///
    /// `c` must be a valid native context pointer.
    pub fn smbc_setTimeout(c: *mut SMBCCTX, timeout: c_int);
    /// Controls whether native debug output is written to standard error.
    ///
    /// # Safety
    ///
    /// `c` must be a valid, uninitialized native context pointer.
    pub fn smbc_setOptionDebugToStderr(c: *mut SMBCCTX, b: smbc_bool);
    /// Sets the file-open sharing mode for `c`.
    ///
    /// # Safety
    ///
    /// `c` must be a valid, uninitialized context and `share_mode` must be supported.
    pub fn smbc_setOptionOpenShareMode(c: *mut SMBCCTX, share_mode: smbc_share_mode);
    /// Sets the SMB encryption policy for `c`.
    ///
    /// # Safety
    ///
    /// `c` must be a valid, uninitialized context and `level` must be supported.
    pub fn smbc_setOptionSmbEncryptionLevel(c: *mut SMBCCTX, level: smbc_smb_encrypt_level);
    /// Controls case-sensitive path matching for `c`.
    ///
    /// # Safety
    ///
    /// `c` must be a valid, uninitialized native context pointer.
    pub fn smbc_setOptionCaseSensitive(c: *mut SMBCCTX, b: smbc_bool);
    /// Sets the maximum local master browser query count for `c`.
    ///
    /// # Safety
    ///
    /// `c` must be a valid, uninitialized native context pointer.
    pub fn smbc_setOptionBrowseMaxLmbCount(c: *mut SMBCCTX, count: c_int);
    /// Controls URL encoding of directory-entry names for `c`.
    ///
    /// # Safety
    ///
    /// `c` must be a valid, uninitialized native context pointer.
    pub fn smbc_setOptionUrlEncodeReaddirEntries(c: *mut SMBCCTX, b: smbc_bool);
    /// Restricts each server connection to one share when enabled.
    ///
    /// # Safety
    ///
    /// `c` must be a valid, uninitialized native context pointer.
    pub fn smbc_setOptionOneSharePerServer(c: *mut SMBCCTX, b: smbc_bool);
    /// Controls whether Kerberos authentication is attempted for `c`.
    ///
    /// # Safety
    ///
    /// `c` must be a valid, uninitialized native context pointer.
    pub fn smbc_setOptionUseKerberos(c: *mut SMBCCTX, b: smbc_bool);
    /// Controls fallback after Kerberos authentication fails.
    ///
    /// # Safety
    ///
    /// `c` must be a valid, uninitialized native context pointer.
    pub fn smbc_setOptionFallbackAfterKerberos(c: *mut SMBCCTX, b: smbc_bool);
    /// Prevents automatic anonymous authentication when enabled.
    ///
    /// # Safety
    ///
    /// `c` must be a valid, uninitialized native context pointer.
    pub fn smbc_setOptionNoAutoAnonymousLogin(c: *mut SMBCCTX, b: smbc_bool);
    /// Controls whether Kerberos uses the credential cache.
    ///
    /// # Safety
    ///
    /// `c` must be a valid, uninitialized native context pointer.
    pub fn smbc_setOptionUseCCache(c: *mut SMBCCTX, b: smbc_bool);
    /// Installs the context-aware authentication callback for `c`.
    ///
    /// # Safety
    ///
    /// `c` must be valid and uninitialized. The callback must uphold the native callback contract.
    pub fn smbc_setFunctionAuthDataWithContext(
        c: *mut SMBCCTX,
        _fn: smbc_get_auth_data_with_context_fn,
    );
    /// Returns the file-open callback installed in `c`.
    ///
    /// # Safety
    ///
    /// `c` must be a valid, initialized native context pointer.
    pub fn smbc_getFunctionOpen(c: *mut SMBCCTX) -> smbc_open_fn;
    /// Returns the file-read callback installed in `c`.
    ///
    /// # Safety
    ///
    /// `c` must be a valid, initialized native context pointer.
    pub fn smbc_getFunctionRead(c: *mut SMBCCTX) -> smbc_read_fn;
    /// Returns the file-write callback installed in `c`.
    ///
    /// # Safety
    ///
    /// `c` must be a valid, initialized native context pointer.
    pub fn smbc_getFunctionWrite(c: *mut SMBCCTX) -> smbc_write_fn;
    /// Returns the file-removal callback installed in `c`.
    ///
    /// # Safety
    ///
    /// `c` must be a valid, initialized native context pointer.
    pub fn smbc_getFunctionUnlink(c: *mut SMBCCTX) -> smbc_unlink_fn;
    /// Returns the entry-rename callback installed in `c`.
    ///
    /// # Safety
    ///
    /// `c` must be a valid, initialized native context pointer.
    pub fn smbc_getFunctionRename(c: *mut SMBCCTX) -> smbc_rename_fn;
    /// Returns the file-seek callback installed in `c`.
    ///
    /// # Safety
    ///
    /// `c` must be a valid, initialized native context pointer.
    pub fn smbc_getFunctionLseek(c: *mut SMBCCTX) -> smbc_lseek_fn;
    /// Returns the path-metadata callback installed in `c`.
    ///
    /// # Safety
    ///
    /// `c` must be a valid, initialized native context pointer.
    pub fn smbc_getFunctionStat(c: *mut SMBCCTX) -> smbc_stat_fn;
    /// Returns the filesystem-statistics callback installed in `c`.
    ///
    /// # Safety
    ///
    /// `c` must be a valid, initialized native context pointer.
    pub fn smbc_getFunctionStatVFS(c: *mut SMBCCTX) -> smbc_statvfs_fn;
    /// Returns the file-close callback installed in `c`.
    ///
    /// # Safety
    ///
    /// `c` must be a valid, initialized native context pointer.
    pub fn smbc_getFunctionClose(c: *mut SMBCCTX) -> smbc_close_fn;
    /// Returns the directory-open callback installed in `c`.
    ///
    /// # Safety
    ///
    /// `c` must be a valid, initialized native context pointer.
    pub fn smbc_getFunctionOpendir(c: *mut SMBCCTX) -> smbc_opendir_fn;
    /// Returns the directory-close callback installed in `c`.
    ///
    /// # Safety
    ///
    /// `c` must be a valid, initialized native context pointer.
    pub fn smbc_getFunctionClosedir(c: *mut SMBCCTX) -> smbc_closedir_fn;
    /// Returns the directory-read callback installed in `c`.
    ///
    /// # Safety
    ///
    /// `c` must be a valid, initialized native context pointer.
    pub fn smbc_getFunctionReaddir(c: *mut SMBCCTX) -> smbc_readdir_fn;
    /// Returns the extended directory-read callback installed in `c`.
    ///
    /// # Safety
    ///
    /// `c` must be a valid, initialized native context pointer.
    pub fn smbc_getFunctionReaddirPlus(c: *mut SMBCCTX) -> smbc_readdirplus_fn;
    /// Returns the directory-creation callback installed in `c`.
    ///
    /// # Safety
    ///
    /// `c` must be a valid, initialized native context pointer.
    pub fn smbc_getFunctionMkdir(c: *mut SMBCCTX) -> smbc_mkdir_fn;
    /// Returns the directory-removal callback installed in `c`.
    ///
    /// # Safety
    ///
    /// `c` must be a valid, initialized native context pointer.
    pub fn smbc_getFunctionRmdir(c: *mut SMBCCTX) -> smbc_rmdir_fn;
    /// Returns the mode-change callback installed in `c`.
    ///
    /// # Safety
    ///
    /// `c` must be a valid, initialized native context pointer.
    pub fn smbc_getFunctionChmod(c: *mut SMBCCTX) -> smbc_chmod_fn;
    /// Returns the file-printing callback installed in `c`.
    ///
    /// # Safety
    ///
    /// `c` must be a valid, initialized native context pointer.
    pub fn smbc_getFunctionPrintFile(c: *mut SMBCCTX) -> smbc_print_file_fn;
    /// Allocates a new, uninitialized native SMB context.
    ///
    /// Returns null and sets `errno` to `ENOMEM` when allocation fails.
    ///
    /// # Safety
    ///
    /// A non-null pointer must be passed to [`smbc_init_context`] before use and eventually passed
    /// exactly once to [`smbc_free_context`].
    pub fn smbc_new_context() -> *mut SMBCCTX;
    /// Attempts to free `context` and optionally shuts down its connections.
    ///
    /// Returns zero on success. Returns one and sets `errno` to `EBUSY` if resources remain in use
    /// when `shutdown_ctx` is zero, or to `EBADF` if `context` is null.
    ///
    /// # Safety
    ///
    /// `context` must be a live pointer allocated by [`smbc_new_context`] and not previously freed.
    /// It remains owned by the caller when this function returns one.
    pub fn smbc_free_context(context: *mut SMBCCTX, shutdown_ctx: c_int) -> c_int;
    /// Initializes a newly allocated native SMB context.
    ///
    /// Returns `context` on success. Returns null and sets `errno` to `EBADF`, `ENOMEM`, or `ENOENT`
    /// for a null context, allocation failure, or an unreadable Samba configuration, respectively.
    ///
    /// # Safety
    ///
    /// `context` must be a live, uninitialized pointer returned by [`smbc_new_context`]. On failure,
    /// the caller still owns it and must pass it to [`smbc_free_context`].
    pub fn smbc_init_context(context: *mut SMBCCTX) -> *mut SMBCCTX;
    /// Returns the linked `libsmbclient` version string.
    ///
    /// # Safety
    ///
    /// The returned pointer is borrowed static storage and must not be modified or freed.
    pub fn smbc_version() -> *const c_char;
}
