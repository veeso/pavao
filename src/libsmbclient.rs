#![allow(non_camel_case_types)]
#![allow(clippy::upper_case_acronyms)]
use std::{clone, default, mem, option};

use libc::{
    c_char, c_int, c_uint, c_ulong, c_ushort, c_void, mode_t, off_t, size_t, ssize_t, stat, time_t,
    timespec, timeval,
};

#[repr(C)]
#[derive(Copy)]
pub struct smbc_dirent {
    /** Type of entity.
    SMBC_WORKGROUP=1,
    SMBC_SERVER=2,
    SMBC_FILE_SHARE=3,
    SMBC_PRINTER_SHARE=4,
    SMBC_COMMS_SHARE=5,
    SMBC_IPC_SHARE=6,
    SMBC_DIR=7,
    SMBC_FILE=8,
    SMBC_LINK=9,*/
    pub smbc_type: c_uint,

    /** Length of this smbc_dirent in bytes
     */
    pub dirlen: c_uint,
    /** The length of the comment string in bytes (does not include
     *  null terminator)
     */
    pub commentlen: c_uint,
    /** Points to the null terminated comment string
     */
    pub comment: *mut c_char,
    /** The length of the name string in bytes (does not include
     *  null terminator)
     */
    pub namelen: c_uint,
    /** Points to the null terminated name string
     */
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
/// Structure that represents all attributes of a directory entry.
/// libsmb_file_info as implemented in libsmbclient.h
pub struct libsmb_file_info {
    /// Size of file
    pub size: c_ulong,
    /// DOS attributes of file
    pub attrs: c_ushort,
    /// User ID of file
    pub uid: c_uint,
    /// Group ID of file
    pub gid: c_uint,
    /// Birth/Create time of file (if supported by system)
    ///Otherwise the value will be 0
    pub btime_ts: timespec,
    /// Modified time for the file
    pub mtime_ts: timespec,
    /// Access time for the file
    pub atime_ts: timespec,
    /// Change time for the file
    pub ctime_ts: timespec,
    /// Name of file
    pub name: *mut c_char,
    /// Short name of file
    pub short_name: *mut c_char,
}

// impl std::fmt::Debug for timespec {
//     fn fmt(&self, f:&mut Formatter<'_>) -> std::fmt::Result {
//         f.debug_struct("timespec")
//             .field("tv_sec", &self.tv_sec)
//             .field("tv_nsec", &self.tv_nsec)
//             .finish()
//     }
// }
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

/*
 * Valid values for the option "open_share_mode", when calling
 * smbc_setOptionOpenShareMode()
 */
pub type smbc_share_mode = c_uint;

/**
 * Values for option SMB Encryption Level, as set and retrieved with
 * smbc_setOptionSmbEncryptionLevel() and smbc_getOptionSmbEncryptionLevel()
 */
pub type smbc_smb_encrypt_level = c_uint;

pub type smbc_bool = c_int;

#[repr(C)]
#[derive(Copy)]
pub struct print_job_info {
    /** numeric ID of the print job
     */
    pub id: c_ushort,

    /** represents print job priority (lower numbers mean higher priority)
     */
    pub priority: c_ushort,

    /** Size of the print job
     */
    pub size: size_t,

    /** Name of the user that owns the print job
     */
    pub user: [c_char; 128usize],

    /** Name of the print job. This will have no name if an anonymous print
     *  file was opened. Ie smb://server/printer
     */
    pub name: [c_char; 128usize],

    /** Time the print job was spooled
     */
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

pub enum _SMBCSRV {}
pub type SMBCSRV = _SMBCSRV;
pub enum _SMBCFILE {}
pub type SMBCFILE = _SMBCFILE;
pub type SMBCCTX = _SMBCCTX;

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
pub type smbc_list_print_job_fn = option::Option<extern "C" fn(i: *mut print_job_info)>;
pub type smbc_check_server_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, srv: *mut SMBCSRV) -> c_int>;
pub type smbc_remove_unused_server_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, srv: *mut SMBCSRV) -> c_int>;
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
pub type smbc_get_cached_srv_fn = option::Option<
    extern "C" fn(
        c: *mut SMBCCTX,
        server: *const c_char,
        share: *const c_char,
        workgroup: *const c_char,
        username: *const c_char,
    ) -> *mut SMBCSRV,
>;
pub type smbc_remove_cached_srv_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, srv: *mut SMBCSRV) -> c_int>;
pub type smbc_purge_cached_fn = option::Option<extern "C" fn(c: *mut SMBCCTX) -> c_int>;

pub type smbc_open_fn = option::Option<
    extern "C" fn(
        c: *mut SMBCCTX,
        fname: *const c_char,
        flags: c_int,
        mode: mode_t,
    ) -> *mut SMBCFILE,
>;
pub type smbc_creat_fn = option::Option<
    extern "C" fn(c: *mut SMBCCTX, path: *const c_char, mode: mode_t) -> *mut SMBCFILE,
>;
pub type smbc_read_fn = option::Option<
    extern "C" fn(c: *mut SMBCCTX, file: *mut SMBCFILE, buf: *mut c_void, count: size_t) -> ssize_t,
>;
pub type smbc_write_fn = option::Option<
    extern "C" fn(
        c: *mut SMBCCTX,
        file: *mut SMBCFILE,
        buf: *const c_void,
        count: size_t,
    ) -> ssize_t,
>;
pub type smbc_unlink_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, fname: *const c_char) -> c_int>;
pub type smbc_rename_fn = option::Option<
    extern "C" fn(
        ocontext: *mut SMBCCTX,
        oname: *const c_char,
        ncontext: *mut SMBCCTX,
        nname: *const c_char,
    ) -> c_int,
>;
pub type smbc_lseek_fn = option::Option<
    extern "C" fn(c: *mut SMBCCTX, file: *mut SMBCFILE, offset: off_t, whence: c_int) -> off_t,
>;
pub type smbc_stat_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, fname: *const c_char, st: *mut stat) -> c_int>;
pub type smbc_fstat_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, file: *mut SMBCFILE, st: *mut stat) -> c_int>;
pub type smbc_close_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, file: *mut SMBCFILE) -> c_int>;
pub type smbc_opendir_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, fname: *const c_char) -> *mut SMBCFILE>;
pub type smbc_closedir_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, dir: *mut SMBCFILE) -> c_int>;
pub type smbc_readdir_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, dir: *mut SMBCFILE) -> *mut smbc_dirent>;
pub type smbc_readdirplus_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, dir: *mut SMBCFILE) -> *mut libsmb_file_info>;
pub type smbc_getdents_fn = option::Option<
    extern "C" fn(
        c: *mut SMBCCTX,
        dir: *mut SMBCFILE,
        dirp: *mut smbc_dirent,
        count: c_int,
    ) -> c_int,
>;
pub type smbc_mkdir_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, fname: *const c_char, mode: mode_t) -> c_int>;
pub type smbc_rmdir_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, fname: *const c_char) -> c_int>;
pub type smbc_telldir_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, dir: *mut SMBCFILE) -> off_t>;
pub type smbc_lseekdir_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, dir: *mut SMBCFILE, offset: off_t) -> c_int>;
pub type smbc_fstatdir_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, dir: *mut SMBCFILE, st: *mut stat) -> c_int>;
pub type smbc_chmod_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, fname: *const c_char, mode: mode_t) -> c_int>;
pub type smbc_utimes_fn = option::Option<
    extern "C" fn(c: *mut SMBCCTX, fname: *const c_char, tbuf: *mut timeval) -> c_int,
>;
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
pub type smbc_getxattr_fn = option::Option<
    extern "C" fn(
        context: *mut SMBCCTX,
        fname: *const c_char,
        name: *const c_char,
        value: *const c_void,
        size: size_t,
    ) -> c_int,
>;
pub type smbc_removexattr_fn = option::Option<
    extern "C" fn(context: *mut SMBCCTX, fname: *const c_char, name: *const c_char) -> c_int,
>;
pub type smbc_listxattr_fn = option::Option<
    extern "C" fn(
        context: *mut SMBCCTX,
        fname: *const c_char,
        list: *mut c_char,
        size: size_t,
    ) -> c_int,
>;
pub type smbc_print_file_fn = option::Option<
    extern "C" fn(
        c_file: *mut SMBCCTX,
        fname: *const c_char,
        c_print: *mut SMBCCTX,
        printq: *const c_char,
    ) -> c_int,
>;
pub type smbc_open_print_job_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, fname: *const c_char) -> *mut SMBCFILE>;
pub type smbc_list_print_jobs_fn = option::Option<
    extern "C" fn(c: *mut SMBCCTX, fname: *const c_char, _fn: smbc_list_print_job_fn) -> c_int,
>;
pub type smbc_unlink_print_job_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, fname: *const c_char, id: c_int) -> c_int>;

pub enum SMBC_internal_data {}
#[repr(C)]
#[derive(Copy)]
pub struct _SMBCCTX {
    pub debug: c_int,
    pub netbios_name: *mut c_char,
    pub workgroup: *mut c_char,
    pub user: *mut c_char,
    pub timeout: c_int,
    pub open: smbc_open_fn,
    pub creat: smbc_creat_fn,
    pub read: smbc_read_fn,
    pub write: smbc_write_fn,
    pub unlink: smbc_unlink_fn,
    pub rename: smbc_rename_fn,
    pub lseek: smbc_lseek_fn,
    pub stat: smbc_stat_fn,
    pub fstat: smbc_fstat_fn,
    pub close_fn: smbc_close_fn,
    pub opendir: smbc_opendir_fn,
    pub closedir: smbc_closedir_fn,
    pub readdir: smbc_readdir_fn,
    pub getdents: smbc_getdents_fn,
    pub mkdir: smbc_mkdir_fn,
    pub rmdir: smbc_rmdir_fn,
    pub telldir: smbc_telldir_fn,
    pub lseekdir: smbc_lseekdir_fn,
    pub fstatdir: smbc_fstatdir_fn,
    pub chmod: smbc_chmod_fn,
    pub utimes: smbc_utimes_fn,
    pub setxattr: smbc_setxattr_fn,
    pub getxattr: smbc_getxattr_fn,
    pub removexattr: smbc_removexattr_fn,
    pub listxattr: smbc_listxattr_fn,
    pub print_file: smbc_print_file_fn,
    pub open_print_job: smbc_open_print_job_fn,
    pub list_print_jobs: smbc_list_print_jobs_fn,
    pub unlink_print_job: smbc_unlink_print_job_fn,
    pub callbacks: _smbc_callbacks,
    pub reserved: *mut c_void,
    pub flags: c_int,
    pub options: _smbc_options,
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
pub struct _smbc_callbacks {
    pub auth_fn: smbc_get_auth_data_fn,
    pub check_server_fn: smbc_check_server_fn,
    pub remove_unused_server_fn: smbc_remove_unused_server_fn,
    pub add_cached_srv_fn: smbc_add_cached_srv_fn,
    pub get_cached_srv_fn: smbc_get_cached_srv_fn,
    pub remove_cached_srv_fn: smbc_remove_cached_srv_fn,
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
pub struct _smbc_options {
    pub browse_max_lmb_count: c_int,
    pub urlencode_readdir_entries: c_int,
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
extern "C" {
    #[cfg(feature = "debug")]
    pub fn smbc_setDebug(c: *mut SMBCCTX, debug: c_int);
    pub fn smbc_getNetbiosName(c: *mut SMBCCTX) -> *mut c_char;
    pub fn smbc_setNetbiosName(c: *mut SMBCCTX, netbios_name: *mut c_char);
    pub fn smbc_getWorkgroup(c: *mut SMBCCTX) -> *mut c_char;
    pub fn smbc_setWorkgroup(c: *mut SMBCCTX, workgroup: *mut c_char);
    pub fn smbc_getUser(c: *mut SMBCCTX) -> *mut c_char;
    pub fn smbc_setUser(c: *mut SMBCCTX, user: *mut c_char);
    pub fn smbc_getTimeout(c: *mut SMBCCTX) -> c_int;
    pub fn smbc_setTimeout(c: *mut SMBCCTX, timeout: c_int);
    pub fn smbc_setOptionDebugToStderr(c: *mut SMBCCTX, b: smbc_bool);
    pub fn smbc_setOptionOpenShareMode(c: *mut SMBCCTX, share_mode: smbc_share_mode);
    pub fn smbc_setOptionSmbEncryptionLevel(c: *mut SMBCCTX, level: smbc_smb_encrypt_level);
    pub fn smbc_setOptionCaseSensitive(c: *mut SMBCCTX, b: smbc_bool);
    pub fn smbc_setOptionBrowseMaxLmbCount(c: *mut SMBCCTX, count: c_int);
    pub fn smbc_setOptionUrlEncodeReaddirEntries(c: *mut SMBCCTX, b: smbc_bool);
    pub fn smbc_setOptionOneSharePerServer(c: *mut SMBCCTX, b: smbc_bool);
    pub fn smbc_setOptionUseKerberos(c: *mut SMBCCTX, b: smbc_bool);
    pub fn smbc_setOptionFallbackAfterKerberos(c: *mut SMBCCTX, b: smbc_bool);
    pub fn smbc_setOptionNoAutoAnonymousLogin(c: *mut SMBCCTX, b: smbc_bool);
    pub fn smbc_setOptionUseCCache(c: *mut SMBCCTX, b: smbc_bool);
    pub fn smbc_setFunctionAuthDataWithContext(
        c: *mut SMBCCTX,
        _fn: smbc_get_auth_data_with_context_fn,
    );
    pub fn smbc_getFunctionOpen(c: *mut SMBCCTX) -> smbc_open_fn;
    pub fn smbc_getFunctionRead(c: *mut SMBCCTX) -> smbc_read_fn;
    pub fn smbc_getFunctionWrite(c: *mut SMBCCTX) -> smbc_write_fn;
    pub fn smbc_getFunctionUnlink(c: *mut SMBCCTX) -> smbc_unlink_fn;
    pub fn smbc_getFunctionRename(c: *mut SMBCCTX) -> smbc_rename_fn;
    pub fn smbc_getFunctionLseek(c: *mut SMBCCTX) -> smbc_lseek_fn;
    pub fn smbc_getFunctionStat(c: *mut SMBCCTX) -> smbc_stat_fn;
    pub fn smbc_getFunctionClose(c: *mut SMBCCTX) -> smbc_close_fn;
    pub fn smbc_getFunctionOpendir(c: *mut SMBCCTX) -> smbc_opendir_fn;
    pub fn smbc_getFunctionClosedir(c: *mut SMBCCTX) -> smbc_closedir_fn;
    pub fn smbc_getFunctionReaddir(c: *mut SMBCCTX) -> smbc_readdir_fn;
    pub fn smbc_getFunctionReaddirPlus(c: *mut SMBCCTX) -> smbc_readdirplus_fn;
    pub fn smbc_getFunctionMkdir(c: *mut SMBCCTX) -> smbc_mkdir_fn;
    pub fn smbc_getFunctionRmdir(c: *mut SMBCCTX) -> smbc_rmdir_fn;
    pub fn smbc_getFunctionChmod(c: *mut SMBCCTX) -> smbc_chmod_fn;
    pub fn smbc_getFunctionPrintFile(c: *mut SMBCCTX) -> smbc_print_file_fn;
    pub fn smbc_new_context() -> *mut SMBCCTX;
    pub fn smbc_free_context(context: *mut SMBCCTX, shutdown_ctx: c_int) -> c_int;
    pub fn smbc_init_context(context: *mut SMBCCTX) -> *mut SMBCCTX;
    pub fn smbc_version() -> *const c_char;
}
