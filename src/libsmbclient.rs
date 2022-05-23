#![allow(non_camel_case_types)]
#![allow(missing_copy_implementations)]
#![allow(unused_imports)]
#![allow(dead_code)]

use std::{clone, default, mem, option};

use libc::{
    c_char, c_double, c_int, c_uchar, c_uint, c_ulong, c_ushort, c_void, mode_t, off_t, size_t,
    ssize_t, stat, time_t, timeval,
};

use nix::sys::statvfs::Statvfs;

static SMBC_BASE_FD: i32 = 10000; /* smallest file descriptor returned */
static SMBC_WORKGROUP: i32 = 1;
static SMBC_SERVER: i32 = 2;
static SMBC_FILE_SHARE: i32 = 3;
static SMBC_PRINTER_SHARE: i32 = 4;
static SMBC_COMMS_SHARE: i32 = 5;
static SMBC_IPC_SHARE: i32 = 6;
static SMBC_DIR: i32 = 7;
static SMBC_FILE: i32 = 8;
static SMBC_LINK: i32 = 9;

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

/*
 * Flags for smbc_setxattr()
 *   Specify a bitwise OR of these, or 0 to add or replace as necessary
 */
static SMBC_XATTR_FLAG_CREATE: i32 = 0x1; /* fail if attr already exists */
static SMBC_XATTR_FLAG_REPLACE: i32 = 0x2; /* fail if attr does not exist */

/*
 * Mappings of the DOS mode bits, as returned by smbc_getxattr() when the
 * attribute name "system.dos_attr.mode" (or "system.dos_attr.*" or
 * "system.*") is specified.
 */
static SMBC_DOS_MODE_READONLY: i32 = 0x01;
static SMBC_DOS_MODE_HIDDEN: i32 = 0x02;
static SMBC_DOS_MODE_SYSTEM: i32 = 0x04;
static SMBC_DOS_MODE_VOLUME_ID: i32 = 0x08;
static SMBC_DOS_MODE_DIRECTORY: i32 = 0x10;
static SMBC_DOS_MODE_ARCHIVE: i32 = 0x20;

/*
 * Valid values for the option "open_share_mode", when calling
 * smbc_setOptionOpenShareMode()
 */
pub type smbc_share_mode = c_uint;
pub const SMBC_SHAREMODE_DENY_DOS: c_uint = 0;
pub const SMBC_SHAREMODE_DENY_ALL: c_uint = 1;
pub const SMBC_SHAREMODE_DENY_WRITE: c_uint = 2;
pub const SMBC_SHAREMODE_DENY_READ: c_uint = 3;
pub const SMBC_SHAREMODE_DENY_NONE: c_uint = 4;
pub const SMBC_SHAREMODE_DENY_FCB: c_uint = 7;

/**
 * Values for option SMB Encryption Level, as set and retrieved with
 * smbc_setOptionSmbEncryptionLevel() and smbc_getOptionSmbEncryptionLevel()
 */
pub type smbc_smb_encrypt_level = c_uint;
pub const SMBC_ENCRYPTLEVEL_NONE: c_uint = 0;
pub const SMBC_ENCRYPTLEVEL_REQUEST: c_uint = 1;
pub const SMBC_ENCRYPTLEVEL_REQUIRE: c_uint = 2;

/**
 * Capabilities set in the f_flag field of struct statvfs, from
 * smbc_statvfs(). These may be OR-ed together to reflect a full set of
 * available capabilities.
 */
pub type smbc_vfs_feature = c_uint;
pub const SMBC_VFS_FEATURE_RDONLY: c_uint = 1 << 0;
pub const SMBC_VFS_FEATURE_DFS: c_uint = 1 << 28;
pub const SMBC_VFS_FEATURE_CASE_INSENSITIVE: c_uint = 1 << 29;
pub const SMBC_VFS_FEATURE_NO_UNIXCIFS: c_uint = 1 << 30;

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

/*
 * Flags for SMBCCTX->flags
 *
 * NEW CODE SHOULD NOT DIRECTLY MANIPULATE THE CONTEXT STRUCTURE.
 * Instead, use:
 *   smbc_setOptionUseKerberos()
 *   smbc_getOptionUseKerberos()
 *   smbc_setOptionFallbackAfterKerberos()
 *   smbc_getOptionFallbackAFterKerberos()
 *   smbc_setOptionNoAutoAnonymousLogin()
 *   smbc_getOptionNoAutoAnonymousLogin()
 *   smbc_setOptionUseCCache()
 *   smbc_getOptionUseCCache()
 */
static SMB_CTX_FLAG_USE_KERBEROS: i32 = 1 << 0;
static SMB_CTX_FLAG_FALLBACK_AFTER_KERBEROS: i32 = 1 << 1;
static SMBCCTX_FLAG_NO_AUTO_ANONYMOUS_LOGON: i32 = 1 << 2;
static SMB_CTX_FLAG_USE_CCACHE: i32 = 1 << 3;

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
    ) -> (),
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
    ) -> (),
>;
pub type smbc_list_print_job_fn = option::Option<extern "C" fn(i: *mut print_job_info) -> ()>;
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

pub enum smbc_server_cache {}

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
pub type smbc_statvfs_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, path: *mut c_char, st: *mut Statvfs) -> c_int>;
pub type smbc_fstatvfs_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, file: *mut SMBCFILE, st: *mut Statvfs) -> c_int>;
pub type smbc_ftruncate_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, f: *mut SMBCFILE, size: off_t) -> c_int>;
pub type smbc_close_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, file: *mut SMBCFILE) -> c_int>;
pub type smbc_opendir_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, fname: *const c_char) -> *mut SMBCFILE>;
pub type smbc_closedir_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, dir: *mut SMBCFILE) -> c_int>;
pub type smbc_readdir_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, dir: *mut SMBCFILE) -> *mut smbc_dirent>;
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
    pub fn smbc_getDebug(c: *mut SMBCCTX) -> c_int;
    pub fn smbc_setDebug(c: *mut SMBCCTX, debug: c_int) -> ();
    pub fn smbc_getNetbiosName(c: *mut SMBCCTX) -> *mut c_char;
    pub fn smbc_setNetbiosName(c: *mut SMBCCTX, netbios_name: *mut c_char) -> ();
    pub fn smbc_getWorkgroup(c: *mut SMBCCTX) -> *mut c_char;
    pub fn smbc_setWorkgroup(c: *mut SMBCCTX, workgroup: *mut c_char) -> ();
    pub fn smbc_getUser(c: *mut SMBCCTX) -> *mut c_char;
    pub fn smbc_setUser(c: *mut SMBCCTX, user: *mut c_char) -> ();
    pub fn smbc_getTimeout(c: *mut SMBCCTX) -> c_int;
    pub fn smbc_setTimeout(c: *mut SMBCCTX, timeout: c_int) -> ();
    pub fn smbc_getOptionDebugToStderr(c: *mut SMBCCTX) -> smbc_bool;
    pub fn smbc_setOptionDebugToStderr(c: *mut SMBCCTX, b: smbc_bool) -> ();
    pub fn smbc_getOptionFullTimeNames(c: *mut SMBCCTX) -> smbc_bool;
    pub fn smbc_setOptionFullTimeNames(c: *mut SMBCCTX, b: smbc_bool) -> ();
    pub fn smbc_getOptionOpenShareMode(c: *mut SMBCCTX) -> smbc_share_mode;
    pub fn smbc_setOptionOpenShareMode(c: *mut SMBCCTX, share_mode: smbc_share_mode) -> ();
    pub fn smbc_getOptionUserData(c: *mut SMBCCTX) -> *mut c_void;
    pub fn smbc_setOptionUserData(c: *mut SMBCCTX, user_data: *mut c_void) -> ();
    pub fn smbc_getOptionSmbEncryptionLevel(c: *mut SMBCCTX) -> smbc_smb_encrypt_level;
    pub fn smbc_setOptionSmbEncryptionLevel(c: *mut SMBCCTX, level: smbc_smb_encrypt_level) -> ();
    pub fn smbc_getOptionCaseSensitive(c: *mut SMBCCTX) -> smbc_bool;
    pub fn smbc_setOptionCaseSensitive(c: *mut SMBCCTX, b: smbc_bool) -> ();
    pub fn smbc_getOptionBrowseMaxLmbCount(c: *mut SMBCCTX) -> c_int;
    pub fn smbc_setOptionBrowseMaxLmbCount(c: *mut SMBCCTX, count: c_int) -> ();
    pub fn smbc_getOptionUrlEncodeReaddirEntries(c: *mut SMBCCTX) -> smbc_bool;
    pub fn smbc_setOptionUrlEncodeReaddirEntries(c: *mut SMBCCTX, b: smbc_bool) -> ();
    pub fn smbc_getOptionOneSharePerServer(c: *mut SMBCCTX) -> smbc_bool;
    pub fn smbc_setOptionOneSharePerServer(c: *mut SMBCCTX, b: smbc_bool) -> ();
    pub fn smbc_getOptionUseKerberos(c: *mut SMBCCTX) -> smbc_bool;
    pub fn smbc_setOptionUseKerberos(c: *mut SMBCCTX, b: smbc_bool) -> ();
    pub fn smbc_getOptionFallbackAfterKerberos(c: *mut SMBCCTX) -> smbc_bool;
    pub fn smbc_setOptionFallbackAfterKerberos(c: *mut SMBCCTX, b: smbc_bool) -> ();
    pub fn smbc_getOptionNoAutoAnonymousLogin(c: *mut SMBCCTX) -> smbc_bool;
    pub fn smbc_setOptionNoAutoAnonymousLogin(c: *mut SMBCCTX, b: smbc_bool) -> ();
    pub fn smbc_getOptionUseCCache(c: *mut SMBCCTX) -> smbc_bool;
    pub fn smbc_setOptionUseCCache(c: *mut SMBCCTX, b: smbc_bool) -> ();
    pub fn smbc_getFunctionAuthData(c: *mut SMBCCTX) -> smbc_get_auth_data_fn;
    pub fn smbc_setFunctionAuthData(c: *mut SMBCCTX, _fn: smbc_get_auth_data_fn) -> ();
    pub fn smbc_getFunctionAuthDataWithContext(
        c: *mut SMBCCTX,
    ) -> smbc_get_auth_data_with_context_fn;
    pub fn smbc_setFunctionAuthDataWithContext(
        c: *mut SMBCCTX,
        _fn: smbc_get_auth_data_with_context_fn,
    ) -> ();
    pub fn smbc_getFunctionCheckServer(c: *mut SMBCCTX) -> smbc_check_server_fn;
    pub fn smbc_setFunctionCheckServer(c: *mut SMBCCTX, _fn: smbc_check_server_fn) -> ();
    pub fn smbc_getFunctionRemoveUnusedServer(c: *mut SMBCCTX) -> smbc_remove_unused_server_fn;
    pub fn smbc_setFunctionRemoveUnusedServer(
        c: *mut SMBCCTX,
        _fn: smbc_remove_unused_server_fn,
    ) -> ();
    pub fn smbc_getFunctionAddCachedServer(c: *mut SMBCCTX) -> smbc_add_cached_srv_fn;
    pub fn smbc_setFunctionAddCachedServer(c: *mut SMBCCTX, _fn: smbc_add_cached_srv_fn) -> ();
    pub fn smbc_getFunctionGetCachedServer(c: *mut SMBCCTX) -> smbc_get_cached_srv_fn;
    pub fn smbc_setFunctionGetCachedServer(c: *mut SMBCCTX, _fn: smbc_get_cached_srv_fn) -> ();
    pub fn smbc_getFunctionRemoveCachedServer(c: *mut SMBCCTX) -> smbc_remove_cached_srv_fn;
    pub fn smbc_setFunctionRemoveCachedServer(
        c: *mut SMBCCTX,
        _fn: smbc_remove_cached_srv_fn,
    ) -> ();
    pub fn smbc_getFunctionPurgeCachedServers(c: *mut SMBCCTX) -> smbc_purge_cached_fn;
    pub fn smbc_setFunctionPurgeCachedServers(c: *mut SMBCCTX, _fn: smbc_purge_cached_fn) -> ();
    pub fn smbc_getServerCacheData(c: *mut SMBCCTX) -> *mut smbc_server_cache;
    pub fn smbc_setServerCacheData(c: *mut SMBCCTX, cache: *mut smbc_server_cache) -> ();
    pub fn smbc_getFunctionOpen(c: *mut SMBCCTX) -> smbc_open_fn;
    pub fn smbc_setFunctionOpen(c: *mut SMBCCTX, _fn: smbc_open_fn) -> ();
    pub fn smbc_getFunctionCreat(c: *mut SMBCCTX) -> smbc_creat_fn;
    pub fn smbc_setFunctionCreat(c: *mut SMBCCTX, arg1: smbc_creat_fn) -> ();
    pub fn smbc_getFunctionRead(c: *mut SMBCCTX) -> smbc_read_fn;
    pub fn smbc_setFunctionRead(c: *mut SMBCCTX, _fn: smbc_read_fn) -> ();
    pub fn smbc_getFunctionWrite(c: *mut SMBCCTX) -> smbc_write_fn;
    pub fn smbc_setFunctionWrite(c: *mut SMBCCTX, _fn: smbc_write_fn) -> ();
    pub fn smbc_getFunctionUnlink(c: *mut SMBCCTX) -> smbc_unlink_fn;
    pub fn smbc_setFunctionUnlink(c: *mut SMBCCTX, _fn: smbc_unlink_fn) -> ();
    pub fn smbc_getFunctionRename(c: *mut SMBCCTX) -> smbc_rename_fn;
    pub fn smbc_setFunctionRename(c: *mut SMBCCTX, _fn: smbc_rename_fn) -> ();
    pub fn smbc_getFunctionLseek(c: *mut SMBCCTX) -> smbc_lseek_fn;
    pub fn smbc_setFunctionLseek(c: *mut SMBCCTX, _fn: smbc_lseek_fn) -> ();
    pub fn smbc_getFunctionStat(c: *mut SMBCCTX) -> smbc_stat_fn;
    pub fn smbc_setFunctionStat(c: *mut SMBCCTX, _fn: smbc_stat_fn) -> ();
    pub fn smbc_getFunctionFstat(c: *mut SMBCCTX) -> smbc_fstat_fn;
    pub fn smbc_setFunctionFstat(c: *mut SMBCCTX, _fn: smbc_fstat_fn) -> ();
    pub fn smbc_getFunctionStatVFS(c: *mut SMBCCTX) -> smbc_statvfs_fn;
    pub fn smbc_setFunctionStatVFS(c: *mut SMBCCTX, _fn: smbc_statvfs_fn) -> ();
    pub fn smbc_getFunctionFstatVFS(c: *mut SMBCCTX) -> smbc_fstatvfs_fn;
    pub fn smbc_setFunctionFstatVFS(c: *mut SMBCCTX, _fn: smbc_fstatvfs_fn) -> ();
    pub fn smbc_getFunctionFtruncate(c: *mut SMBCCTX) -> smbc_ftruncate_fn;
    pub fn smbc_setFunctionFtruncate(c: *mut SMBCCTX, _fn: smbc_ftruncate_fn) -> ();
    pub fn smbc_getFunctionClose(c: *mut SMBCCTX) -> smbc_close_fn;
    pub fn smbc_setFunctionClose(c: *mut SMBCCTX, _fn: smbc_close_fn) -> ();
    pub fn smbc_getFunctionOpendir(c: *mut SMBCCTX) -> smbc_opendir_fn;
    pub fn smbc_setFunctionOpendir(c: *mut SMBCCTX, _fn: smbc_opendir_fn) -> ();
    pub fn smbc_getFunctionClosedir(c: *mut SMBCCTX) -> smbc_closedir_fn;
    pub fn smbc_setFunctionClosedir(c: *mut SMBCCTX, _fn: smbc_closedir_fn) -> ();
    pub fn smbc_getFunctionReaddir(c: *mut SMBCCTX) -> smbc_readdir_fn;
    pub fn smbc_setFunctionReaddir(c: *mut SMBCCTX, _fn: smbc_readdir_fn) -> ();
    pub fn smbc_getFunctionGetdents(c: *mut SMBCCTX) -> smbc_getdents_fn;
    pub fn smbc_setFunctionGetdents(c: *mut SMBCCTX, _fn: smbc_getdents_fn) -> ();
    pub fn smbc_getFunctionMkdir(c: *mut SMBCCTX) -> smbc_mkdir_fn;
    pub fn smbc_setFunctionMkdir(c: *mut SMBCCTX, _fn: smbc_mkdir_fn) -> ();
    pub fn smbc_getFunctionRmdir(c: *mut SMBCCTX) -> smbc_rmdir_fn;
    pub fn smbc_setFunctionRmdir(c: *mut SMBCCTX, _fn: smbc_rmdir_fn) -> ();
    pub fn smbc_getFunctionTelldir(c: *mut SMBCCTX) -> smbc_telldir_fn;
    pub fn smbc_setFunctionTelldir(c: *mut SMBCCTX, _fn: smbc_telldir_fn) -> ();
    pub fn smbc_getFunctionLseekdir(c: *mut SMBCCTX) -> smbc_lseekdir_fn;
    pub fn smbc_setFunctionLseekdir(c: *mut SMBCCTX, _fn: smbc_lseekdir_fn) -> ();
    pub fn smbc_getFunctionFstatdir(c: *mut SMBCCTX) -> smbc_fstatdir_fn;
    pub fn smbc_setFunctionFstatdir(c: *mut SMBCCTX, _fn: smbc_fstatdir_fn) -> ();
    pub fn smbc_getFunctionChmod(c: *mut SMBCCTX) -> smbc_chmod_fn;
    pub fn smbc_setFunctionChmod(c: *mut SMBCCTX, _fn: smbc_chmod_fn) -> ();
    pub fn smbc_getFunctionUtimes(c: *mut SMBCCTX) -> smbc_utimes_fn;
    pub fn smbc_setFunctionUtimes(c: *mut SMBCCTX, _fn: smbc_utimes_fn) -> ();
    pub fn smbc_getFunctionSetxattr(c: *mut SMBCCTX) -> smbc_setxattr_fn;
    pub fn smbc_setFunctionSetxattr(c: *mut SMBCCTX, _fn: smbc_setxattr_fn) -> ();
    pub fn smbc_getFunctionGetxattr(c: *mut SMBCCTX) -> smbc_getxattr_fn;
    pub fn smbc_setFunctionGetxattr(c: *mut SMBCCTX, _fn: smbc_getxattr_fn) -> ();
    pub fn smbc_getFunctionRemovexattr(c: *mut SMBCCTX) -> smbc_removexattr_fn;
    pub fn smbc_setFunctionRemovexattr(c: *mut SMBCCTX, _fn: smbc_removexattr_fn) -> ();
    pub fn smbc_getFunctionListxattr(c: *mut SMBCCTX) -> smbc_listxattr_fn;
    pub fn smbc_setFunctionListxattr(c: *mut SMBCCTX, _fn: smbc_listxattr_fn) -> ();
    pub fn smbc_getFunctionPrintFile(c: *mut SMBCCTX) -> smbc_print_file_fn;
    pub fn smbc_setFunctionPrintFile(c: *mut SMBCCTX, _fn: smbc_print_file_fn) -> ();
    pub fn smbc_getFunctionOpenPrintJob(c: *mut SMBCCTX) -> smbc_open_print_job_fn;
    pub fn smbc_setFunctionOpenPrintJob(c: *mut SMBCCTX, _fn: smbc_open_print_job_fn) -> ();
    pub fn smbc_getFunctionListPrintJobs(c: *mut SMBCCTX) -> smbc_list_print_jobs_fn;
    pub fn smbc_setFunctionListPrintJobs(c: *mut SMBCCTX, _fn: smbc_list_print_jobs_fn) -> ();
    pub fn smbc_getFunctionUnlinkPrintJob(c: *mut SMBCCTX) -> smbc_unlink_print_job_fn;
    pub fn smbc_setFunctionUnlinkPrintJob(c: *mut SMBCCTX, _fn: smbc_unlink_print_job_fn) -> ();
    pub fn smbc_new_context() -> *mut SMBCCTX;
    pub fn smbc_free_context(context: *mut SMBCCTX, shutdown_ctx: c_int) -> c_int;
    pub fn smbc_option_set(context: *mut SMBCCTX, option_name: *mut c_char, ...) -> ();
    pub fn smbc_option_get(context: *mut SMBCCTX, option_name: *mut c_char) -> *mut c_void;
    pub fn smbc_init_context(context: *mut SMBCCTX) -> *mut SMBCCTX;
    pub fn smbc_init(_fn: smbc_get_auth_data_fn, debug: c_int) -> c_int;
    pub fn smbc_set_context(new_context: *mut SMBCCTX) -> *mut SMBCCTX;
    pub fn smbc_open(furl: *const c_char, flags: c_int, mode: mode_t) -> c_int;
    pub fn smbc_creat(furl: *const c_char, mode: mode_t) -> c_int;
    pub fn smbc_read(fd: c_int, buf: *mut c_void, bufsize: size_t) -> ssize_t;
    pub fn smbc_write(fd: c_int, buf: *const c_void, bufsize: size_t) -> ssize_t;
    pub fn smbc_lseek(fd: c_int, offset: off_t, whence: c_int) -> off_t;
    pub fn smbc_close(fd: c_int) -> c_int;
    pub fn smbc_unlink(furl: *const c_char) -> c_int;
    pub fn smbc_rename(ourl: *const c_char, nurl: *const c_char) -> c_int;
    pub fn smbc_opendir(durl: *const c_char) -> c_int;
    pub fn smbc_closedir(dh: c_int) -> c_int;
    pub fn smbc_getdents(dh: c_uint, dirp: *mut smbc_dirent, count: c_int) -> c_int;
    pub fn smbc_readdir(dh: c_uint) -> *mut smbc_dirent;
    pub fn smbc_telldir(dh: c_int) -> off_t;
    pub fn smbc_lseekdir(fd: c_int, offset: off_t) -> c_int;
    pub fn smbc_mkdir(durl: *const c_char, mode: mode_t) -> c_int;
    pub fn smbc_rmdir(durl: *const c_char) -> c_int;
    pub fn smbc_stat(url: *const c_char, st: *mut stat) -> c_int;
    pub fn smbc_fstat(fd: c_int, st: *mut stat) -> c_int;
    pub fn smbc_statvfs(url: *mut c_char, st: *mut Statvfs) -> c_int;
    pub fn smbc_fstatvfs(fd: c_int, st: *mut Statvfs) -> c_int;
    pub fn smbc_ftruncate(fd: c_int, size: off_t) -> c_int;
    pub fn smbc_chmod(url: *const c_char, mode: mode_t) -> c_int;
    pub fn smbc_utimes(url: *const c_char, tbuf: *mut timeval) -> c_int;
    pub fn smbc_setxattr(
        url: *const c_char,
        name: *const c_char,
        value: *const c_void,
        size: size_t,
        flags: c_int,
    ) -> c_int;
    pub fn smbc_lsetxattr(
        url: *const c_char,
        name: *const c_char,
        value: *const c_void,
        size: size_t,
        flags: c_int,
    ) -> c_int;
    pub fn smbc_fsetxattr(
        fd: c_int,
        name: *const c_char,
        value: *const c_void,
        size: size_t,
        flags: c_int,
    ) -> c_int;
    pub fn smbc_getxattr(
        url: *const c_char,
        name: *const c_char,
        value: *const c_void,
        size: size_t,
    ) -> c_int;
    pub fn smbc_lgetxattr(
        url: *const c_char,
        name: *const c_char,
        value: *const c_void,
        size: size_t,
    ) -> c_int;
    pub fn smbc_fgetxattr(
        fd: c_int,
        name: *const c_char,
        value: *const c_void,
        size: size_t,
    ) -> c_int;
    pub fn smbc_removexattr(url: *const c_char, name: *const c_char) -> c_int;
    pub fn smbc_lremovexattr(url: *const c_char, name: *const c_char) -> c_int;
    pub fn smbc_fremovexattr(fd: c_int, name: *const c_char) -> c_int;
    pub fn smbc_listxattr(url: *const c_char, list: *mut c_char, size: size_t) -> c_int;
    pub fn smbc_llistxattr(url: *const c_char, list: *mut c_char, size: size_t) -> c_int;
    pub fn smbc_flistxattr(fd: c_int, list: *mut c_char, size: size_t) -> c_int;
    pub fn smbc_print_file(fname: *const c_char, printq: *const c_char) -> c_int;
    pub fn smbc_open_print_job(fname: *const c_char) -> c_int;
    pub fn smbc_list_print_jobs(purl: *const c_char, _fn: smbc_list_print_job_fn) -> c_int;
    pub fn smbc_unlink_print_job(purl: *const c_char, id: c_int) -> c_int;
    pub fn smbc_remove_unused_server(context: *mut SMBCCTX, srv: *mut SMBCSRV) -> c_int;
    pub fn smbc_urldecode(dest: *mut c_char, src: *mut c_char, max_dest_len: size_t) -> c_int;
    pub fn smbc_urlencode(dest: *mut c_char, src: *mut c_char, max_dest_len: c_int) -> c_int;
    pub fn smbc_version() -> *const c_char;
    pub fn smbc_set_credentials(
        workgroup: *const c_char,
        user: *const c_char,
        password: *const c_char,
        use_kerberos: smbc_bool,
        signing_state: *const c_char,
    ) -> ();
    pub fn smbc_set_credentials_with_fallback(
        ctx: *mut SMBCCTX,
        workgroup: *const c_char,
        user: *const c_char,
        password: *const c_char,
    ) -> ();
    pub fn smbc_thread_posix() -> ();
    pub fn smbc_thread_impl(
        create_mutex: ::std::option::Option<
            extern "C" fn(
                lockname: *const c_char,
                pplock: *mut *mut c_void,
                location: *const c_char,
            ) -> c_int,
        >,
        destroy_mutex: ::std::option::Option<
            extern "C" fn(plock: *mut c_void, location: *const c_char) -> (),
        >,
        lock_mutex: ::std::option::Option<
            extern "C" fn(plock: *mut c_void, lock_type: c_int, location: *const c_char) -> c_int,
        >,
        create_tls: ::std::option::Option<
            extern "C" fn(
                keyname: *const c_char,
                ppkey: *mut *mut c_void,
                location: *const c_char,
            ) -> c_int,
        >,
        destroy_tls: ::std::option::Option<
            extern "C" fn(ppkey: *mut *mut c_void, location: *const c_char) -> (),
        >,
        set_tls: ::std::option::Option<
            extern "C" fn(pkey: *mut c_void, pval: *const c_void, location: *const c_char) -> c_int,
        >,
        get_tls: ::std::option::Option<
            extern "C" fn(pkey: *mut c_void, location: *const c_char) -> *mut c_void,
        >,
    ) -> ();
}
