//! Safe access to a shared native `libsmbclient` context.

use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{mem, ptr};

use libc::{self, c_char, c_int};
use pavao_sys::{SMBCCTX, *};

use super::{
    AuthService, SmbCredentials, SmbDirentInfo, SmbFile, SmbMode, SmbOpenOptions, SmbOptions,
    SmbStat, SmbStatVfs,
};
use crate::{SmbDirent, SmbError, SmbResult, utils};

struct SmbContext {
    inner: *mut SMBCCTX,
}

impl SmbContext {
    /// Creates an empty context holder.
    fn null() -> Self {
        SmbContext {
            inner: ptr::null_mut(),
        }
    }

    /// Replaces the stored native context pointer.
    pub fn set(&mut self, ctx: *mut SMBCCTX) {
        self.inner = ctx;
    }

    /// Returns the stored native context pointer.
    pub fn get(&self) -> *mut SMBCCTX {
        self.inner
    }

    /// Returns whether no native context is stored.
    pub fn is_null(&self) -> bool {
        self.get().is_null()
    }
}

unsafe impl Sync for SmbContext {}
unsafe impl Send for SmbContext {}

lazy_static! {
    static ref AUTH_SERVICE: Mutex<AuthService> = Mutex::new(AuthService::default());
    static ref SMBCTX: Arc<Mutex<SmbContext>> = Arc::new(Mutex::new(SmbContext::null()));
}

/// A client for accessing files and directories on an SMB share.
///
/// Client instances use a process-wide native `libsmbclient` context. The first client created
/// while that context is active supplies its credentials and options. Dropping any client frees
/// that shared context, so multiple client instances must not remain alive simultaneously.
#[derive(Debug)]
pub struct SmbClient {
    uri: String,
}

impl SmbClient {
    /// Creates a client for the server and share in `credentials`.
    ///
    /// `options` configures the native context when this is the first active client.
    ///
    /// # Errors
    ///
    /// Returns an error if shared state is poisoned or the native context cannot be initialized.
    ///
    /// # Panics
    ///
    /// Panics if the authentication credential store is poisoned during initialization.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use pavao::{SmbClient, SmbCredentials, SmbOptions};
    ///
    /// let client = SmbClient::new(
    ///     SmbCredentials::default()
    ///         .server("smb://server.example")
    ///         .share("/documents"),
    ///     SmbOptions::default(),
    /// )?;
    /// # Ok::<(), pavao::SmbError>(())
    /// ```
    pub fn new(credentials: SmbCredentials, options: SmbOptions) -> SmbResult<Self> {
        let uri = Self::build_uri(credentials.server.as_str(), credentials.share.as_str());
        let smbc = SmbClient { uri };
        // insert credentials
        trace!("creating context...");
        // get current context
        let mut ctx_lock = SMBCTX.lock().map_err(|_| SmbError::Mutex)?;
        // if context is null, create a new one
        if ctx_lock.is_null() {
            unsafe {
                let ctx = utils::result_from_ptr_mut(smbc_new_context())?;
                // set options
                trace!("configuring client options");
                smbc_setFunctionAuthDataWithContext(ctx, Some(Self::auth_wrapper));
                Self::setup_options(ctx, options);

                // set ctx
                let smb_ctx = utils::result_from_ptr_mut(smbc_init_context(ctx))?;
                trace!("context initialized");
                AUTH_SERVICE
                    .lock()
                    .unwrap()
                    .insert(Self::auth_service_uuid(smb_ctx), credentials);

                // set context
                ctx_lock.set(smb_ctx);
            }
        }
        Ok(smbc)
    }

    /// Returns the NetBIOS name configured on the native context.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is unavailable or the name cannot be decoded.
    pub fn get_netbios_name(&self) -> SmbResult<String> {
        trace!("getting netbios name");
        unsafe {
            let ptr = utils::result_from_ptr_mut(smbc_getNetbiosName(self.ctx()?))?;
            utils::char_ptr_to_string(ptr).map_err(|_| SmbError::BadValue)
        }
    }

    /// Sets the NetBIOS name on the native context.
    ///
    /// # Errors
    ///
    /// Returns an error if `name` contains a NUL byte or the context is unavailable.
    pub fn set_netbios_name<S>(&self, name: S) -> SmbResult<()>
    where
        S: AsRef<str>,
    {
        trace!("setting netbios name to {name}", name = name.as_ref());
        let name = utils::str_to_cstring(name)?;
        unsafe { smbc_setNetbiosName(self.ctx()?, name.into_raw()) }
        Ok(())
    }

    /// Returns the workgroup configured on the native context.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is unavailable or the workgroup cannot be decoded.
    pub fn get_workgroup(&self) -> SmbResult<String> {
        trace!("getting workgroup");
        unsafe {
            let ptr = utils::result_from_ptr_mut(smbc_getWorkgroup(self.ctx()?))?;
            utils::char_ptr_to_string(ptr).map_err(|_| SmbError::BadValue)
        }
    }

    /// Sets the workgroup on the native context.
    ///
    /// # Errors
    ///
    /// Returns an error if `name` contains a NUL byte or the context is unavailable.
    pub fn set_workgroup<S>(&self, name: S) -> SmbResult<()>
    where
        S: AsRef<str>,
    {
        trace!("configuring workgroup to {name}", name = name.as_ref());
        let name = utils::str_to_cstring(name)?;
        unsafe { smbc_setWorkgroup(self.ctx()?, name.into_raw()) }
        Ok(())
    }

    /// Returns the username configured on the native context.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is unavailable or the username cannot be decoded.
    pub fn get_user(&self) -> SmbResult<String> {
        trace!("getting current username");
        unsafe {
            let ptr = utils::result_from_ptr_mut(smbc_getUser(self.ctx()?))?;
            utils::char_ptr_to_string(ptr).map_err(|_| SmbError::BadValue)
        }
    }

    /// Sets the username on the native context.
    ///
    /// # Errors
    ///
    /// Returns an error if `name` contains a NUL byte or the context is unavailable.
    pub fn set_user<S>(&self, name: S) -> SmbResult<()>
    where
        S: AsRef<str>,
    {
        trace!(
            "configuring current username as {name}",
            name = name.as_ref()
        );
        let name = utils::str_to_cstring(name)?;
        unsafe { smbc_setUser(self.ctx()?, name.into_raw()) }
        Ok(())
    }

    /// Returns the native context timeout.
    ///
    /// # Errors
    ///
    /// Returns an error if the shared context state is poisoned.
    pub fn get_timeout(&self) -> SmbResult<Duration> {
        trace!("getting timeout");
        unsafe { Ok(Duration::from_millis(smbc_getTimeout(self.ctx()?) as u64)) }
    }

    /// Sets the native context timeout.
    ///
    /// The duration is passed to `libsmbclient` as milliseconds.
    ///
    /// # Errors
    ///
    /// Returns an error if the shared context state is poisoned.
    pub fn set_timeout(&self, timeout: Duration) -> SmbResult<()> {
        trace!(
            "setting timeout to {timeout_ms}ms",
            timeout_ms = timeout.as_millis()
        );
        unsafe { smbc_setTimeout(self.ctx()?, timeout.as_millis() as c_int) }
        Ok(())
    }

    /// Returns the linked `libsmbclient` version string.
    ///
    /// # Errors
    ///
    /// Returns an error if the native version string is null or invalid UTF-8.
    pub fn get_version(&self) -> SmbResult<String> {
        trace!("getting smb version");
        unsafe {
            let ptr = smbc_version();
            utils::char_ptr_to_string(ptr).map_err(|_| SmbError::BadValue)
        }
    }

    /// Removes the file at `path` from the configured share.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid paths, unavailable native functions, or server failures.
    pub fn unlink<S>(&self, path: S) -> SmbResult<()>
    where
        S: AsRef<str>,
    {
        trace!("unlinking entry at {path}", path = path.as_ref());
        let path = utils::str_to_cstring(self.uri(path))?;
        let unlink_fn = self.get_fn(self.ctx()?, smbc_getFunctionUnlink)?;
        utils::to_result_with_ioerror((), unlink_fn(self.ctx()?, path.as_ptr()))
    }

    /// Renames `orig_url` to `new_url` within the configured share.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid paths, unavailable native functions, or server failures.
    pub fn rename<S>(&self, orig_url: S, new_url: S) -> SmbResult<()>
    where
        S: AsRef<str>,
    {
        trace!(
            "renaming {orig_url} to {new_url}",
            orig_url = orig_url.as_ref(),
            new_url = new_url.as_ref()
        );
        let orig_url = utils::str_to_cstring(self.uri(orig_url))?;
        let new_url = utils::str_to_cstring(self.uri(new_url))?;
        let rename_fn = self.get_fn(self.ctx()?, smbc_getFunctionRename)?;
        utils::to_result_with_ioerror(
            (),
            rename_fn(
                self.ctx()?,
                orig_url.as_ptr(),
                self.ctx()?,
                new_url.as_ptr(),
            ),
        )
    }

    /// Lists entries in the directory at `path`.
    ///
    /// The synthetic `.` and `..` entries are omitted. Entries that cannot be decoded are logged
    /// and skipped.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be opened or required native functions are absent.
    pub fn list_dir<S>(&self, path: S) -> SmbResult<Vec<SmbDirent>>
    where
        S: AsRef<str>,
    {
        trace!("listing files at {path}", path = path.as_ref());
        let path = utils::str_to_cstring(self.uri(path))?;
        let opendir_fn = self.get_fn(self.ctx()?, smbc_getFunctionOpendir)?;
        let fd = opendir_fn(self.ctx()?, path.as_ptr());
        if fd.is_null() {
            error!("failed to open directory: returned a bad file descriptor");
            return Err(SmbError::BadFileDescriptor);
        }
        let closedir_fn = self.get_fn(self.ctx()?, smbc_getFunctionClosedir)?;
        let mut entries = Vec::new();
        let readdir_fn = self.get_fn(self.ctx()?, smbc_getFunctionReaddir)?;
        loop {
            let dirent = readdir_fn(self.ctx()?, fd);
            if dirent.is_null() {
                break;
            }
            unsafe {
                match SmbDirent::try_from(*dirent) {
                    Ok(dirent)
                        if dirent.name() != "."
                            && dirent.name() != ".."
                            && !dirent.name().is_empty() =>
                    {
                        trace!("found dirent: {dirent:?}");
                        entries.push(dirent);
                    }
                    Ok(_) => {
                        trace!("ignoring '..', '.' directories");
                    }
                    Err(e) => {
                        error!("failed to decode directory entity {dirent:?}: {e}");
                    }
                }
            }
        }
        trace!("decoded {count} dirents", count = entries.len());
        // Close directory
        let _ = closedir_fn(self.ctx()?, fd);
        Ok(entries)
    }

    /// Lists entries and metadata for the directory at `path`.
    ///
    /// The synthetic `.` and `..` entries are omitted. Entries that cannot be decoded are logged
    /// and skipped.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be opened or required native functions are absent.
    pub fn list_dirplus<S>(&self, path: S) -> SmbResult<Vec<SmbDirentInfo>>
    where
        S: AsRef<str>,
    {
        trace!(
            "listing files with metadata at {path}",
            path = path.as_ref()
        );
        let path = utils::str_to_cstring(self.uri(path))?;
        let opendir_fn = self.get_fn(self.ctx()?, smbc_getFunctionOpendir)?;
        let fd = opendir_fn(self.ctx()?, path.as_ptr());
        if fd.is_null() {
            error!("failed to open directory: returned a bad file descriptor");
            return Err(SmbError::BadFileDescriptor);
        }
        let closedir_fn = self.get_fn(self.ctx()?, smbc_getFunctionClosedir)?;
        let mut entries = Vec::new();
        let readdirplus_fn = self.get_fn(self.ctx()?, smbc_getFunctionReaddirPlus)?;
        loop {
            let direntplus = readdirplus_fn(self.ctx()?, fd);
            if direntplus.is_null() {
                break;
            }
            unsafe {
                match SmbDirentInfo::try_from(*direntplus) {
                    Ok(direntplus)
                        if direntplus.name() != "."
                            && direntplus.name() != ".."
                            && !direntplus.name().is_empty() =>
                    {
                        trace!("found direntplus: {direntplus:?}");
                        entries.push(direntplus);
                    }
                    Ok(_) => {
                        trace!("ignoring '..', '.' directories");
                    }
                    Err(e) => {
                        error!(
                            "failed to decode directory entity with metadata {direntplus:?}: {e}"
                        );
                    }
                }
            }
        }
        trace!(
            "decoded {count} directory entries with metadata",
            count = entries.len()
        );
        // Close directory
        let _ = closedir_fn(self.ctx()?, fd);
        Ok(entries)
    }

    /// Creates a directory at `p` with the provided POSIX `mode`.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid paths, unavailable native functions, or server failures.
    pub fn mkdir<S>(&self, p: S, mode: SmbMode) -> SmbResult<()>
    where
        S: AsRef<str>,
    {
        trace!(
            "making directory at {path} with mode {mode:?}",
            path = p.as_ref()
        );
        let p = utils::str_to_cstring(self.uri(p))?;
        let mkdir_fn = self.get_fn(self.ctx()?, smbc_getFunctionMkdir)?;
        utils::to_result_with_ioerror((), mkdir_fn(self.ctx()?, p.as_ptr(), mode.into()))
    }

    /// Removes the directory at `p`.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid paths, unavailable native functions, or server failures.
    pub fn rmdir<S>(&self, p: S) -> SmbResult<()>
    where
        S: AsRef<str>,
    {
        trace!("removing directory at {path}", path = p.as_ref());
        let p = utils::str_to_cstring(self.uri(p))?;
        let rmdir_fn = self.get_fn(self.ctx()?, smbc_getFunctionRmdir)?;
        utils::to_result_with_ioerror((), rmdir_fn(self.ctx()?, p.as_ptr()))
    }

    /// Returns filesystem statistics for the share containing `p`.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid paths, unavailable native functions, or server failures.
    pub fn statvfs<S>(&self, p: S) -> SmbResult<SmbStatVfs>
    where
        S: AsRef<str>,
    {
        trace!("reading filesystem metadata at {path}", path = p.as_ref());
        let p = utils::str_to_cstring(self.uri(p))?;
        unsafe {
            let mut st: libc::statvfs = mem::zeroed();
            let statvfs_fn = self.get_fn(self.ctx()?, smbc_getFunctionStatVFS)?;
            if statvfs_fn(self.ctx()?, p.as_ptr(), &mut st) < 0 {
                error!(
                    "failed to stat filesystem: {error}",
                    error = utils::last_os_error()
                );
                Err(utils::last_os_error())
            } else {
                Ok(SmbStatVfs::from(st))
            }
        }
    }

    /// Returns metadata for the remote entry at `p`.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid paths, unavailable native functions, or server failures.
    pub fn stat<S>(&self, p: S) -> SmbResult<SmbStat>
    where
        S: AsRef<str>,
    {
        trace!("reading file metadata at {path}", path = p.as_ref());
        let p = utils::str_to_cstring(self.uri(p))?;
        unsafe {
            let mut st: libc::stat = mem::zeroed();
            let stat_fn = self.get_fn(self.ctx()?, smbc_getFunctionStat)?;
            if stat_fn(self.ctx()?, p.as_ptr(), &mut st) < 0 {
                error!(
                    "failed to stat file: {error}",
                    error = utils::last_os_error()
                );
                Err(utils::last_os_error())
            } else {
                Ok(SmbStat::from(st))
            }
        }
    }

    /// Changes the POSIX mode of the remote entry at `p`.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid paths, unavailable native functions, or server failures.
    pub fn chmod<S>(&self, p: S, mode: SmbMode) -> SmbResult<()>
    where
        S: AsRef<str>,
    {
        trace!("changing mode for {path} with {mode:?}", path = p.as_ref());
        let p = utils::str_to_cstring(self.uri(p))?;
        let chmod_fn = self.get_fn(self.ctx()?, smbc_getFunctionChmod)?;
        utils::to_result_with_ioerror((), chmod_fn(self.ctx()?, p.as_ptr(), mode.into()))
    }

    /// Submits the remote file at `p` to `print_queue`.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid paths, unavailable native functions, or server failures.
    pub fn print<S>(&self, p: S, print_queue: S) -> SmbResult<()>
    where
        S: AsRef<str>,
    {
        trace!(
            "printing {path} to {print_queue} queue",
            path = p.as_ref(),
            print_queue = print_queue.as_ref()
        );
        let p = utils::str_to_cstring(self.uri(p))?;
        let print_queue = utils::str_to_cstring(self.uri(print_queue))?;
        let print_fn = self.get_fn(self.ctx()?, smbc_getFunctionPrintFile)?;
        utils::to_result_with_ioerror(
            (),
            print_fn(self.ctx()?, p.as_ptr(), self.ctx()?, print_queue.as_ptr()),
        )
    }

    // -- internal private

    /// Builds the base connection URI.
    fn build_uri(server: &str, share: &str) -> String {
        let separator = if share.starts_with('/') { "" } else { "/" };
        format!("{server}{separator}{share}")
    }

    /// Builds a URI relative to this client's share.
    fn uri<S>(&self, p: S) -> String
    where
        S: AsRef<str>,
    {
        format!("{base}{path}", base = self.uri, path = p.as_ref())
    }

    /// Retrieves a required operation callback from the native context.
    #[expect(
        improper_ctypes_definitions,
        reason = "libsmbclient exposes function-pointer getters through its C ABI"
    )]
    pub(crate) fn get_fn<T>(
        &self,
        ctx: *mut SMBCCTX,
        get_func: unsafe extern "C" fn(*mut SMBCCTX) -> Option<T>,
    ) -> std::io::Result<T> {
        unsafe { get_func(ctx).ok_or_else(|| std::io::Error::from_raw_os_error(libc::EINVAL)) }
    }

    /// Applies client options to a native context.
    unsafe fn setup_options(ctx: *mut SMBCCTX, options: SmbOptions) {
        unsafe {
            smbc_setOptionBrowseMaxLmbCount(ctx, options.browser_max_lmb_count);
            smbc_setOptionCaseSensitive(ctx, options.case_sensitive as i32);
            smbc_setOptionDebugToStderr(ctx, 0);
            smbc_setOptionFallbackAfterKerberos(ctx, options.fallback_after_kerberos as i32);
            smbc_setOptionNoAutoAnonymousLogin(ctx, options.no_auto_anonymous_login as i32);
            smbc_setOptionOneSharePerServer(ctx, options.one_share_per_server as i32);
            smbc_setOptionOpenShareMode(ctx, options.open_share_mode.into());
            smbc_setOptionSmbEncryptionLevel(ctx, options.encryption_level.into());
            smbc_setOptionUrlEncodeReaddirEntries(ctx, options.url_encode_readdir_entries as i32);
            smbc_setOptionUseCCache(ctx, options.use_ccache as i32);
            smbc_setOptionUseKerberos(ctx, options.use_kerberos as i32);
            #[cfg(feature = "debug")]
            smbc_setOptionDebugToStderr(ctx, 1 as i32);
            #[cfg(feature = "debug")]
            smbc_setDebug(ctx, 10);
        }
    }

    /// Auth wrapper passed to `SMBCCTX` to authenticate requests to SMB servers.
    extern "C" fn auth_wrapper(
        ctx: *mut SMBCCTX,
        srv: *const c_char,
        shr: *const c_char,
        wg: *mut c_char,
        wglen: c_int,
        un: *mut c_char,
        unlen: c_int,
        pw: *mut c_char,
        pwlen: c_int,
    ) {
        unsafe {
            let srv = utils::cstr(srv);
            let shr = utils::cstr(shr);
            trace!("authenticating on {srv}\\{shr}");
            let creds = AUTH_SERVICE
                .lock()
                .unwrap()
                .get(Self::auth_service_uuid(ctx))
                .clone();
            utils::write_to_cstr(wg as *mut u8, wglen as usize, &creds.workgroup);
            utils::write_to_cstr(un as *mut u8, unlen as usize, &creds.username);
            utils::write_to_cstr(pw as *mut u8, pwlen as usize, &creds.password);
        }
    }

    fn auth_service_uuid(ctx: *mut SMBCCTX) -> String {
        format!("{ctx:?}")
    }

    /// Returns the process-wide native context pointer.
    ///
    /// The pointer is owned by Pavão and is invalidated when any [`SmbClient`] is dropped. Callers
    /// must not free it, retain it across a client drop, or keep multiple clients alive at once.
    ///
    /// # Errors
    ///
    /// Returns an error if the shared context state is poisoned.
    pub fn ctx(&self) -> SmbResult<*mut SMBCCTX> {
        Ok(SMBCTX.lock().map_err(|_| SmbError::Mutex)?.get())
    }
}

impl<'a> SmbClient {
    /// Opens the remote file at `path` with `options`.
    ///
    /// The returned file borrows this client and closes its native handle when dropped.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid paths, unavailable native functions, or open failures.
    pub fn open_with<P: AsRef<str>>(
        &'a self,
        path: P,
        options: SmbOpenOptions,
    ) -> SmbResult<SmbFile<'a>> {
        trace!("opening {path} with {options:?}", path = path.as_ref());
        let open_fn = self.get_fn(self.ctx()?, smbc_getFunctionOpen)?;
        let path = utils::str_to_cstring(self.uri(path))?;
        let fd = utils::result_from_ptr_mut(open_fn(
            self.ctx()?,
            path.as_ptr(),
            options.to_flags(),
            options.mode,
        ))?;
        if (fd as i64) < 0 {
            error!("got a negative file descriptor");
            Err(SmbError::BadFileDescriptor)
        } else {
            trace!("opened file with file descriptor {fd:?}");
            Ok(SmbFile::new(self, fd))
        }
    }
}

// -- destructor
impl Drop for SmbClient {
    fn drop(&mut self) {
        trace!("removing uri from auth service");
        unsafe {
            if let Ok(mut context) = SMBCTX.lock() {
                AUTH_SERVICE
                    .lock()
                    .unwrap()
                    .remove(Self::auth_service_uuid(context.get()));
                trace!("closing smbclient");
                smbc_free_context(context.get(), 1_i32);
                // set context to null
                context.set(ptr::null_mut());
            }
        }
        trace!("smbclient context freed");
    }
}

#[cfg(test)]
mod test {
    use std::io::{Cursor, Read, Seek, SeekFrom, Write};
    use std::time::UNIX_EPOCH;

    use pretty_assertions::{assert_eq, assert_ne};
    use serial_test::serial;

    use super::*;
    use crate::test::TestCtx;
    use crate::{SmbDirentType, mock};

    #[test]
    #[serial]
    fn should_initialize_client() {
        mock::logger();
        let ctx = init_ctx();
        assert_eq!(ctx.client.ctx().unwrap().is_null(), false);
        finalize_ctx(ctx);
    }

    #[test]
    #[serial]
    fn should_get_netbios() {
        mock::logger();
        let ctx = init_ctx();
        assert!(ctx.client.get_netbios_name().is_ok());
        finalize_ctx(ctx);
    }

    #[test]
    #[serial]
    fn should_set_netbios() {
        mock::logger();
        let ctx = init_ctx();
        assert!(ctx.client.set_netbios_name("foobar").is_ok());
        assert_eq!(ctx.client.get_netbios_name().unwrap().as_str(), "foobar");
        finalize_ctx(ctx);
    }

    #[test]
    #[serial]
    fn should_get_workgroup() {
        mock::logger();
        let ctx = init_ctx();
        assert!(ctx.client.get_workgroup().is_ok());
        finalize_ctx(ctx);
    }

    #[test]
    #[serial]
    fn should_set_workgroup() {
        mock::logger();
        let ctx = init_ctx();
        assert!(ctx.client.set_workgroup("foobar").is_ok());
        assert_eq!(ctx.client.get_workgroup().unwrap().as_str(), "foobar");
        finalize_ctx(ctx);
    }

    #[test]
    #[serial]
    fn should_get_user() {
        mock::logger();
        let ctx = init_ctx();
        assert!(ctx.client.get_user().is_ok());
        finalize_ctx(ctx);
    }

    #[test]
    #[serial]
    fn should_set_user() {
        mock::logger();
        let ctx = init_ctx();
        assert!(ctx.client.set_user("test").is_ok());
        assert_eq!(ctx.client.get_user().unwrap().as_str(), "test");
        finalize_ctx(ctx);
    }

    #[test]
    #[serial]
    fn should_get_timeout() {
        mock::logger();
        let ctx = init_ctx();
        assert!(ctx.client.get_timeout().is_ok());
        finalize_ctx(ctx);
    }

    #[test]
    #[serial]
    fn should_set_timeout() {
        mock::logger();
        let ctx = init_ctx();
        assert!(ctx.client.set_timeout(Duration::from_secs(3)).is_ok());
        assert_eq!(ctx.client.get_timeout().unwrap(), Duration::from_secs(3));
        finalize_ctx(ctx);
    }

    #[test]
    #[serial]
    fn should_get_version() {
        mock::logger();
        let ctx = init_ctx();
        assert!(ctx.client.get_version().is_ok());
        finalize_ctx(ctx);
    }

    #[test]
    #[serial]
    fn should_unlink() {
        mock::logger();
        let ctx = init_ctx();
        create_file_at(&ctx.client, "/cargo-test/test", "Hello, World!\n");
        let _ = ctx.client.unlink("/cargo-test/test"); // NOTE: may not be supported by the server
        finalize_ctx(ctx);
    }

    #[test]
    #[serial]
    fn should_rename() {
        mock::logger();
        let ctx = init_ctx();
        create_file_at(&ctx.client, "/cargo-test/test", "Hello, World!\n");
        let _ = ctx.client.rename("/cargo-test/test", "/cargo-test/new"); // NOTE: may not be supported by the server
        finalize_ctx(ctx);
    }

    #[test]
    #[serial]
    fn should_list_dir() {
        mock::logger();
        let ctx = init_ctx();
        create_file_at(&ctx.client, "/cargo-test/abc", "Hello, World!\n");
        create_file_at(&ctx.client, "/cargo-test/def", "Hello, World!\n");
        assert!(
            ctx.client
                .mkdir("/cargo-test/jfk", SmbMode::from(0o755))
                .is_ok()
        );
        // list dir
        let mut entries = ctx.client.list_dir("/cargo-test").unwrap();
        entries.sort_by(|a, b| a.name().cmp(b.name()));
        assert_eq!(entries.len(), 3);
        let abc = entries.first().unwrap();
        assert_eq!(abc.name(), "abc");
        assert_eq!(abc.get_type(), SmbDirentType::File);
        let def = entries.get(1).unwrap();
        assert_eq!(def.name(), "def");
        assert_eq!(def.get_type(), SmbDirentType::File);
        let jfk = entries.get(2).unwrap();
        assert_eq!(jfk.name(), "jfk");
        assert_eq!(jfk.get_type(), SmbDirentType::Dir);
        finalize_ctx(ctx);
    }

    #[test]
    #[serial]
    fn should_list_dirplus() {
        mock::logger();
        let ctx = init_ctx();
        create_file_at(&ctx.client, "/cargo-test/ghi", "Hello, World!\n");
        create_file_at(&ctx.client, "/cargo-test/jkl", "Hello, World!\n");
        assert!(
            ctx.client
                .mkdir("/cargo-test/hil", SmbMode::from(0o755))
                .is_ok()
        );
        // list directory with metadata
        let mut entries = ctx.client.list_dirplus("/cargo-test").unwrap();
        entries.sort_by(|a, b| a.name().cmp(b.name()));
        assert_eq!(entries.len(), 3);
        let abc = entries.first().unwrap();
        assert_eq!(abc.name(), "ghi");
        assert_eq!(abc.get_type(), SmbDirentType::File);
        let def = entries.get(1).unwrap();
        assert_eq!(def.name(), "hil");
        assert_eq!(def.get_type(), SmbDirentType::Dir);
        let jfk = entries.get(2).unwrap();
        assert_eq!(jfk.name(), "jkl");
        assert_eq!(jfk.get_type(), SmbDirentType::File);
        finalize_ctx(ctx);
    }

    #[test]
    #[serial]
    fn should_mkdir() {
        mock::logger();
        let ctx = init_ctx();
        assert!(
            ctx.client
                .mkdir("/cargo-test/testdir", SmbMode::from(0o755))
                .is_ok()
        );
        finalize_ctx(ctx);
    }

    #[test]
    #[serial]
    fn should_rmdir() {
        mock::logger();
        let ctx = init_ctx();
        assert!(
            ctx.client
                .mkdir("/cargo-test/testdir", SmbMode::from(0o755))
                .is_ok()
        );
        // will return err on this server
        let _ = ctx.client.rmdir("/cargo-test/testdir");
        finalize_ctx(ctx);
    }

    #[test]
    #[serial]
    fn should_statvfs() {
        mock::logger();
        let ctx = init_ctx();
        assert!(ctx.client.statvfs("/cargo-test").is_ok());
        finalize_ctx(ctx);
    }

    #[test]
    #[serial]
    fn should_stat() {
        mock::logger();
        let ctx = init_ctx();
        // Create file
        create_file_at(&ctx.client, "/cargo-test/test", "Hello, World!\n");
        // stat
        let file = ctx.client.stat("/cargo-test/test").unwrap();
        assert_ne!(file.accessed, UNIX_EPOCH);
        assert_ne!(file.blksize, 0);
        assert_ne!(file.blocks, 0);
        //assert_eq!(file.mode, SmbMode::from(0o744));
        assert_eq!(file.size, 14);
        finalize_ctx(ctx);
    }

    #[test]
    #[serial]
    fn should_chmod() {
        mock::logger();
        let ctx = init_ctx();
        // Create file
        create_file_at(&ctx.client, "/cargo-test/test", "Hello, World!\n");
        let _ = ctx.client.chmod("/cargo-test/test", SmbMode::from(0o755)); // NOTE: may not be supported by the server
        finalize_ctx(ctx);
    }

    #[test]
    #[serial]
    fn should_build_uri() {
        mock::logger();
        let ctx = init_ctx();

        assert!(ctx.client.uri("/test").as_str().ends_with("/temp/test"));
        finalize_ctx(ctx);
    }

    #[test]
    #[serial]
    fn should_read_file() {
        mock::logger();
        let ctx = init_ctx();
        create_file_at(&ctx.client, "/cargo-test/test", "Hello, World!\n");
        // read file
        let mut reader = ctx
            .client
            .open_with("/cargo-test/test", SmbOpenOptions::default().read(true))
            .unwrap();
        let mut output = String::default();
        assert!(reader.read_to_string(&mut output).is_ok());
        drop(reader);
        assert_eq!(output.as_str(), "Hello, World!\n");
        finalize_ctx(ctx);
    }

    #[test]
    #[serial]
    fn should_write_file() {
        mock::logger();
        let ctx = init_ctx();
        // write file
        let mut writer = ctx
            .client
            .open_with(
                "/cargo-test/test",
                SmbOpenOptions::default().write(true).create(true),
            )
            .unwrap();
        let mut reader = Cursor::new("test string\n".as_bytes());
        assert_eq!(std::io::copy(&mut reader, &mut writer).unwrap(), 12);
        writer.flush().unwrap();
        drop(writer);
        finalize_ctx(ctx);
    }

    #[test]
    #[serial]
    fn should_append_to_file() {
        mock::logger();
        let ctx = init_ctx();
        create_file_at(&ctx.client, "/cargo-test/test", "Hello, World!\n");
        // append
        let mut writer = ctx
            .client
            .open_with(
                "/cargo-test/test",
                SmbOpenOptions::default().write(true).append(true),
            )
            .unwrap();
        let mut reader = Cursor::new("Bonjour\n".as_bytes());
        assert_eq!(std::io::copy(&mut reader, &mut writer).unwrap(), 8);
        drop(writer);
        // read
        let mut reader = ctx
            .client
            .open_with("/cargo-test/test", SmbOpenOptions::default().read(true))
            .unwrap();
        let mut output = String::default();
        assert!(reader.read_to_string(&mut output).is_ok());
        drop(reader);
        assert_eq!(output.as_str(), "Hello, World!\nBonjour\n");
        finalize_ctx(ctx);
    }

    #[test]
    #[serial]
    fn should_seek_file() {
        mock::logger();
        let ctx = init_ctx();
        create_file_at(&ctx.client, "/cargo-test/test", "Hello, World!\n");
        let mut file = ctx
            .client
            .open_with("/cargo-test/test", SmbOpenOptions::default().read(true))
            .unwrap();

        assert_eq!(file.seek(SeekFrom::Start(7)).unwrap(), 7);
        assert_eq!(file.seek(SeekFrom::Current(5)).unwrap(), 12);
        assert_eq!(file.seek(SeekFrom::End(-7)).unwrap(), 7);

        let mut output = String::new();
        file.read_to_string(&mut output).unwrap();
        assert_eq!(output, "World!\n");
        drop(file);
        finalize_ctx(ctx);
    }

    fn init_ctx() -> TestCtx {
        TestCtx::default()
    }

    fn finalize_ctx(ctx: TestCtx) {
        std::thread::sleep(Duration::from_secs(1));
        drop(ctx);
    }

    fn create_file_at<S: AsRef<str>>(client: &SmbClient, uri: S, content: S) {
        info!("create_file_at - uri: {uri}", uri = uri.as_ref());

        let mut reader = Cursor::new(content.as_ref().as_bytes());
        let mut writer = client
            .open_with(
                uri,
                SmbOpenOptions::default()
                    .create(true)
                    .write(true)
                    .mode(0o744),
            )
            .expect("failed to open file");
        assert!(std::io::copy(&mut reader, &mut writer).is_ok());
    }
}
