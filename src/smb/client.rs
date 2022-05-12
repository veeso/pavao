//! # Client
//!
//! module which exposes the Smb Client

use super::{SmbCredentials, SmbFile, SmbMode, SmbOpenOptions, SmbOptions, SmbStat};
use crate::{utils, SmbDirent};
use crate::{SmbError, SmbResult};

use libc::{self, c_char, c_int, c_void, mode_t, off_t};
use smbclient_sys::{SMBCCTX as SmbContext, *};
use std::mem;
use std::panic;
use std::ptr;

const SMBC_FALSE: smbc_bool = 0;
const SMBC_TRUE: smbc_bool = 1;

/// Smb protocol client
pub struct SmbClient {
    pub(crate) ctx: *mut SmbContext,
    uri: String,
}

impl SmbClient {
    /// Initialize a new `SmbClient` with the provided credentials to connect to the remote smb server
    pub fn new<F>(credentials: SmbCredentials, options: SmbOptions) -> SmbResult<Self>
    where
        F: Fn(&str, &str) -> (String, String, String),
    {
        let mut smbc = SmbClient {
            ctx: ptr::null_mut(),
            uri: Self::build_uri(&credentials),
        };
        let auth_fn = |_: &str, _: &str| -> (String, String, String) {
            (
                credentials.workgroup,
                credentials.username,
                credentials.password,
            )
        };

        unsafe {
            let ctx = utils::result_from_ptr_mut(smbc_new_context())?;
            // set options
            smbc_setOptionUserData(ctx, &auth_fn as *const _ as *mut c_void);
            smbc_setFunctionAuthDataWithContext(ctx, Some(Self::auth_wrapper::<F>));
            Self::setup_options(ctx, options);
            // set ctx
            smbc.ctx = utils::result_from_ptr_mut(smbc_init_context(ctx))?;
        }
        Ok(smbc)
    }

    /// Get netbios name from server
    pub fn get_netbios_name(&self) -> SmbResult<String> {
        unsafe {
            let ptr = utils::result_from_ptr_mut(smbc_getNetbiosName(self.ctx))?;
            utils::char_ptr_to_string(ptr).map_err(|_| SmbError::BadValue)
        }
    }

    /// Set netbios name to server
    pub fn set_netbios_name<S>(&self, name: S) -> SmbResult<()>
    where
        S: AsRef<str>,
    {
        let cstr = utils::str_to_cstring(name)?;
        unsafe { smbc_setNetbiosName(self.ctx, cstr.into_raw()) }
        Ok(())
    }

    /// Get workgroup name from server
    pub fn get_workgroup(&self) -> SmbResult<String> {
        unsafe {
            let ptr = utils::result_from_ptr_mut(smbc_getWorkgroup(self.ctx))?;
            utils::char_ptr_to_string(ptr).map_err(|_| SmbError::BadValue)
        }
    }

    /// Set workgroup name to server
    pub fn set_workgroup<S>(&self, name: S) -> SmbResult<()>
    where
        S: AsRef<str>,
    {
        let cstr = utils::str_to_cstring(name)?;
        unsafe { smbc_setWorkgroup(self.ctx, cstr.into_raw()) }
        Ok(())
    }

    /// Get get_user name from server
    pub fn get_user(&self) -> SmbResult<String> {
        unsafe {
            let ptr = utils::result_from_ptr_mut(smbc_getUser(self.ctx))?;
            utils::char_ptr_to_string(ptr).map_err(|_| SmbError::BadValue)
        }
    }

    /// Set user name to server
    pub fn set_user<S>(&self, name: S) -> SmbResult<()>
    where
        S: AsRef<str>,
    {
        let cstr = utils::str_to_cstring(name)?;
        unsafe { smbc_setUser(self.ctx, cstr.into_raw()) }
        Ok(())
    }

    /// Get timeout from server
    pub fn get_timeout(&self) -> SmbResult<usize> {
        unsafe { Ok(smbc_getTimeout(self.ctx) as usize) }
    }

    /// Set timeout to server
    pub fn set_timeout(&self, timeout: usize) -> SmbResult<()> {
        unsafe { smbc_setTimeout(self.ctx, timeout as c_int) }
        Ok(())
    }

    /// Get smbc version
    pub fn get_version(&self) -> SmbResult<String> {
        unsafe {
            let ptr = smbc_version();
            utils::char_ptr_to_string(ptr).map_err(|_| SmbError::BadValue)
        }
    }

    /// Unlink file at `path`
    pub fn unlink<S>(&self, path: S) -> SmbResult<()>
    where
        S: AsRef<str>,
    {
        todo!()
    }

    /// Rename file at `orig_url` to `new_url`
    pub fn rename<S>(&self, orig_url: S, new_url: S) -> SmbResult<()>
    where
        S: AsRef<str>,
    {
        todo!()
    }

    /// List content of directory at `path`
    pub fn list_dir<S>(&self, path: S) -> SmbResult<Vec<SmbDirent>>
    where
        S: AsRef<str>,
    {
        todo!()
        /*
            int dir_fd = smbc_opendir(argv[1]);
        fprintf(stderr, "dir_fd: %d\n", dir_fd);
        if (dir_fd < 0)
        {
            die("smbc_opendir failed: %s\n", strerror(errno));
        }

        const int size = 10000;
        char dirsbuf[size];
        e = smbc_getdents(dir_fd, (struct smbc_dirent*) dirsbuf, size);
        if (e == 0 || e < size)
        {
            fprintf(stderr, "No more dirents\n");
        }
        else if (e < 0)
        {
            die("smbc_getdents failed: %s\n", strerror(errno));
        }
        char* current = dirsbuf;
        for (int i = 0; i < e; ++i)
        {
            struct smbc_dirent* d = (struct smbc_dirent*) current;
            if (interesting_dirent(d))
            {
                char* url = calloc(1, strlen(argv[1]) + strlen(d->name) + 1);
                strcat(url, argv[1]);
                strcat(url, d->name);
                fprintf(stderr, "%s\t", url);
                struct stat fs;
                int e = smbc_stat(url, &fs);
                free(url);
                if (e < 0)
                {
                    die("smbc_stat: failed for '%s'\n", url);
                }
                fprintf(stderr, " size: %ld\n", fs.st_size);
            }
            current += d->dirlen;
        }
        smbc_closedir(dir_fd);
        */
    }

    /// Make directory at `p` with provided `mode`
    pub fn mkdir<S>(&self, p: S, mode: SmbMode) -> SmbResult<()>
    where
        S: AsRef<str>,
    {
        todo!()
    }

    /// Remove directory at `p`
    pub fn rmdir<S>(&self, p: S) -> SmbResult<()>
    where
        S: AsRef<str>,
    {
        todo!()
    }

    /// Stat file at `p` and return its metadata
    pub fn stat<S>(&self, p: S) -> SmbResult<SmbStat>
    where
        S: AsRef<str>,
    {
        todo!()
    }

    /// Change file mode for file at `p`
    pub fn chmod<S>(&self, p: S, mode: SmbMode) -> SmbResult<()>
    where
        S: AsRef<str>,
    {
        todo!()
    }

    /// Print file at `p` using the `print_queue`
    pub fn print<S>(&self, p: S, print_queue: S) -> SmbResult<()>
    where
        S: AsRef<str>,
    {
        todo!()
    }

    // -- internal private

    /// Build connection uri
    fn build_uri(SmbCredentials { server, share, .. }: &SmbCredentials) -> String {
        format!(
            "{}{}{}",
            server,
            match share.starts_with('/') {
                true => "",
                false => "/",
            },
            share
        )
    }

    /// Get file uri
    fn uri<S>(&self, p: S) -> String
    where
        S: AsRef<str>,
    {
        format!("{}{}", self.uri, p.as_ref())
    }

    /// Callback to get file descriptor
    pub(crate) fn get_fn<T>(
        &self,
        get_func: unsafe extern "C" fn(*mut SMBCCTX) -> Option<T>,
    ) -> std::io::Result<T> {
        unsafe { get_func(self.ctx).ok_or(std::io::Error::from_raw_os_error(libc::EINVAL as i32)) }
    }

    /// Setup options in the context
    unsafe fn setup_options(ctx: *mut SMBCCTX, options: SmbOptions) {
        smbc_setOptionBrowseMaxLmbCount(ctx, options.browser_max_lmb_count);
        smbc_setOptionCaseSensitive(ctx, options.case_sensitive as i32);
        smbc_setOptionDebugToStderr(ctx, SMBC_FALSE);
        smbc_setOptionFallbackAfterKerberos(ctx, options.fallback_after_kerberos as i32);
        smbc_setOptionNoAutoAnonymousLogin(ctx, options.no_auto_anonymous_login as i32);
        smbc_setOptionOneSharePerServer(ctx, options.one_share_per_server as i32);
        smbc_setOptionOpenShareMode(ctx, options.open_share_mode.into());
        smbc_setOptionSmbEncryptionLevel(ctx, options.encryption_level.into());
        smbc_setOptionUrlEncodeReaddirEntries(ctx, options.url_encode_readdir_entries as i32);
        smbc_setOptionUseCCache(ctx, options.use_ccache as i32);
        smbc_setOptionUseKerberos(ctx, options.use_kerberos as i32);
    }

    /// Auth wrapper passed to `SMBCCTX` to authenticate requests to SMB servers.
    extern "C" fn auth_wrapper<F>(
        ctx: *mut SMBCCTX,
        srv: *const c_char,
        shr: *const c_char,
        wg: *mut c_char,
        wglen: c_int,
        un: *mut c_char,
        unlen: c_int,
        pw: *mut c_char,
        pwlen: c_int,
    ) where
        F: Fn(&str, &str) -> (String, String, String),
    {
        unsafe {
            let srv = utils::cstr(srv);
            let shr = utils::cstr(shr);
            trace!(target: "pavao", "authenticating on {}\\{}", &srv, &shr);

            let auth: &F = mem::transmute(smbc_getOptionUserData(ctx) as *const c_void);
            let auth = panic::AssertUnwindSafe(auth);
            let (workgroup, username, password) = panic::catch_unwind(|| {
                trace!(target: "pavao", "auth with {:?}\\{:?}", srv, shr);
                auth(&srv, &shr)
            })
            .unwrap();
            trace!(target: "pavao", "cred: {}\\{} {}", &workgroup, &username, &password);
            utils::write_to_cstr(wg as *mut u8, wglen as usize, &workgroup);
            utils::write_to_cstr(un as *mut u8, unlen as usize, &username);
            utils::write_to_cstr(pw as *mut u8, pwlen as usize, &password);
        }
    }
}

impl<'a> SmbClient {
    /// Open a file at `P` with provided options
    pub fn open_with<P: AsRef<str>>(
        &'a self,
        path: P,
        options: SmbOpenOptions,
    ) -> SmbResult<SmbFile<'a>> {
        trace!(target: "pavao", "open_with {:?}", options);

        let open_fn = self.get_fn(smbc_getFunctionOpen)?;

        let path = utils::str_to_cstring(self.uri(path))?;
        trace!(target: "pavao", "opening {:?}", path);

        let fd = utils::result_from_ptr_mut(open_fn(
            self.ctx,
            path.as_ptr(),
            options.to_flags(),
            options.mode,
        ))?;
        if (fd as i64) < 0 {
            error!(target: "pavao", "got a negative file descriptor");
            Err(SmbError::BadFileDescriptor)
        } else {
            trace!(target: "pavao", "opened file with file descriptor {:?}", fd);
            Ok(SmbFile::new(self, fd))
        }
    }
}

// -- destructor
impl Drop for SmbClient {
    fn drop(&mut self) {
        trace!(target: "pavao", "closing smbclient");
        unsafe {
            smbc_free_context(self.ctx, 1 as c_int);
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use pretty_assertions::assert_eq;
}
