//! # Client
//!
//! module which exposes the Smb Client

/**
 *
 * 	Copyright (C) 2022 Christian Visintin - <christian.visintin1997@gmail.com>
 *
 * 	This file is part of "Pavão"
 *
 *   Pavão is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   Pavão is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Pavão. If not, see <http://www.gnu.org/licenses/>.
 *
 */
use super::{SmbCredentials, SmbOptions};
use crate::utils;
use crate::{SmbError, SmbResult};

use libc::{self, c_char, c_int, c_void, mode_t, off_t};
use smbclient_sys::{SMBCCTX as SmbContext, *};
use std::io::{Read, Seek, SeekFrom, Write};
use std::mem;
use std::panic;
use std::ptr;

const SMBC_FALSE: smbc_bool = 0;
const SMBC_TRUE: smbc_bool = 1;

/// Smb protocol client
pub struct SmbClient {
    ctx: *mut SmbContext,
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
