//! # Options
//!
//! module which exposes the smb client options

use smbclient_sys::{smbc_share_mode, smbc_smb_encrypt_level};

/// Smb connection options
#[derive(Debug, Clone)]
pub struct SmbOptions {
    pub(crate) browser_max_lmb_count: i32,
    pub(crate) case_sensitive: bool,
    pub(crate) encryption_level: SmbEncryptionLevel,
    pub(crate) fallback_after_kerberos: bool,
    pub(crate) full_time_names: bool,
    pub(crate) no_auto_anonymous_login: bool,
    pub(crate) one_share_per_server: bool,
    pub(crate) open_share_mode: SmbShareMode,
    pub(crate) url_encode_readdir_entries: bool,
    pub(crate) use_ccache: bool,
    pub(crate) use_kerberos: bool,
}

impl Default for SmbOptions {
    fn default() -> Self {
        Self {
            browser_max_lmb_count: 0,
            case_sensitive: false,
            encryption_level: SmbEncryptionLevel::None,
            fallback_after_kerberos: false,
            full_time_names: false,
            no_auto_anonymous_login: false,
            one_share_per_server: false,
            open_share_mode: SmbShareMode::DenyNone,
            url_encode_readdir_entries: false,
            use_ccache: false,
            use_kerberos: false,
        }
    }
}

impl SmbOptions {
    pub fn browser_max_lmb_count(mut self, browser_max_lmb_count: i32) -> Self {
        self.browser_max_lmb_count = browser_max_lmb_count;
        self
    }

    pub fn case_sensitive(mut self, case_sensitive: bool) -> Self {
        self.case_sensitive = case_sensitive;
        self
    }

    pub fn encryption_level(mut self, encryption_level: SmbEncryptionLevel) -> Self {
        self.encryption_level = encryption_level;
        self
    }

    pub fn fallback_after_kerberos(mut self, fallback_after_kerberos: bool) -> Self {
        self.fallback_after_kerberos = fallback_after_kerberos;
        self
    }

    pub fn full_time_names(mut self, full_time_names: bool) -> Self {
        self.full_time_names = full_time_names;
        self
    }

    pub fn no_auto_anonymous_login(mut self, no_auto_anonymous_login: bool) -> Self {
        self.no_auto_anonymous_login = no_auto_anonymous_login;
        self
    }

    pub fn one_share_per_server(mut self, one_share_per_server: bool) -> Self {
        self.one_share_per_server = one_share_per_server;
        self
    }

    pub fn open_share_mode(mut self, open_share_mode: SmbShareMode) -> Self {
        self.open_share_mode = open_share_mode;
        self
    }

    pub fn url_encode_readdir_entries(mut self, url_encode_readdir_entries: bool) -> Self {
        self.url_encode_readdir_entries = url_encode_readdir_entries;
        self
    }

    pub fn use_ccache(mut self, use_ccache: bool) -> Self {
        self.use_ccache = use_ccache;
        self
    }

    pub fn use_kerberos(mut self, use_kerberos: bool) -> Self {
        self.use_kerberos = use_kerberos;
        self
    }
}

/// Share mode option
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmbShareMode {
    DenyDos,
    DenyAll,
    DenyWrite,
    DenyRead,
    DenyNone,
    DenyFcb,
}

impl From<SmbShareMode> for smbc_share_mode {
    fn from(mode: SmbShareMode) -> Self {
        match mode {
            SmbShareMode::DenyDos => 0,
            SmbShareMode::DenyAll => 1,
            SmbShareMode::DenyWrite => 2,
            SmbShareMode::DenyRead => 3,
            SmbShareMode::DenyNone => 4,
            SmbShareMode::DenyFcb => 7,
        }
    }
}

/// Encryption level option
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmbEncryptionLevel {
    None,
    Request,
    Require,
}

impl From<SmbEncryptionLevel> for smbc_smb_encrypt_level {
    fn from(mode: SmbEncryptionLevel) -> Self {
        match mode {
            SmbEncryptionLevel::None => 0,
            SmbEncryptionLevel::Request => 1,
            SmbEncryptionLevel::Require => 2,
        }
    }
}

#[cfg(test)]
mod test {

    use super::*;

    use pretty_assertions::assert_eq;

    #[test]
    fn should_initialize_smb_options() {
        let options = SmbOptions::default();
        assert_eq!(options.browser_max_lmb_count, 0);
        assert_eq!(options.case_sensitive, false);
        assert_eq!(options.encryption_level, SmbEncryptionLevel::None);
        assert_eq!(options.fallback_after_kerberos, false);
        assert_eq!(options.full_time_names, false);
        assert_eq!(options.no_auto_anonymous_login, false);
        assert_eq!(options.one_share_per_server, false);
        assert_eq!(options.open_share_mode, SmbShareMode::DenyNone);
        assert_eq!(options.url_encode_readdir_entries, false);
        assert_eq!(options.use_ccache, false);
        assert_eq!(options.use_kerberos, false);
    }

    #[test]
    fn should_configure_smb_options() {
        let options = SmbOptions::default()
            .browser_max_lmb_count(10)
            .case_sensitive(true)
            .encryption_level(SmbEncryptionLevel::Require)
            .fallback_after_kerberos(true)
            .full_time_names(true)
            .no_auto_anonymous_login(true)
            .one_share_per_server(true)
            .open_share_mode(SmbShareMode::DenyAll)
            .url_encode_readdir_entries(true)
            .use_ccache(true)
            .use_kerberos(true);
        assert_eq!(options.browser_max_lmb_count, 10);
        assert_eq!(options.case_sensitive, true);
        assert_eq!(options.encryption_level, SmbEncryptionLevel::Require);
        assert_eq!(options.fallback_after_kerberos, true);
        assert_eq!(options.full_time_names, true);
        assert_eq!(options.no_auto_anonymous_login, true);
        assert_eq!(options.one_share_per_server, true);
        assert_eq!(options.open_share_mode, SmbShareMode::DenyAll);
        assert_eq!(options.url_encode_readdir_entries, true);
        assert_eq!(options.use_ccache, true);
        assert_eq!(options.use_kerberos, true);
    }

    #[test]
    fn should_convert_share_mode_to_i32() {
        assert_eq!(smbc_share_mode::from(SmbShareMode::DenyNone), 4);
        assert_eq!(smbc_share_mode::from(SmbShareMode::DenyAll), 1);
        assert_eq!(smbc_share_mode::from(SmbShareMode::DenyFcb), 7);
        assert_eq!(smbc_share_mode::from(SmbShareMode::DenyRead), 3);
        assert_eq!(smbc_share_mode::from(SmbShareMode::DenyWrite), 2);
        assert_eq!(smbc_share_mode::from(SmbShareMode::DenyDos), 0);
    }

    #[test]
    fn should_convert_encryption_level_to_i32() {
        assert_eq!(smbc_smb_encrypt_level::from(SmbEncryptionLevel::None), 0);
        assert_eq!(smbc_smb_encrypt_level::from(SmbEncryptionLevel::Request), 1);
        assert_eq!(smbc_smb_encrypt_level::from(SmbEncryptionLevel::Require), 2);
    }
}
