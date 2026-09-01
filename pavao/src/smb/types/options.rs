//! Connection options for [`SmbClient`](crate::SmbClient).

use pavao_sys::{smbc_share_mode, smbc_smb_encrypt_level};

/// Optional behavior applied when initializing the shared SMB context.
///
/// Use the builder-style methods to override individual defaults.
///
/// # Examples
///
/// ```
/// use pavao::{SmbEncryptionLevel, SmbOptions, SmbShareMode};
///
/// let options = SmbOptions::default()
///     .case_sensitive(true)
///     .encryption_level(SmbEncryptionLevel::Require)
///     .open_share_mode(SmbShareMode::DenyWrite);
/// ```
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
    /// Sets the maximum number of local master browsers queried when browsing.
    pub fn browser_max_lmb_count(mut self, browser_max_lmb_count: i32) -> Self {
        self.browser_max_lmb_count = browser_max_lmb_count;
        self
    }

    /// Controls whether remote path matching is case-sensitive.
    pub fn case_sensitive(mut self, case_sensitive: bool) -> Self {
        self.case_sensitive = case_sensitive;
        self
    }

    /// Sets the SMB transport encryption policy.
    pub fn encryption_level(mut self, encryption_level: SmbEncryptionLevel) -> Self {
        self.encryption_level = encryption_level;
        self
    }

    /// Controls whether authentication falls back after Kerberos fails.
    pub fn fallback_after_kerberos(mut self, fallback_after_kerberos: bool) -> Self {
        self.fallback_after_kerberos = fallback_after_kerberos;
        self
    }

    /// Controls whether directory listings request full time information.
    ///
    /// This option is retained for compatibility but is not currently forwarded to
    /// `libsmbclient`.
    pub fn full_time_names(mut self, full_time_names: bool) -> Self {
        self.full_time_names = full_time_names;
        self
    }

    /// Prevents automatic anonymous login attempts when authentication fails.
    pub fn no_auto_anonymous_login(mut self, no_auto_anonymous_login: bool) -> Self {
        self.no_auto_anonymous_login = no_auto_anonymous_login;
        self
    }

    /// Restricts each server connection to a single share.
    pub fn one_share_per_server(mut self, one_share_per_server: bool) -> Self {
        self.one_share_per_server = one_share_per_server;
        self
    }

    /// Sets the sharing restrictions applied when files are opened.
    pub fn open_share_mode(mut self, open_share_mode: SmbShareMode) -> Self {
        self.open_share_mode = open_share_mode;
        self
    }

    /// Controls URL encoding of names returned by directory reads.
    pub fn url_encode_readdir_entries(mut self, url_encode_readdir_entries: bool) -> Self {
        self.url_encode_readdir_entries = url_encode_readdir_entries;
        self
    }

    /// Controls whether Kerberos credentials are read from the credential cache.
    pub fn use_ccache(mut self, use_ccache: bool) -> Self {
        self.use_ccache = use_ccache;
        self
    }

    /// Controls whether Kerberos authentication is attempted.
    pub fn use_kerberos(mut self, use_kerberos: bool) -> Self {
        self.use_kerberos = use_kerberos;
        self
    }
}

/// Sharing restrictions applied when opening a remote file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmbShareMode {
    /// Uses DOS compatibility sharing rules.
    DenyDos,
    /// Denies other readers and writers.
    DenyAll,
    /// Denies other writers while allowing readers.
    DenyWrite,
    /// Denies other readers while allowing writers.
    DenyRead,
    /// Allows other readers and writers.
    DenyNone,
    /// Uses file-control-block compatibility sharing rules.
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

/// Encryption policy for SMB transport traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmbEncryptionLevel {
    /// Does not request transport encryption.
    None,
    /// Requests encryption but permits an unencrypted connection.
    Request,
    /// Requires transport encryption.
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

    use pretty_assertions::assert_eq;

    use super::*;

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
