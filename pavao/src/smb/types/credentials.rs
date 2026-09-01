//! Credentials used to authenticate with an SMB server.

/// Authentication and share-selection settings for [`SmbClient`](crate::SmbClient).
///
/// Authentication fields default to empty strings, allowing anonymous authentication when the
/// server supports it. A usable client still requires an appropriate server and share.
///
/// # Examples
///
/// ```
/// use pavao::SmbCredentials;
///
/// let credentials = SmbCredentials::default()
///     .server("smb://server.example")
///     .share("/documents")
///     .username("alice")
///     .password("secret")
///     .workgroup("WORKGROUP");
/// ```
#[derive(Debug, Default, Clone)]
pub struct SmbCredentials {
    pub(crate) password: String,
    pub(crate) server: String,
    pub(crate) share: String,
    pub(crate) username: String,
    pub(crate) workgroup: String,
}

impl SmbCredentials {
    /// Sets the password used for authentication.
    pub fn password<S: AsRef<str>>(mut self, password: S) -> Self {
        self.password = password.as_ref().to_string();
        self
    }

    /// Sets the SMB server URL, such as `smb://server.example`.
    pub fn server<S: AsRef<str>>(mut self, server: S) -> Self {
        self.server = server.as_ref().to_string();
        self
    }

    /// Sets the share path on the server.
    pub fn share<S: AsRef<str>>(mut self, share: S) -> Self {
        self.share = share.as_ref().to_string();
        self
    }

    /// Sets the username used for authentication.
    pub fn username<S: AsRef<str>>(mut self, username: S) -> Self {
        self.username = username.as_ref().to_string();
        self
    }

    /// Sets the Windows workgroup or domain used for authentication.
    pub fn workgroup<S: AsRef<str>>(mut self, workgroup: S) -> Self {
        self.workgroup = workgroup.as_ref().to_string();
        self
    }
}

#[cfg(test)]
mod test {

    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn should_init_smb_credentials() {
        let creds = SmbCredentials::default();
        assert_eq!(creds.password.as_str(), "");
        assert_eq!(creds.server.as_str(), "");
        assert_eq!(creds.share.as_str(), "");
        assert_eq!(creds.username.as_str(), "");
        assert_eq!(creds.workgroup.as_str(), "");
    }

    #[test]
    fn should_build_smb_credentials() {
        let creds = SmbCredentials::default()
            .password("password")
            .server("server")
            .share("share")
            .username("username")
            .workgroup("workgroup");
        assert_eq!(creds.password.as_str(), "password");
        assert_eq!(creds.server.as_str(), "server");
        assert_eq!(creds.share.as_str(), "share");
        assert_eq!(creds.username.as_str(), "username");
        assert_eq!(creds.workgroup.as_str(), "workgroup");
    }
}
