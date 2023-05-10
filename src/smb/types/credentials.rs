//! # Credentials
//!
//! module which exposes the smb credentials to authenticate to the smb server

/// SmbCredentials
#[derive(Debug, Default, Clone)]
pub struct SmbCredentials {
    pub(crate) password: String,
    pub(crate) server: String,
    pub(crate) share: String,
    pub(crate) username: String,
    pub(crate) workgroup: String,
}

impl SmbCredentials {
    /// Construct SmbCredentials with the provided password
    pub fn password<S: AsRef<str>>(mut self, password: S) -> Self {
        self.password = password.as_ref().to_string();
        self
    }

    /// Construct SmbCredentials with the provided server
    pub fn server<S: AsRef<str>>(mut self, server: S) -> Self {
        self.server = server.as_ref().to_string();
        self
    }

    /// Construct SmbCredentials with the provided share
    pub fn share<S: AsRef<str>>(mut self, share: S) -> Self {
        self.share = share.as_ref().to_string();
        self
    }

    /// Construct SmbCredentials with the provided username
    pub fn username<S: AsRef<str>>(mut self, username: S) -> Self {
        self.username = username.as_ref().to_string();
        self
    }

    /// Construct SmbCredentials with the provided workgroup
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
