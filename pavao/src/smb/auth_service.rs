//! Credential storage used by the native authentication callback.

use std::collections::HashMap;

use crate::SmbCredentials;

/// Associates native context identifiers with their SMB credentials.
#[derive(Debug, Default)]
pub struct AuthService {
    /// Credentials indexed by a native context identifier.
    pub credentials: HashMap<String, SmbCredentials>,
}

impl AuthService {
    /// Associates `creds` with `uuid`, replacing any existing credentials.
    pub fn insert<S: AsRef<str>>(&mut self, uuid: S, creds: SmbCredentials) {
        trace!("new credentials for {}", uuid.as_ref());
        self.credentials.insert(uuid.as_ref().to_string(), creds);
    }

    /// Removes credentials associated with `uuid`.
    pub fn remove<S: AsRef<str>>(&mut self, uuid: S) {
        trace!("removed credentials for {}", uuid.as_ref());
        self.credentials.remove(uuid.as_ref());
    }

    /// Returns the credentials associated with `uuid`.
    ///
    /// # Panics
    ///
    /// Panics if `uuid` is not present in the store.
    pub fn get<S: AsRef<str>>(&self, uuid: S) -> &SmbCredentials {
        self.credentials.get(uuid.as_ref()).unwrap()
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn should_use_auth_service() {
        let mut auth_service = AuthService::default();
        auth_service.insert("test", SmbCredentials::default());
        let _ = auth_service.get("test");
        auth_service.remove("test");
    }

    #[test]
    #[should_panic]
    fn should_panic_when_accessing_unknown_credentials() {
        let auth_service = AuthService::default();
        auth_service.get("test");
    }
}
