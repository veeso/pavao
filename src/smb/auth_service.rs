//! # AuthService
//!
//! a static structure which is used to store credentials for authentication

use std::collections::HashMap;

use crate::SmbCredentials;

#[derive(Debug, Default)]
pub struct AuthService {
    pub credentials: HashMap<String, SmbCredentials>,
}

impl AuthService {
    pub fn insert<S: AsRef<str>>(&mut self, uuid: S, creds: SmbCredentials) {
        trace!("new credentials for {}", uuid.as_ref());
        self.credentials.insert(uuid.as_ref().to_string(), creds);
    }

    pub fn remove<S: AsRef<str>>(&mut self, uuid: S) {
        trace!("removed credentials for {}", uuid.as_ref());
        self.credentials.remove(uuid.as_ref());
    }

    pub fn get<S: AsRef<str>>(&self, uuid: S) -> &SmbCredentials {
        self.credentials.get(uuid.as_ref()).unwrap()
    }
}

#[cfg(test)]
mod test {

    use super::*;

    use pretty_assertions::assert_eq;

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
