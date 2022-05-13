//! # mock
//!
//! mock functions and services

pub fn logger() {
    let _ = env_logger::builder().is_test(true).try_init();
}
