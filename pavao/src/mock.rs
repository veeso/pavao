//! Test-only logging helpers.

/// Initializes a logger suitable for unit tests.
pub fn logger() {
    let _ = env_logger::builder()
        .is_test(true)
        .filter_level(log::LevelFilter::Debug)
        .try_init();
}
