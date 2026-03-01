#[path = "integration/helpers.rs"]
mod helpers;

pub(crate) use helpers::*;

#[path = "integration/core_tests.rs"]
mod core_tests;

#[path = "integration/auth_tests.rs"]
mod auth_tests;

#[path = "integration/runtime_tests.rs"]
mod runtime_tests;

#[path = "integration/console_tests.rs"]
mod console_tests;

#[path = "integration/erasure_tests.rs"]
mod erasure_tests;

#[path = "integration/checksum_tests.rs"]
mod checksum_tests;

#[path = "integration/parity_tests.rs"]
mod parity_tests;
