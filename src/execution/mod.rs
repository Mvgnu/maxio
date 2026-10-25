//! Optional trusted local execution. This is not a remote worker security boundary.
pub mod contract;
pub mod runner;
pub use contract::*;
pub use runner::{doctor, run, run_verified};
