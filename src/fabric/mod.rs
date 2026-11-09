//! Optional managed workspace authority and storage-aware execution.
//! Standalone S3 does not import or initialize this module.
pub mod authority;
pub mod cache;
pub mod client;
pub mod contract;
pub mod transport;
pub mod worker;
