//! Optional selective workspace client. The S3 server never initializes this layer.
pub mod contract;
pub mod local;
pub mod remote;
pub use contract::*;
pub use local::LocalWorkspace;
pub use remote::WorkspaceRemote;
