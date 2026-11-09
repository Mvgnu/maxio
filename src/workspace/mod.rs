//! Optional selective workspace client. The S3 server never initializes this layer.
pub mod contract;
pub mod local;
pub mod remote;
pub use contract::*;
pub use local::LocalWorkspace;
pub use remote::WorkspaceRemote;

impl contract::WorkspaceReader for WorkspaceRemote {
    fn target_id(&self) -> String {
        WorkspaceRemote::target_id(self)
    }
    fn download_at<'a>(
        &'a self,
        snapshot: &'a contract::Snapshot,
        path: &'a str,
        destination: &'a std::path::Path,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send + 'a>> {
        Box::pin(async move {
            let file = snapshot
                .manifest
                .files
                .get(path)
                .ok_or_else(|| anyhow::anyhow!("path is absent from selected revision"))?;
            self.download(file, destination).await
        })
    }
}
