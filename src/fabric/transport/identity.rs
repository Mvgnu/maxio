//! Individual device key creation and proof. Private keys never leave their device.
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use openssl::pkey::{Id, PKey, Private};
use openssl::sign::{Signer, Verifier};
use std::io::Write;
use std::path::Path;

pub struct DeviceKey {
    key: PKey<Private>,
}
impl DeviceKey {
    pub fn generate(path: &Path) -> Result<Self> {
        ensure!(path.is_absolute(), "device key path must be absolute");
        let key = PKey::generate_ed25519()?;
        let mut file = crate::files::new_file(path)?;
        file.write_all(&key.private_key_to_pem_pkcs8()?)?;
        file.sync_all()?;
        crate::files::sync_directory(path.parent().context("key path has no parent")?)?;
        Ok(Self { key })
    }
    pub fn load(path: &Path) -> Result<Self> {
        ensure!(path.is_absolute(), "device key path must be absolute");
        let meta = std::fs::symlink_metadata(path)?;
        ensure!(
            meta.is_file() && !meta.file_type().is_symlink() && meta.len() <= 16 * 1024,
            "device key must be a bounded regular private file"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            ensure!(
                meta.permissions().mode() & 0o077 == 0,
                "device key must have private permissions (chmod 600)"
            );
        }
        let pem = std::fs::read(path)?;
        ensure!(
            !String::from_utf8_lossy(&pem).contains("ENCRYPTED"),
            "encrypted device key files are not supported"
        );
        let key = PKey::private_key_from_pem_passphrase(&pem, b"")
            .context("invalid Ed25519 device key")?;
        ensure!(key.id() == Id::ED25519, "device key must be Ed25519");
        Ok(Self { key })
    }
    pub fn public_key(&self) -> Result<String> {
        Ok(STANDARD.encode(self.key.raw_public_key()?))
    }
    pub fn sign(&self, challenge: &super::Challenge) -> Result<String> {
        let mut signer = Signer::new_without_digest(&self.key)?;
        Ok(STANDARD.encode(signer.sign_oneshot_to_vec(&challenge_message(challenge)?)?))
    }
}

pub(crate) fn challenge_message(challenge: &super::Challenge) -> Result<Vec<u8>> {
    let mut message = b"MaxIO device authentication v1\0".to_vec();
    message.extend(serde_json::to_vec(challenge)?);
    Ok(message)
}

pub(crate) fn verify(
    public_key: &str,
    challenge: &super::Challenge,
    signature: &str,
) -> Result<bool> {
    let public = STANDARD.decode(public_key)?;
    let signature = STANDARD.decode(signature)?;
    ensure!(
        public.len() == 32 && signature.len() == 64,
        "invalid device proof size"
    );
    let key = PKey::public_key_from_raw_bytes(&public, Id::ED25519)?;
    let mut verifier = Verifier::new_without_digest(&key)?;
    Ok(verifier.verify_oneshot(&signature, &challenge_message(challenge)?)?)
}

pub(crate) fn random_secret() -> Result<String> {
    let mut bytes = [0u8; 32];
    openssl::rand::rand_bytes(&mut bytes)?;
    Ok(hex::encode(bytes))
}

pub(crate) fn now_ms() -> Result<u64> {
    Ok(u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis(),
    )?)
}
