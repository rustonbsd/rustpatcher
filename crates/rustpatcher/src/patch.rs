use crate::Version;
use ed25519_dalek::{Signature, SigningKey, ed25519::signature::SignerMut};
use serde::{Deserialize, Serialize};
use sha2::Digest;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PatchInfo {
    pub version: Version,
    pub size: u64,
    pub hash: [u8; 32],
    pub signature: Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Patch {
    info: PatchInfo,
    data: Vec<u8>,
}

impl Patch {
    pub fn info(&self) -> &PatchInfo {
        &self.info
    }

    pub fn data(&self) -> &Vec<u8> {
        &self.data
    }

    pub fn verify(&self) -> anyhow::Result<()> {
        #[cfg(target_os = "macos")]
        let data_stripped: Vec<u8> = crate::macho::exclude_code_signature(self.data.as_slice())?;
        #[cfg(target_os = "macos")]
        let data_stripped = data_stripped.as_slice();
        #[cfg(not(target_os = "macos"))]
        let data_stripped = self.data.as_slice();

        let (data_no_embed, _, _) = crate::embed::cut_embed_section(data_stripped)?;

        let mut data_hasher = sha2::Sha512::new();
        data_hasher.update(&data_no_embed);
        let data_hash: [u8; 32] = data_hasher.finalize()[..32].try_into()?;

        let mut sign_hash = sha2::Sha512::new();
        sign_hash.update(self.info.version.to_string());
        sign_hash.update(data_hash);
        sign_hash.update((data_no_embed.len() as u64).to_le_bytes());
        let sign_hash = sign_hash.finalize();

        crate::get_owner_pub_key().verify_strict(&sign_hash, &self.info.signature)?;

        if data_hash != self.info.hash {
            anyhow::bail!("data hash mismatch");
        }

        if data_no_embed.len() as u64 != self.info.size {
            anyhow::bail!("data size mismatch");
        }

        Ok(())
    }

    pub fn sign(
        owner_signing_key: SigningKey,
        data_no_embed: Vec<u8>,
        version: Version,
    ) -> anyhow::Result<PatchInfo> {
        let mut owner_siging_key = owner_signing_key;
        let mut data_hasher = sha2::Sha512::new();
        data_hasher.update(data_no_embed.as_slice());
        let data_hash = data_hasher.finalize()[..32].try_into()?;

        let mut sign_hash = sha2::Sha512::new();
        sign_hash.update(version.to_string());
        sign_hash.update(data_hash);
        sign_hash.update((data_no_embed.len() as u64).to_le_bytes());
        let sign_hash = sign_hash.finalize();
        let signature = owner_siging_key.sign(&sign_hash);

        Ok(PatchInfo {
            version,
            size: data_no_embed.len() as u64,
            hash: data_hash,
            signature,
        })
    }

    pub fn from_self() -> anyhow::Result<Self> {
        let data = std::fs::read(std::env::current_exe()?)?;
        let patch_info = crate::embed::get_embedded_patch_info(data.as_slice())?;

        let patch = Self {
            info: patch_info,
            data,
        };
        patch.verify()?;
        Ok(patch)
    }
}
