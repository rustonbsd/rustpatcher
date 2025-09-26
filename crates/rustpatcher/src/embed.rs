use std::str::FromStr;

use once_cell::sync::OnceCell;

use crate::{PatchInfo, Version};

#[doc(hidden)]
static APP_VERSION: OnceCell<&'static str> = OnceCell::new();
#[doc(hidden)]
static OWNER_PUB_KEY: OnceCell<ed25519_dalek::VerifyingKey> = OnceCell::new();

#[doc(hidden)]
pub fn __set_version(version: &'static str) {
    let _ = APP_VERSION.set(version);
}

#[doc(hidden)]
pub fn __set_owner_pub_key(pub_key: ed25519_dalek::VerifyingKey) {
    let _ = OWNER_PUB_KEY.set(pub_key);
}

pub fn get_owner_pub_key() -> &'static ed25519_dalek::VerifyingKey {
    OWNER_PUB_KEY.get().expect("Owner public key not initialized")
}

pub fn get_app_version() -> &'static str {
    APP_VERSION.get().expect("Version not initialized")
}

// 28_bytes
// hex: 0x1742525553545041544348455242454d42454442424f554e44534217
#[doc(hidden)]
pub static EMBED_BOUNDS: &[u8] = b"\x17\x42RUSTPATCHER\x42EMBED\x42BOUNDS\x42\x17";

#[doc(hidden)]
const VERSION_FIELD_LEN: usize = 16;
#[doc(hidden)]
const VERSION_ASCII: &str = env!("CARGO_PKG_VERSION");

#[doc(hidden)]
const fn version_field_ascii_padded(s: &str) -> [u8; VERSION_FIELD_LEN] {
    let bytes = s.as_bytes();
    let mut out = [0u8; VERSION_FIELD_LEN];
    let mut i = 0;
    while i < bytes.len() && i < VERSION_FIELD_LEN {
        out[i] = bytes[i];
        i += 1;
    }
    out
}

#[doc(hidden)]
const VERSION_BYTES: [u8; VERSION_FIELD_LEN] = version_field_ascii_padded(VERSION_ASCII);

#[doc(hidden)]
const BIN_HASH: [u8; 32] = [0; 32];
#[doc(hidden)]
const BIN_SIZE: [u8; 8] = [0; 8];
#[doc(hidden)]
const BIN_SIG: [u8; 64] = [0; 64];
#[doc(hidden)]
pub const EMBED_REGION_LEN: usize =
    28 + VERSION_BYTES.len() + BIN_HASH.len() + BIN_SIZE.len() + BIN_SIG.len() + 28;

// Assert sizes at compile time
#[doc(hidden)]
const _: () = {
    assert!(EMBED_BOUNDS.len() == 28);
    assert!(VERSION_BYTES.len() == 16);
    assert!(EMBED_REGION_LEN == 176);
};

// Build const array without any runtime code or allocation
#[doc(hidden)]
#[unsafe(link_section = ".embedded_signature")]
#[used]
#[unsafe(no_mangle)]
pub static EMBED_REGION: [u8; EMBED_REGION_LEN] = {
    let mut buf = [0u8; EMBED_REGION_LEN];
    let mut off = 0;

    // bounds start
    {
        let b = EMBED_BOUNDS;
        let mut i = 0;
        while i < b.len() {
            buf[off + i] = b[i];
            i += 1;
        }
        off += b.len();
    }

    // bin_hash placeholder
    {
        let b = BIN_HASH;
        let mut i = 0;
        while i < b.len() {
            buf[off + i] = b[i];
            i += 1;
        }
        off += b.len();
    }

    // bin_size placeholder
    {
        let b = BIN_SIZE;
        let mut i = 0;
        while i < b.len() {
            buf[off + i] = b[i];
            i += 1;
        }
        off += b.len();
    }

    // bin_sig placeholder
    {
        let b = BIN_SIG;
        let mut i = 0;
        while i < b.len() {
            buf[off + i] = b[i];
            i += 1;
        }
        off += b.len();
    }

    // padded-str-version
    {
        let b = VERSION_BYTES;
        let mut i = 0;
        while i < b.len() {
            buf[off + i] = b[i];
            i += 1;
        }
        off += b.len();
    }

    // bounds end
    {
        let b = EMBED_BOUNDS;
        let mut i = 0;
        while i < b.len() {
            buf[off + i] = b[i];
            i += 1;
        }
    }
    buf
};

#[doc(hidden)]
pub fn embed(version: &'static str, pub_key: &'static str) {
    __set_version(version);
    __set_owner_pub_key(z32::decode(pub_key.as_bytes()).ok().and_then(|k_bytes| {
        let key_array: [u8; 32] = k_bytes.try_into().ok()?;
        ed25519_dalek::VerifyingKey::from_bytes(&key_array).ok()
    }).expect("failed to decode public key"));
    #[cfg(not(debug_assertions))]
    unsafe {
        core::ptr::read_volatile(&EMBED_REGION as *const _);
    }
}

#[doc(hidden)]
pub struct EmbeddedRegion {
    pub start: usize,
    pub end: usize,
}

#[doc(hidden)]
pub fn cut_embed_section(bin_bytes: Vec<u8>) -> anyhow::Result<(Vec<u8>, Vec<u8>, EmbeddedRegion)> {
    let start = bin_bytes
        .windows(EMBED_BOUNDS.len())
        .position(|window| window == EMBED_BOUNDS)
        .ok_or_else(|| anyhow::anyhow!("failed to find embed bounds start"))?;
    let end = bin_bytes
        .windows(EMBED_BOUNDS.len())
        .rposition(|window| window == EMBED_BOUNDS)
        .ok_or_else(|| anyhow::anyhow!("failed to find embed bounds end"))?
        + EMBED_BOUNDS.len();
    if end as i128 - start as i128 != EMBED_REGION.len() as i128 {
        return Err(anyhow::anyhow!("invalid embed section size"));
    }
    let mut out = bin_bytes;
    let embed_region = out.drain(start..end).into_iter().collect::<Vec<_>>();
    Ok((out, embed_region, EmbeddedRegion { start, end }))
}

#[doc(hidden)]
pub fn get_embedded_version(embed_region_bytes: &Vec<u8>) -> anyhow::Result<Version> {
    let version_offset = EMBED_BOUNDS.len() + BIN_HASH.len() + BIN_SIZE.len() + BIN_SIG.len();
    let version_bytes =
        embed_region_bytes[version_offset..version_offset + VERSION_FIELD_LEN].to_vec();
    let version_str = std::str::from_utf8(&version_bytes)?;
    Version::from_str(version_str.trim_end_matches(char::from(0)).trim())
}

#[doc(hidden)]
pub fn get_embedded_patch_info(bin_data: &Vec<u8>) -> anyhow::Result<crate::PatchInfo> {
    let (_, embed_region_bytes, _) = cut_embed_section(bin_data.clone())?;

    let (_, buf) = embed_region_bytes.split_at(EMBED_BOUNDS.len());
    let (hash_buf, buf) = buf.split_at(BIN_HASH.len());
    let (size_buf, buf) = buf.split_at(BIN_SIZE.len());
    let (sig_buf, _) = buf.split_at(BIN_SIG.len());

    let version = get_embedded_version(&embed_region_bytes)?;
    let size = u64::from_le_bytes(size_buf.try_into().map_err(|_| anyhow::anyhow!("invalid size bytes"))?);
    let hash: [u8; 32] = hash_buf.try_into().map_err(|_| anyhow::anyhow!("invalid hash bytes"))?;
    let signature: [u8; 64] = sig_buf.try_into().map_err(|_| anyhow::anyhow!("invalid signature bytes"))?;

    Ok(crate::PatchInfo {
        version,
        size,
        hash,
        signature: signature.into(),
    })
}

#[doc(hidden)]
pub fn set_embedded_patch_info(bin_data: &mut Vec<u8>, patch_info: PatchInfo,embed_region_bytes: EmbeddedRegion) -> anyhow::Result<()> {

    let (start, end) = (embed_region_bytes.start, embed_region_bytes.end);
    if end - start != EMBED_REGION_LEN {
        return Err(anyhow::anyhow!("invalid embed region length"));
    }

    let mut region_buf = Vec::with_capacity(EMBED_REGION_LEN);
    region_buf.extend_from_slice(EMBED_BOUNDS);
    region_buf.extend_from_slice(&patch_info.hash);
    region_buf.extend_from_slice(&patch_info.size.to_le_bytes());
    region_buf.extend_from_slice(&patch_info.signature.to_bytes());
    region_buf.extend_from_slice(&VERSION_BYTES);
    region_buf.extend_from_slice(EMBED_BOUNDS);

    if region_buf.len() != EMBED_REGION_LEN {
        return Err(anyhow::anyhow!("internal error: invalid embed region length"));
    }

    bin_data.splice(start..end, region_buf.iter().cloned());

    Ok(())
}