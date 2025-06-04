use std::{str::FromStr, sync::Arc, time::Duration};

use anyhow::bail;
use bytes::Bytes;
use ed25519_dalek::{ed25519::signature::SignerMut, Signature, SigningKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, SIGNATURE_LENGTH};
use iroh::{Endpoint, PublicKey};
use iroh_topic_tracker::topic_tracker::{Topic, TopicTracker};
use pkarr::{Keypair, SignedPacket};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::{utils::{compute_hash, Storage, LAST_REPLY_ID_NAME}, LastReplyId};

#[derive(Debug, Clone, Serialize,Deserialize,PartialOrd, PartialEq, Eq)]
pub struct Version(pub i32, pub i32, pub i32);

impl ToString for Version {
    fn to_string(&self) -> String {
        format!("{}.{}.{}",self.0,self.1,self.2)
    }
}

impl FromStr for Version {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('.').collect();

        if parts.len() != 3 {
            bail!("wrong version format")
        }

        // Parse each component individually
        let parse_component = |s: &str| -> anyhow::Result<i32> {
            Ok(s.parse::<i32>()?)
        };

        let major = parse_component(parts[0])?;
        let minor = parse_component(parts[1])?;
        let patch = parse_component(parts[2])?;

        Ok(Version(major, minor, patch))
        }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let self_sum: i128 = ((i32::MAX as i128).pow(2) * self.0 as i128)
            + ((i32::MAX as i128).pow(1) * self.1 as i128)
            + self.2 as i128;
        let other_sum: i128 = ((i32::MAX as i128).pow(2) * other.0 as i128)
            + ((i32::MAX as i128).pow(1) * other.1 as i128)
            + other.2 as i128;
        self_sum.cmp(&other_sum)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionInfo {
    #[serde(with = "serde_version")]
    pub version: Version,
    #[serde(with = "serde_z32_array")]
    pub hash: [u8; 32],
    #[serde(with = "serde_z32_signature")]
    pub signature: Signature,
}

impl VersionInfo {
    pub fn to_topic_hash(&self,shared_secret: [u8;SECRET_KEY_LENGTH]) -> anyhow::Result<Topic> {
        let mut signing_key = SigningKey::from_bytes(&shared_secret);
        let data = serde_json::to_string(self)?;
        let signature = signing_key.sign(data.as_bytes());
        Ok(Topic::from_passphrase(&z32::encode(&signature.to_bytes())))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionTracker {
    #[serde(with = "serde_z32_array")]
    trusted_key: [u8; PUBLIC_KEY_LENGTH],
    version_info: Option<VersionInfo>,
    #[serde(with = "serde_z32_vec_array")]
    node_ids: Vec<[u8; PUBLIC_KEY_LENGTH]>,
    #[serde(with = "serde_z32_bytes_option")]
    data: Option<Bytes>,
}

impl VersionTracker {
    pub fn new(trusted_key: &[u8; PUBLIC_KEY_LENGTH]) -> Self {
        Self {
            trusted_key: trusted_key.clone(),
            version_info: None,
            node_ids: vec![],
            data: None,
        }
    }

    pub fn version_info(&self) -> Option<VersionInfo> {
        self.version_info.clone()
    }

    pub fn data(&self) -> Option<Bytes> {
        self.data.clone()
    }

    pub fn node_ids(&self) -> Vec<[u8; PUBLIC_KEY_LENGTH]> {
        self.node_ids.clone()
    }

    pub fn load(
        trusted_key: &[u8; PUBLIC_KEY_LENGTH],
        version_info: &VersionInfo,
        data: &Bytes,
        node_ids: Vec<[u8; PUBLIC_KEY_LENGTH]>,
    ) -> anyhow::Result<Self> {
        Self::verify_data(trusted_key,version_info, data)?;

        Ok(Self {
            trusted_key: trusted_key.clone(),
            version_info: Some(version_info.clone()),
            node_ids: node_ids,
            data: Some(data.clone()),
        })
    }

    // Verify data signature, update version
    pub fn update_version(
        self: &mut Self,
        version_info: &VersionInfo,
        data: &Bytes,
        node_ids: Option<Vec<[u8; PUBLIC_KEY_LENGTH]>>,
    ) -> anyhow::Result<()> {
        Self::verify_data(&self.trusted_key,version_info, data)?;

        self.version_info = Some(version_info.clone());
        self.node_ids = node_ids.unwrap_or(vec![]);
        self.data = Some(data.clone());

        Ok(())
    }

    pub fn add_node_id(self: &mut Self, node_id: &[u8; PUBLIC_KEY_LENGTH]) {
        if !self.node_ids.contains(node_id) {
            self.node_ids.push(node_id.clone());
        }
    }

    pub fn rm_node_id(self: &mut Self, node_id: &[u8; PUBLIC_KEY_LENGTH]) {
        if self.node_ids.contains(node_id) {
            let len = self.node_ids.len();
            for i in 1..len + 1 {
                if self.node_ids[len - i].eq(node_id) {
                    self.node_ids.remove(len - i);
                }
            }
        }
    }

    pub fn verify_data(trusted_key: &[u8; PUBLIC_KEY_LENGTH], version_info: &VersionInfo, data: &Bytes) -> anyhow::Result<()> {
        let pub_key = PublicKey::from_bytes(&trusted_key)?;
        let sig = version_info.signature;

        log::debug!("Sig: {}",z32::encode(&sig.to_bytes()));
        log::debug!("hash: {}",z32::encode(&compute_hash(&data)));
        log::debug!("trusted: {}",z32::encode(trusted_key));

        match pub_key.verify(&data, &sig) {
            Ok(_) => Ok(()),
            Err(_) => anyhow::bail!("signature doesn't match data"),
        }
    }

    pub async fn as_signed_packet(&self,secret_key: &[u8;SECRET_KEY_LENGTH]) -> anyhow::Result<SignedPacket> {
        if self.version_info().is_none() {
            bail!("uninitialized version info")
        } 
        if self.data().is_none() {
            bail!("uninitialized data")
        }

        // Set reply id to unix time
        let vi = self.version_info.clone().unwrap();

        let mut last_reply_id: LastReplyId = LastReplyId::from_file(LAST_REPLY_ID_NAME)
            .await
            .unwrap_or(LastReplyId(0));

        // Not sure if rap around will cause an error so to be safe
        last_reply_id.0 = if last_reply_id.0 >= u16::MAX - 1 {
            0
        } else {
            last_reply_id.0 + 1
        };
        let _ = last_reply_id.to_file("last_reply_id").await;
        let mut signed_packet = SignedPacket::builder();

        // Version
        let version = serde_json::to_string(&vi.version)?;
        signed_packet = signed_packet.txt("_version".try_into()?, version.as_str().try_into()?, 30);

        // Signature
        let signature = serde_json::to_string(&vi.signature)?;
        signed_packet = signed_packet.txt("_signature".try_into()?, signature.as_str().try_into()?, 30);

        // Hash
        let hash = serde_json::to_string(&vi.hash)?;
        signed_packet = signed_packet.txt("_hash".try_into()?, hash.as_str().try_into()?, 30);

        let key_pair = Keypair::from_secret_key(secret_key);

        Ok(signed_packet.sign(&key_pair, )?)
    }
}

#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct AuthRequest {
    pub sign_request: Bytes,
}

#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct Auth {
    pub signature: Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Protocol {
    Ready,
    AuthRequest(AuthRequest),
    Request(Auth),
    Data(VersionInfo, Bytes),
    DataUnavailable,
    Done,
}

#[derive(Debug, Clone)]
pub struct Patcher {
    pub trusted_key: [u8; PUBLIC_KEY_LENGTH],
    pub(crate) secret_key: [u8; SECRET_KEY_LENGTH],
    pub(crate) public_key: [u8; PUBLIC_KEY_LENGTH],
    pub(crate) shared_secret_key: [u8; SECRET_KEY_LENGTH],
    pub(crate) inner: Inner,
}

#[derive(Debug, Clone)]
pub(crate) struct Inner {
    pub endpoint: Endpoint,
    pub topic_tracker: TopicTracker,
    pub latest_version: Arc<Mutex<VersionTracker>>,
    pub latest_trusted_package: Arc<Mutex<Option<SignedPacket>>>,
    pub pkarr_publishing_interval: Duration,
}

pub mod serde_version {

    use serde::de::Error;
    use serde::{Deserializer, Serializer};

    use super::*;

    pub fn serialize<S>(version: &Version, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&version.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Version, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match Version::from_str(&s) {
            Ok(version) => Ok(version),
            Err(err) => Err(D::Error::custom(err)),
        }
    }
}

pub mod serde_z32_array {
    use serde::de::Error;
    use serde::{Deserializer, Serializer};

    use super::*;

    pub fn serialize<S, const N: usize>(bytes: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = z32::encode(bytes);
        serializer.serialize_str(&encoded)
    }

    pub fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = z32::decode(s.as_bytes()).map_err(|e| D::Error::custom(e.to_string()))?;

        if bytes.len() != N {
            return Err(D::Error::custom("invalid length"));
        }

        let mut arr = [0u8; N];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

pub mod serde_z32_bytes {
    use serde::de::Error;
    use serde::{Deserializer, Serializer};

    use super::*;

    pub fn serialize<S>(bytes: &Bytes, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = z32::encode(bytes);
        serializer.serialize_str(&encoded)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Bytes, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = z32::decode(s.as_bytes()).map_err(|e| D::Error::custom(e.to_string()))?;

        Ok(bytes.into())
    }
}

pub mod serde_z32_bytes_option {
    use serde::de::Error;
    use serde::{Deserializer, Serializer};

    use super::*;

    pub fn serialize<S>(bytes: &Option<Bytes>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = if let Some(bytes) = bytes {
            z32::encode(bytes)
        } else {
            "".to_string()
        };
        serializer.serialize_str(&encoded)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Bytes>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        if s.len() == 0 {
            return Ok(None)
        }
        let bytes = z32::decode(s.as_bytes()).map_err(|e| D::Error::custom(e.to_string()))?;

        Ok(Some(bytes.into()))
    }
}

pub mod serde_z32_signature {
    use serde::de::Error;
    use serde::{Deserializer, Serializer};

    use super::*;

    pub fn serialize<S>(signature: &Signature, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = z32::encode(&signature.to_bytes());
        serializer.serialize_str(&encoded)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Signature, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = z32::decode(s.as_bytes()).map_err(|e| D::Error::custom(e.to_string()))?;

        if bytes.len() != SIGNATURE_LENGTH {
            return Err(D::Error::custom("invalid length"));
        }

        let mut arr = [0u8; SIGNATURE_LENGTH];
        arr.copy_from_slice(&bytes);

        Ok(Signature::from_bytes(&arr))
    }
}

pub mod serde_z32_vec_array {
    use serde::{Deserializer, Serializer};

    use super::*;

    pub fn serialize<S, const N: usize>(
        vec: &Vec<[u8; N]>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = vec
            .iter()
            .map(|bytes| z32::encode(bytes))
            .collect::<Vec<String>>()
            .join(",");
        serializer.serialize_str(&encoded)
    }

    pub fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<Vec<[u8; N]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let vec = s
            .split(",")
            .filter_map(|s| match z32::decode(s.as_bytes()) {
                Ok(bytes) => {
                    if !bytes.len().eq(&N) {
                        return None;
                    }

                    let mut arr = [0u8; N];
                    arr.copy_from_slice(&bytes);
                    Some(arr)
                }
                Err(_) => None,
            })
            .collect::<Vec<[u8; N]>>();

        Ok(vec)
    }
}
