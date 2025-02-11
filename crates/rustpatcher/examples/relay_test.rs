use ed25519_dalek::{ Signature, Verifier, VerifyingKey};
use pkarr::{PublicKey, SignedPacket};
use reqwest::Client;
use rustpatcher::utils::Storage;
use tokio;
use z32;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();
    let z32_public_key = "ewkijs9aynd1gxp8bd7y73qkc7maqc8qh1j8kej9dumuwr9cq7by";
    let relay_url = format!("https://relay.pkarr.org/{}", z32_public_key);

    // Decode z-base-32 public key
    let public_key_bytes = VerifyingKey::from_bytes(&[69,21,84,219,248,0,135,35,61,167,8,250,14,229,202,103,87,135,48,238,228,146,117,33,63,28,215,58,19,236,119,66])?;
    let public_key = public_key_bytes;

    let response = client
        .get(&relay_url)
        .header("Accept", "application/pkarr.org/relays#payload")
        .send()
        .await?;

    if response.status().is_success() {
        let bytes = response.bytes().await?;

        // Direct verification approach
        let signature = Signature::from_bytes(bytes[0..64].try_into()?);
        let timestamp = &bytes[64..72];
        let dns_packet = &bytes[72..];
        
        let mut signed_message = dns_packet.to_vec();
        println!("Verification result: {:?}", public_key.verify(&bytes, &signature));

        // pkarr::SignedPacket approach (requires public key prepended)
        let signed_packet = SignedPacket::from_bytes({
            let mut temp = public_key_bytes.as_bytes().clone().to_vec().clone().to_vec();
            temp.extend_from_slice(&bytes);
            &bytes::Bytes::from_owner(temp)
        })?;
        
        println!("Valid SignedPacket:");
        println!("  Public Key: {}", z32::encode(signed_packet.public_key().as_bytes()));
        println!("  Timestamp: {} μs", signed_packet.timestamp());
        println!("  DNS Packet Size: {} bytes", signed_packet.encoded_packet().len());
    }

    Ok(())
}