use anyhow::{anyhow, Result};
use base58::ToBase58;
use libp2p::identity::{ed25519, Keypair as Libp2pKeypair, PublicKey as Libp2pPublicKey};
use libp2p_identity::PeerId;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;

use crate::encrypted_text::EncryptedText;
use crate::json_stringify_deterministic::stringify_deterministic;

#[derive(Clone)]
pub enum KeypairOrPublicKey {
    Keypair(Libp2pKeypair),
    PublicKey(Libp2pPublicKey),
}

#[derive(Clone)]
pub struct Keypair {
    pub inner: KeypairOrPublicKey,
}

#[derive(Serialize, Deserialize)]
pub struct KeypairJSON {
    pub id: String,
    pub public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_private_key: Option<String>,
}

impl KeypairJSON {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn public_key(&self) -> &str {
        &self.public_key
    }

    pub fn private_key(&self) -> Option<&str> {
        self.private_key.as_deref()
    }

    pub fn encrypted_private_key(&self) -> Option<&str> {
        self.encrypted_private_key.as_deref()
    }
}

impl Keypair {
    pub fn new(key: KeypairOrPublicKey) -> Self {
        Self { inner: key }
    }

    pub fn generate() -> Result<Self> {
        let key = ed25519::Keypair::generate();
        let libp2p_keypair = Libp2pKeypair::from(key);
        Ok(Self::new(KeypairOrPublicKey::Keypair(libp2p_keypair)))
    }

    pub async fn as_ssh_private_pem(&self, _comment: &str) -> Result<String> {
        // TODO: Implement SSH PEM conversion
        unimplemented!("SSH PEM conversion not implemented yet")
    }

    pub fn as_ssh_dot_pub(&self, _comment: &str) -> Result<String> {
        // TODO: Implement SSH public key conversion
        unimplemented!("SSH public key conversion not implemented yet")
    }

    pub fn from_ssh_dot_pub(_public_key_str: &str, _key_type: &str) -> Result<Self> {
        // TODO: Implement SSH public key parsing
        unimplemented!("SSH public key parsing not implemented yet")
    }

    fn uint8_array_as_base58_identity(bytes: &[u8]) -> String {
        let mut identity_hash = vec![0x00, bytes.len() as u8];
        identity_hash.extend_from_slice(bytes);
        identity_hash.to_base58()
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        match &self.inner {
            KeypairOrPublicKey::Keypair(k) => k.public().encode_protobuf(),
            KeypairOrPublicKey::PublicKey(pk) => pk.encode_protobuf(),
        }
    }

    pub fn public_key_as_base58_identity(&self) -> String {
        Self::uint8_array_as_base58_identity(&self.public_key_bytes())
    }

    pub fn as_public_key_id(&self) -> String {
        self.public_key_as_base58_identity()
    }

    pub fn as_public_address(&self) -> String {
        self.public_key_as_base58_identity()
    }

    fn uint8_array_as_base64_pad(bytes: &[u8]) -> String {
        base64::encode(bytes)
    }

    pub fn public_key_as_base64_pad(&self) -> String {
        Self::uint8_array_as_base64_pad(&self.public_key_bytes())
    }

    pub fn private_key_as_base64_pad(&self) -> Result<String> {
        match &self.inner {
            KeypairOrPublicKey::Keypair(k) => {
                Ok(Self::uint8_array_as_base64_pad(&k.to_protobuf_encoding()?))
            }
            KeypairOrPublicKey::PublicKey(_) => Err(anyhow!("No private key available")),
        }
    }

    pub fn public_key_to_multiaddr_string(&self) -> String {
        let public_key_id = self.public_key_as_base58_identity();
        format!("/ed25519-pub/{}", public_key_id)
    }

    pub fn as_public_multiaddress(&self) -> String {
        self.public_key_to_multiaddr_string()
    }

    pub fn from_public_key(public_key_id: &str, key_type: &str) -> Result<Self> {
        Self::from_public_multiaddress(&format!("/{}-pub/{}", key_type, public_key_id))
    }

    pub fn from_public_multiaddress(multiaddress: &str) -> Result<Self> {
        let re = Regex::new(r"^(.+)-pub/(.+)$").unwrap();
        let captures = re
            .captures(multiaddress)
            .ok_or_else(|| anyhow!("Invalid multiaddress format"))?;

        // let _key_type = captures.get(1)
        //     .ok_or_else(|| anyhow!("Failed to extract key type"))?
        //     .as_str();
        let peer_id_str = captures
            .get(2)
            .ok_or_else(|| anyhow!("Failed to extract public key ID"))?
            .as_str();

        // Parse the peer ID
        let peer_id = peer_id_str
            .parse::<PeerId>()
            .map_err(|e| anyhow!("Failed to parse peer ID: {:?}", e))?;

        let public_key = libp2p::identity::PublicKey::try_decode_protobuf(&peer_id.to_bytes())
            .map_err(|e| anyhow!("Failed to decode public key from peer ID: {}", e))?;

        Ok(Self::new(KeypairOrPublicKey::PublicKey(public_key)))
    }

    pub fn from_json(json: &KeypairJSON) -> Result<Self> {
        if let Some(private_key) = &json.private_key {
            let key_bytes = base64::decode(private_key)?;
            let key = Libp2pKeypair::from_protobuf_encoding(&key_bytes)?;
            Ok(Self::new(KeypairOrPublicKey::Keypair(key)))
        } else {
            let key_bytes = base64::decode(&json.public_key)?;
            let public_key = Libp2pPublicKey::try_decode_protobuf(&key_bytes)?;
            Ok(Self::new(KeypairOrPublicKey::PublicKey(public_key)))
        }
    }

    pub fn from_json_string(json_str: &str) -> Result<Self> {
        let json: KeypairJSON = serde_json::from_str(json_str)?;
        Self::from_json(&json)
    }

    pub fn from_encrypted_json_file(filepath: &str, password: &str) -> Result<Self> {
        let json_str = fs::read_to_string(filepath)?;
        let json: KeypairJSON = serde_json::from_str(&json_str)?;

        println!("keypair json: {}", json_str);

        if let Some(encrypted_key) = json.encrypted_private_key() {
            let decrypted_key = EncryptedText::decrypt(encrypted_key, password).ok();
            let decrypted_json = KeypairJSON {
                id: json.id().to_string(),
                public_key: json.public_key().to_string(),
                private_key: decrypted_key,
                encrypted_private_key: None,
            };
            Self::from_json(&decrypted_json)
        } else {
            Self::from_json(&json)
        }
    }

    pub fn from_json_file(filepath: &str) -> Result<Self> {
        let json_str = fs::read_to_string(filepath)?;
        Self::from_json_string(&json_str)
    }

    pub fn as_public_json(&self) -> Result<KeypairJSON> {
        Ok(KeypairJSON {
            id: self.public_key_as_base58_identity(),
            public_key: self.public_key_as_base64_pad(),
            private_key: None,
            encrypted_private_key: None,
        })
    }

    pub fn as_public_json_string(&self) -> Result<String> {
        let json = self.as_public_json()?;
        Ok(serde_json::to_string(&json)?)
    }

    pub fn as_public_json_file(&self, path: &str) -> Result<()> {
        let json_string = self.as_public_json_string()?;
        fs::write(path, json_string)?;
        Ok(())
    }

    pub fn as_json(&self) -> Result<KeypairJSON> {
        let private_key = self.private_key_as_base64_pad().ok();
        let encrypted_private_key = if private_key.is_some() {
            None
        } else {
            Some("".to_string()) // Use actual encrypted_private_key if available
        };

        Ok(KeypairJSON {
            id: self.public_key_as_base58_identity(),
            public_key: self.public_key_as_base64_pad(),
            private_key,
            encrypted_private_key,
        })
    }

    pub fn as_json_string(&self) -> Result<String> {
        let json = self.as_json()?;
        Ok(serde_json::to_string(&json)?)
    }

    pub fn as_json_file(&self, path: &str) -> Result<()> {
        let json_string = self.as_json_string()?;
        fs::write(path, json_string)?;
        Ok(())
    }

    pub fn as_encrypted_json(&self, password: &str) -> Result<KeypairJSON> {
        let enc_pk = EncryptedText::encrypt(&self.private_key_as_base64_pad()?, password).ok();
        Ok(KeypairJSON {
            id: self.public_key_as_base58_identity(),
            public_key: self.public_key_as_base64_pad(),
            private_key: None,
            encrypted_private_key: enc_pk,
        })
    }

    pub fn as_encrypted_json_string(&self, password: &str) -> Result<String> {
        let json = self.as_encrypted_json(password)?;
        Ok(serde_json::to_string(&json)?)
    }

    pub fn as_encrypted_json_file(&self, path: &str, password: &str) -> Result<()> {
        let json_string = self.as_encrypted_json_string(password)?;
        fs::write(path, json_string)?;
        Ok(())
    }

    pub fn sign_bytes(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        match &self.inner {
            KeypairOrPublicKey::Keypair(k) => Ok(k.sign(bytes)?),
            KeypairOrPublicKey::PublicKey(_) => Err(anyhow!("Cannot sign with public key only")),
        }
    }

    pub fn sign_string(&self, s: &str) -> Result<Vec<u8>> {
        self.sign_bytes(s.as_bytes())
    }

    pub fn sign_string_as_base64_pad(&self, s: &str) -> Result<String> {
        let signature = self.sign_string(s)?;
        Ok(base64::encode(signature))
    }

    pub fn sign_json(&self, json: &Value) -> Result<String> {
        let str = stringify_deterministic(json, None);
        self.sign_string_as_base64_pad(&str)
    }

    pub fn sign_json_element(&self, json: &mut Value, name: &str, suffix: &str) -> Result<()> {
        let signature = self.sign_json(&json[name])?;
        json[format!("{}{}", name, suffix)] = Value::String(signature);
        Ok(())
    }

    pub fn sign_json_as_key(&self, json: &mut Value, key: &str) -> Result<()> {
        let signature = self.sign_json(json)?;
        json[key] = Value::String(signature);
        Ok(())
    }

    pub fn verify_signature_for_bytes(&self, signature: &str, bytes: &[u8]) -> Result<bool> {
        let signature_bytes = base64::decode(signature)?;
        match &self.inner {
            KeypairOrPublicKey::Keypair(k) => Ok(k.public().verify(bytes, &signature_bytes)),
            KeypairOrPublicKey::PublicKey(pk) => Ok(pk.verify(bytes, &signature_bytes)),
        }
    }

    pub fn verify_signature_for_string(&self, signature: &str, s: &str) -> Result<bool> {
        self.verify_signature_for_bytes(signature, s.as_bytes())
    }

    pub fn verify_json(&self, signature: &str, json: &Value) -> Result<bool> {
        let str = stringify_deterministic(json, None);
        self.verify_signature_for_string(signature, &str)
    }

    pub fn verify_json_with_signature_key(
        &self,
        json: &Value,
        signature_key: &str,
    ) -> Result<bool> {
        if let Value::Object(map) = json {
            let signature = map
                .get(signature_key)
                .ok_or_else(|| anyhow!("Signature key not found"))?
                .as_str()
                .ok_or_else(|| anyhow!("Signature must be a string"))?;

            let mut json_without_signature = json.clone();
            if let Value::Object(map_without_signature) = &mut json_without_signature {
                map_without_signature.remove(signature_key);
            }

            let stringified = stringify_deterministic(&json_without_signature, None);
            self.verify_signature_for_string(signature, &stringified)
        } else {
            Err(anyhow!("Input must be a JSON object"))
        }
    }

    pub fn verify_signatures_in_json(&self, json: &Value, suffix: Option<&str>) -> Result<bool> {
        let suffix = suffix.unwrap_or(".signature");
        let suffix_regex = Regex::new(&format!(r"(.+){}$", regex::escape(suffix)))?;

        if let Value::Object(map) = json {
            for (key, value) in map {
                if let Some(captures) = suffix_regex.captures(key) {
                    let original_key = captures.get(1).unwrap().as_str();
                    if let Some(original_value) = map.get(original_key) {
                        let signature = value
                            .as_str()
                            .ok_or_else(|| anyhow!("Signature must be a string"))?;
                        let stringified = stringify_deterministic(original_value, None);

                        if !self.verify_signature_for_string(signature, &stringified)? {
                            return Ok(false);
                        }
                    } else {
                        return Ok(false); // Original value not found
                    }
                }
            }
            Ok(true) // All signatures verified successfully
        } else {
            Err(anyhow!("Input must be a JSON object"))
        }
    }
}
