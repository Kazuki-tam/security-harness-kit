use super::kind::Kind;
use super::validate_token_bits;
use crate::suppression::hex_lower;
use anyhow::{Result, anyhow};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2_hmac::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};
use zeroize::Zeroize;

const BASE32: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
const MATERIAL_PREFIX: &str = "v1:";

/// Master secret plus salt for one project.
///
/// Per-kind HKDF outputs are cached after first use so tokenizing a large
/// table costs one HMAC per cell instead of one HKDF extract/expand pair plus
/// one HMAC. Every cached key is zeroized together with the master material.
pub struct KeyMaterial {
    master: [u8; 32],
    salt: [u8; 32],
    kind_keys: Mutex<BTreeMap<String, [u8; 32]>>,
}

impl Clone for KeyMaterial {
    fn clone(&self) -> Self {
        Self::from_parts(self.master, self.salt)
    }
}

impl Drop for KeyMaterial {
    fn drop(&mut self) {
        self.master.zeroize();
        self.salt.zeroize();
        let mut cache = self
            .kind_keys
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        for key in cache.values_mut() {
            key.zeroize();
        }
        cache.clear();
    }
}

impl KeyMaterial {
    pub fn from_parts(master: [u8; 32], salt: [u8; 32]) -> Self {
        Self {
            master,
            salt,
            kind_keys: Mutex::new(BTreeMap::new()),
        }
    }

    /// Generate fresh material from the OS CSPRNG.
    pub fn generate() -> Result<Self> {
        let mut master = [0u8; 32];
        let mut salt = [0u8; 32];
        getrandom::getrandom(&mut master).map_err(|err| anyhow!("CSPRNG failed: {err}"))?;
        getrandom::getrandom(&mut salt).map_err(|err| anyhow!("CSPRNG failed: {err}"))?;
        Ok(Self::from_parts(master, salt))
    }

    fn kind_key(&self, kind: &Kind) -> Result<[u8; 32]> {
        let info = kind.hkdf_info();
        let mut cache = self
            .kind_keys
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(key) = cache.get(&info) {
            return Ok(*key);
        }
        let key = derive_info_key(self, &info)?;
        cache.insert(info, key);
        Ok(key)
    }

    pub fn encode_store(&self) -> String {
        format!(
            "{MATERIAL_PREFIX}{}:{}",
            hex_lower(&self.master),
            hex_lower(&self.salt)
        )
    }

    pub fn fingerprint(&self) -> String {
        fingerprint(self)
    }
}

pub fn parse_stored_material(raw: &str) -> Result<KeyMaterial> {
    let body = raw
        .strip_prefix(MATERIAL_PREFIX)
        .ok_or_else(|| anyhow!("unrecognized pseudonymize material format"))?;
    let Some((master_hex, salt_hex)) = body.split_once(':') else {
        return Err(anyhow!("unrecognized pseudonymize material format"));
    };
    Ok(KeyMaterial::from_parts(
        decode_hex32(master_hex)?,
        decode_hex32(salt_hex)?,
    ))
}

pub fn fingerprint(material: &KeyMaterial) -> String {
    let mut hasher = Sha256::new();
    hasher.update(material.master);
    hasher.update(material.salt);
    let digest = hasher.finalize();
    hex_lower(&digest[..8])
}

pub fn token(
    material: &KeyMaterial,
    kind: &Kind,
    normalized: &str,
    token_bits: u16,
) -> Result<String> {
    validate_token_bits(token_bits).map_err(|err| anyhow!(err))?;
    let mut derived = material.kind_key(kind)?;
    let take = usize::from(token_bits / 8);
    let mut mac =
        Hmac::<Sha256>::new_from_slice(&derived).map_err(|_| anyhow!("invalid HMAC length"))?;
    derived.zeroize();
    mac.update(normalized.as_bytes());
    let digest = mac.finalize().into_bytes();
    let encoded = encode_base32_nopad(&digest[..take]);
    Ok(format!("{}_{encoded}", kind.token_prefix()))
}

pub(crate) fn derive_info_key(material: &KeyMaterial, info: &str) -> Result<[u8; 32]> {
    let hkdf = Hkdf::<Sha256>::new(Some(&material.salt), &material.master);
    let mut okm = [0u8; 32];
    hkdf.expand(info.as_bytes(), &mut okm)
        .map_err(|_| anyhow!("HKDF expand failed"))?;
    Ok(okm)
}

fn encode_base32_nopad(bytes: &[u8]) -> String {
    let mut bits = 0u16;
    let mut nbits = 0u8;
    let mut out = String::new();
    for &byte in bytes {
        bits = (bits << 8) | u16::from(byte);
        nbits += 8;
        while nbits >= 5 {
            nbits -= 5;
            let idx = ((bits >> nbits) & 31) as usize;
            out.push(BASE32[idx] as char);
        }
    }
    if nbits > 0 {
        let idx = ((bits << (5 - nbits)) & 31) as usize;
        out.push(BASE32[idx] as char);
    }
    out
}

fn decode_hex32(hex: &str) -> Result<[u8; 32]> {
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(anyhow!("invalid hex material"));
    }
    let mut out = [0u8; 32];
    for (idx, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let text = std::str::from_utf8(chunk).map_err(|_| anyhow!("invalid hex material"))?;
        out[idx] = u8::from_str_radix(text, 16).map_err(|_| anyhow!("invalid hex material"))?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> KeyMaterial {
        KeyMaterial::from_parts([0x11; 32], [0x22; 32])
    }

    #[test]
    fn tokens_are_deterministic_and_kind_scoped() {
        let material = sample();
        let email = ["foo", "@", "example.com"].concat();
        let a = token(&material, &Kind::Email, &email, 64).unwrap();
        let b = token(&material, &Kind::Email, &email, 64).unwrap();
        let phone = token(&material, &Kind::Phone, &email, 64).unwrap();
        let custom_a = token(&material, &Kind::Custom("member_id".into()), &email, 64).unwrap();
        let custom_b = token(&material, &Kind::Custom("order_id".into()), &email, 64).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, phone);
        assert_ne!(custom_a, custom_b);
        assert!(a.starts_with("email_"));
        assert!(phone.starts_with("phone_"));
        assert!(custom_a.starts_with("member_id_"));
    }

    #[test]
    fn fingerprint_and_store_round_trip() {
        let material = sample();
        let encoded = material.encode_store();
        let parsed = parse_stored_material(&encoded).unwrap();
        assert_eq!(fingerprint(&material), fingerprint(&parsed));
        assert_eq!(fingerprint(&material).len(), 16);
        assert!(encoded.starts_with("v1:"));
    }

    #[test]
    fn cached_kind_key_matches_fresh_derivation() {
        let material = sample();
        let email = ["foo", "@", "example.com"].concat();
        let first = token(&material, &Kind::Email, &email, 64).unwrap();
        let fresh = token(&material.clone(), &Kind::Email, &email, 64).unwrap();
        assert_eq!(first, fresh);
        assert_eq!(
            material.kind_key(&Kind::Email).unwrap(),
            derive_info_key(&material, &Kind::Email.hkdf_info()).unwrap()
        );
    }

    #[test]
    fn generated_material_is_random() {
        let a = KeyMaterial::generate().unwrap();
        let b = KeyMaterial::generate().unwrap();
        assert_ne!(fingerprint(&a), fingerprint(&b));
    }

    #[test]
    fn rejects_malformed_stored_material() {
        let hex64 = "ab".repeat(32);
        for raw in [
            "v2:x:y",
            "v1:nocolon",
            &format!("v1:{hex64}:{}", &hex64[..62]),
            &format!("v1:{}:{hex64}", "zz".repeat(32)),
        ] {
            assert!(parse_stored_material(raw).is_err(), "{raw}");
        }
        assert!(parse_stored_material(&format!("v1:{hex64}:{hex64}")).is_ok());
    }

    #[test]
    fn token_bits_must_be_valid() {
        let material = sample();
        let email = ["foo", "@", "example.com"].concat();
        assert!(token(&material, &Kind::Email, &email, 60).is_err());
        assert!(token(&material, &Kind::Email, &email, 136).is_err());
        assert!(token(&material, &Kind::Email, &email, 128).is_ok());
    }
}
