//! AES-256-GCM helpers used to hide the subpage config UUID inside the session cookie.
//! Wire format (base64url): `iv(12) | tag(16) | ciphertext`.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};

const IV_LEN: usize = 12;
const TAG_LEN: usize = 16;

fn cipher(secret: &str) -> Aes256Gcm {
    let key = Sha256::digest(secret.as_bytes());
    Aes256Gcm::new_from_slice(&key).expect("sha256 digest is a valid AES-256 key")
}

pub fn encrypt_uuid(uuid: &str, secret: &str) -> String {
    let mut iv = [0u8; IV_LEN];
    rand::thread_rng().fill_bytes(&mut iv);

    // aes-gcm returns `ciphertext | tag`
    let sealed = cipher(secret)
        .encrypt(
            Nonce::from_slice(&iv),
            Payload {
                msg: uuid.as_bytes(),
                aad: b"",
            },
        )
        .expect("AES-GCM encryption does not fail for in-memory buffers");
    let (ciphertext, tag) = sealed.split_at(sealed.len() - TAG_LEN);

    let mut out = Vec::with_capacity(IV_LEN + TAG_LEN + ciphertext.len());
    out.extend_from_slice(&iv);
    out.extend_from_slice(tag);
    out.extend_from_slice(ciphertext);
    URL_SAFE_NO_PAD.encode(out)
}

pub fn decrypt_uuid(data: &str, secret: &str) -> Option<String> {
    let buf = URL_SAFE_NO_PAD.decode(data).ok()?;
    if buf.len() < IV_LEN + TAG_LEN {
        return None;
    }
    let (iv, rest) = buf.split_at(IV_LEN);
    let (tag, ciphertext) = rest.split_at(TAG_LEN);

    let mut sealed = Vec::with_capacity(ciphertext.len() + TAG_LEN);
    sealed.extend_from_slice(ciphertext);
    sealed.extend_from_slice(tag);

    let plain = cipher(secret)
        .decrypt(
            Nonce::from_slice(iv),
            Payload {
                msg: &sealed,
                aad: b"",
            },
        )
        .ok()?;
    String::from_utf8(plain).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let uuid = "00000000-0000-0000-0000-000000000000";
        let enc = encrypt_uuid(uuid, "secret");
        assert_eq!(decrypt_uuid(&enc, "secret").as_deref(), Some(uuid));
        assert_ne!(encrypt_uuid(uuid, "secret"), enc, "IV must be random");
    }

    #[test]
    fn wrong_key_or_tampering_is_rejected() {
        let enc = encrypt_uuid("abc", "secret");
        assert!(decrypt_uuid(&enc, "other").is_none());
        let mut bytes = URL_SAFE_NO_PAD.decode(&enc).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        assert!(decrypt_uuid(&URL_SAFE_NO_PAD.encode(bytes), "secret").is_none());
        assert!(decrypt_uuid("short", "secret").is_none());
    }
}
