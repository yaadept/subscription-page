//! Session cookie: a short-lived HS256 JWT binding the browser to its (encrypted) subpage config.

use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand::Rng;
use serde::{Deserialize, Serialize};

pub const COOKIE_NAME: &str = "session";
pub const COOKIE_MAX_AGE_SECS: i64 = 1_800; // browser cookie lifetime (30 min)
const JWT_TTL_SECS: i64 = 33 * 60;

const NANOID_ALPHABET: &[u8] = b"useandom-26T198340PX75pxJACKVERYMINDBUSHWOLF_GQZbfghjklqvwyzrict";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    #[serde(rename = "sessionId")]
    pub session_id: String,
    /// Encrypted subpage config UUID.
    pub su: String,
    pub iat: i64,
    pub exp: i64,
}

fn nanoid32() -> String {
    let mut rng = rand::thread_rng();
    (0..32)
        .map(|_| NANOID_ALPHABET[rng.gen_range(0..NANOID_ALPHABET.len())] as char)
        .collect()
}

pub fn now_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

pub fn sign(su: String, secret: &str) -> Result<String, jsonwebtoken::errors::Error> {
    let iat = now_secs();
    let claims = Claims {
        session_id: nanoid32(),
        su,
        iat,
        exp: iat + JWT_TTL_SECS,
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
}

pub fn verify(token: &str, secret: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.leeway = 0;
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map(|d| d.claims)
}

/// Extracts a cookie value from the raw `Cookie` header(s).
pub fn cookie_value<'a>(
    cookie_headers: impl Iterator<Item = &'a str>,
    name: &str,
) -> Option<String> {
    for header in cookie_headers {
        for pair in header.split(';') {
            if let Some((k, v)) = pair.trim().split_once('=') {
                if k == name {
                    return Some(v.trim_matches('"').to_string());
                }
            }
        }
    }
    None
}

pub fn set_cookie_header(token: &str, secure: bool) -> String {
    let expires = chrono::Utc::now() + chrono::Duration::seconds(COOKIE_MAX_AGE_SECS);
    let mut c = format!(
        "{COOKIE_NAME}={token}; Max-Age={COOKIE_MAX_AGE_SECS}; Path=/; Expires={}; HttpOnly",
        expires.format("%a, %d %b %Y %H:%M:%S GMT")
    );
    if secure {
        c.push_str("; Secure");
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let t = sign("enc".into(), "s3cret").unwrap();
        let c = verify(&t, "s3cret").unwrap();
        assert_eq!(c.su, "enc");
        assert_eq!(c.session_id.len(), 32);
        assert_eq!(c.exp - c.iat, JWT_TTL_SECS);
        assert!(verify(&t, "other").is_err());
        assert!(verify("garbage", "s3cret").is_err());
    }

    #[test]
    fn expired_tokens_are_rejected() {
        let claims = Claims {
            session_id: "x".into(),
            su: "y".into(),
            iat: 1,
            exp: 2,
        };
        let t = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(b"k"),
        )
        .unwrap();
        assert!(verify(&t, "k").is_err());
    }

    #[test]
    fn cookie_parsing() {
        let v = cookie_value(["a=1; session=tok; b=2"].into_iter(), "session");
        assert_eq!(v.as_deref(), Some("tok"));
        assert!(cookie_value(["a=1"].into_iter(), "session").is_none());
    }
}
