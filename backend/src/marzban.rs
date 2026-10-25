//! Legacy Marzban subscription link support: decodes a Marzban token into a username and
//! resolves it to a Remnawave short UUID.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, NaiveDate, NaiveDateTime, TimeZone, Utc};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::panel::PanelClient;

#[derive(Debug, PartialEq, Eq)]
pub enum Resolution {
    /// Not a Marzban link (or feature off): use the path value as-is.
    PassThrough,
    Resolved(String),
    Drop,
}

pub struct MarzbanResolver {
    panel: PanelClient,
    secret_keys: Vec<String>,
    valid_from: Option<DateTime<Utc>>,
    drop_revoked: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Decoded {
    pub username: String,
    pub created_at: Option<DateTime<Utc>>,
}

#[derive(Deserialize)]
struct JwtPayload {
    sub: Option<String>,
    access: Option<String>,
    iat: Option<i64>,
}

impl MarzbanResolver {
    pub fn new(
        panel: PanelClient,
        secret_keys: Vec<String>,
        valid_from: Option<&str>,
        drop_revoked: bool,
    ) -> Self {
        Self {
            panel,
            secret_keys,
            valid_from: valid_from.and_then(parse_js_date),
            drop_revoked,
        }
    }

    pub async fn resolve_short_uuid(&self, marzban_link: &str, client_ip: &str) -> Resolution {
        let Some(decoded) = self.try_decode(marzban_link) else {
            return Resolution::PassThrough;
        };

        let sanitized = sanitize_username(&decoded.username);
        tracing::info!(
            "Decoded Marzban username: {:?}, sanitized username: {sanitized}",
            decoded.username
        );

        match self.panel.get_user_by_username(client_ip, &sanitized).await {
            Err(e) => {
                tracing::error!(
                    "Decoded Marzban username is not found in Remnawave, decoded username: {sanitized} ({e})"
                );
                Resolution::Drop
            }
            Ok(user) if self.drop_revoked && user.sub_revoked => Resolution::Drop,
            Ok(user) => Resolution::Resolved(user.short_uuid),
        }
    }

    pub fn try_decode(&self, link: &str) -> Option<Decoded> {
        if self.secret_keys.is_empty() {
            return None;
        }
        if link.chars().count() < 10 {
            tracing::debug!("Marzban token too short");
            return None;
        }
        for key in &self.secret_keys {
            if let Some(d) = self.decode_with_key(link, key) {
                return Some(d);
            }
        }
        tracing::debug!("Decoding Marzban link failed with all keys");
        None
    }

    fn decode_with_key(&self, token: &str, secret: &str) -> Option<Decoded> {
        if token.split('.').count() == 3 {
            match self.decode_jwt(token, secret) {
                Ok(Some(d)) => return Some(d),
                Ok(None) => return None,
                Err(e) => tracing::debug!("JWT verification failed: {e}"),
            }
        }

        // Legacy format: base64url(`username,created_at`) + 10-char signature.
        let chars: Vec<char> = token.chars().collect();
        let split = chars.len() - 10;
        let u_token: String = chars[..split].iter().collect();
        let u_signature: String = chars[split..].iter().collect();

        let decoded = String::from_utf8_lossy(&lenient_base64url_decode(&u_token)).into_owned();

        let mut hasher = Sha256::new();
        hasher.update(u_token.as_bytes());
        hasher.update(secret.as_bytes());
        let expected: String = URL_SAFE_NO_PAD
            .encode(hasher.finalize())
            .chars()
            .take(10)
            .collect();

        if !constant_time_eq(u_signature.as_bytes(), expected.as_bytes()) {
            tracing::debug!("Marzban signature mismatch");
            return None;
        }

        let mut parts = decoded.split(',');
        let username = parts.next()?;
        let created_at_raw = parts.next()?;
        let created_at_secs = js_parse_int(created_at_raw)?;
        let created_at = Utc.timestamp_opt(created_at_secs, 0).single();

        if !self.check_validity(created_at, username) {
            return None;
        }
        Some(Decoded {
            username: username.to_string(),
            created_at,
        })
    }

    fn decode_jwt(&self, token: &str, secret: &str) -> Result<Option<Decoded>, String> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.required_spec_claims.clear();
        validation.leeway = 0;
        let payload = decode::<JwtPayload>(
            token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &validation,
        )
        .map_err(|e| e.to_string())?
        .claims;

        if payload.access.as_deref() != Some("subscription") {
            return Err("JWT access field is not subscription".into());
        }
        let username = payload.sub.ok_or("JWT has no sub")?;
        let created_at = payload
            .iat
            .and_then(|iat| Utc.timestamp_opt(iat, 0).single());

        if !self.check_validity(created_at, &username) {
            return Ok(None);
        }
        Ok(Some(Decoded {
            username,
            created_at,
        }))
    }

    fn check_validity(&self, created_at: Option<DateTime<Utc>>, username: &str) -> bool {
        let (Some(valid_from), Some(created_at)) = (self.valid_from, created_at) else {
            return true;
        };
        if created_at < valid_from {
            tracing::warn!(
                "{{\"username\":\"{username}\",\"createdAt\":\"{}\"}} – subscription createdAt is before validFrom",
                created_at.to_rfc3339()
            );
            return false;
        }
        true
    }
}

/// Port of `sanitizeUsername`: invalid characters become `_`, minimum length is 6.
pub fn sanitize_username(username: &str) -> String {
    let mut out: String = username
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    while out.len() < 6 {
        out.push('_');
    }
    out
}

/// Node's `Buffer.from(s, 'base64url')`: skips invalid characters, accepts both alphabets,
/// ignores padding and a dangling sextet.
fn lenient_base64url_decode(s: &str) -> Vec<u8> {
    let mut acc: u32 = 0;
    let mut bits = 0;
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    for c in s.chars() {
        let v = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32 + 26,
            '0'..='9' => c as u32 - '0' as u32 + 52,
            '-' | '+' => 62,
            '_' | '/' => 63,
            _ => continue,
        };
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    out
}

/// `parseInt(s, 10)`: leading whitespace, optional sign, then digits (trailing junk ignored).
fn js_parse_int(s: &str) -> Option<i64> {
    let s = s.trim_start();
    let (neg, rest) = match s.as_bytes().first()? {
        b'-' => (true, &s[1..]),
        b'+' => (false, &s[1..]),
        _ => (false, s),
    };
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        return None;
    }
    let n: i64 = digits.parse().ok()?;
    Some(if neg { -n } else { n })
}

/// `new Date(str)` for the formats an operator would realistically write; an unparsable value
/// means "no restriction" (comparisons against an Invalid Date are always false in JS).
fn parse_js_date(s: &str) -> Option<DateTime<Utc>> {
    let s = s.trim();
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }
    for fmt in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%d %H:%M:%S%.f"] {
        if let Ok(dt) = NaiveDateTime::parse_from_str(s, fmt) {
            return Some(Utc.from_utc_datetime(&dt));
        }
    }
    NaiveDate::parse_from_str(s, "%Y-%m-%d")
        .ok()
        .and_then(|d| d.and_hms_opt(0, 0, 0))
        .map(|dt| Utc.from_utc_datetime(&dt))
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use std::collections::HashMap;

    fn resolver(keys: &[&str], valid_from: Option<&str>) -> MarzbanResolver {
        let env: HashMap<String, String> = [
            ("REMNAWAVE_PANEL_URL", "http://127.0.0.1:1"),
            ("REMNAWAVE_API_TOKEN", "t"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let cfg = Config::from_map(&env).unwrap();
        MarzbanResolver::new(
            PanelClient::new(&cfg).unwrap(),
            keys.iter().map(|k| k.to_string()).collect(),
            valid_from,
            false,
        )
    }

    fn legacy_token(username: &str, created_at: i64, key: &str) -> String {
        let u = URL_SAFE_NO_PAD.encode(format!("{username},{created_at}"));
        let mut h = Sha256::new();
        h.update(u.as_bytes());
        h.update(key.as_bytes());
        let sig: String = URL_SAFE_NO_PAD
            .encode(h.finalize())
            .chars()
            .take(10)
            .collect();
        format!("{u}{sig}")
    }

    #[tokio::test]
    async fn decodes_legacy_token() {
        let r = resolver(&["k1", "k2"], None);
        let d = r
            .try_decode(&legacy_token("alice", 1_700_000_000, "k2"))
            .unwrap();
        assert_eq!(d.username, "alice");
        assert_eq!(d.created_at.unwrap().timestamp(), 1_700_000_000);
        assert!(r
            .try_decode(&legacy_token("alice", 1_700_000_000, "bad"))
            .is_none());
    }

    #[tokio::test]
    async fn decodes_jwt_token() {
        #[derive(serde::Serialize)]
        struct C {
            sub: &'static str,
            access: &'static str,
            iat: i64,
        }
        let tok = encode(
            &Header::new(Algorithm::HS256),
            &C {
                sub: "bob",
                access: "subscription",
                iat: 1_700_000_000,
            },
            &EncodingKey::from_secret(b"k1"),
        )
        .unwrap();
        let r = resolver(&["k1"], None);
        assert_eq!(r.try_decode(&tok).unwrap().username, "bob");

        let wrong = encode(
            &Header::new(Algorithm::HS256),
            &C {
                sub: "bob",
                access: "other",
                iat: 1,
            },
            &EncodingKey::from_secret(b"k1"),
        )
        .unwrap();
        assert!(r.try_decode(&wrong).is_none());
    }

    #[tokio::test]
    async fn valid_from_rejects_old_links() {
        let r = resolver(&["k"], Some("2025-01-17T15:38:45.065Z"));
        assert!(r
            .try_decode(&legacy_token("alice", 1_700_000_000, "k"))
            .is_none());
        assert!(r
            .try_decode(&legacy_token("alice", 1_800_000_000, "k"))
            .is_some());
        // Unparsable boundary behaves like "not set" (as Invalid Date does in JS).
        let r = resolver(&["k"], Some("not a date"));
        assert!(r.try_decode(&legacy_token("alice", 1, "k")).is_some());
    }

    #[test]
    fn helpers() {
        assert_eq!(sanitize_username("ab"), "ab____");
        assert_eq!(sanitize_username("a.b@é-9"), "a_b__-9");
        assert_eq!(js_parse_int(" 12abc"), Some(12));
        assert_eq!(js_parse_int("x1"), None);
        assert_eq!(lenient_base64url_decode("YWxpY2U"), b"alice");
        assert_eq!(lenient_base64url_decode("YWxpY2U="), b"alice");
    }
}
