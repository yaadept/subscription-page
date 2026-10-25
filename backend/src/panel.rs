//! HTTP client for the Remnawave panel API (replacement for `AxiosService`).

use std::time::Duration;

use bytes::Bytes;
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::{redirect, Method, StatusCode};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::config::Config;
use crate::constants::{is_ignored_header, REAL_IP_HEADER, SUBPAGE_VERSION_HEADER, VERSION};

/// `encodeURIComponent`: everything except `A-Za-z0-9 - _ . ! ~ * ' ( )` is escaped.
const URI_COMPONENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'!')
    .remove(b'~')
    .remove(b'*')
    .remove(b'\'')
    .remove(b'(')
    .remove(b')');

pub fn encode_component(s: &str) -> String {
    utf8_percent_encode(s, URI_COMPONENT).to_string()
}

#[derive(Debug, thiserror::Error)]
pub enum PanelError {
    #[error("{0}")]
    Request(String),
    #[error("panel responded with {0}")]
    Status(StatusCode),
    #[error("unexpected panel response: {0}")]
    Shape(&'static str),
}

impl PanelError {
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::Status(StatusCode::NOT_FOUND))
    }
}

impl From<reqwest::Error> for PanelError {
    fn from(e: reqwest::Error) -> Self {
        // Do not leak the (possibly credential-bearing) URL into logs.
        Self::Request(e.without_url().to_string())
    }
}

#[derive(Debug, Clone)]
pub struct PanelUser {
    pub short_uuid: String,
    pub sub_revoked: bool,
}

#[derive(Debug, Clone)]
pub struct SubpageConfigRef {
    pub subpage_config_uuid: Option<String>,
    pub webpage_allowed: bool,
}

pub struct SubscriptionResponse {
    pub body: Bytes,
    pub headers: HeaderMap,
}

#[derive(Clone)]
pub struct PanelClient {
    http: reqwest::Client,
    base_url: String,
    /// Headers every request to the panel carries (token, Caddy/Cloudflare auth, ...).
    defaults: HeaderMap,
}

fn header_value(v: &str) -> Result<HeaderValue, PanelError> {
    HeaderValue::from_str(v).map_err(|_| PanelError::Request("invalid header value".into()))
}

impl PanelClient {
    pub fn new(config: &Config) -> Result<Self, String> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(redirect::Policy::limited(5))
            .build()
            .map_err(|e| e.to_string())?;

        let mut defaults = HeaderMap::new();
        let mut put = |name: &'static str, value: &str| -> Result<(), String> {
            let v =
                HeaderValue::from_str(value).map_err(|_| format!("invalid value for {name}"))?;
            defaults.insert(HeaderName::from_static(name), v);
            Ok(())
        };

        put("user-agent", "Remnawave Subscription Page")?;
        put(SUBPAGE_VERSION_HEADER, VERSION)?;
        put("authorization", &format!("Bearer {}", config.api_token))?;
        if let Some(token) = &config.caddy_auth_api_token {
            put("x-api-key", token)?;
        }
        if let (Some(id), Some(secret)) = (
            &config.cloudflare_client_id,
            &config.cloudflare_client_secret,
        ) {
            put("cf-access-client-id", id)?;
            put("cf-access-client-secret", secret)?;
        }
        if config.panel_url.starts_with("http://") {
            put("x-forwarded-for", "127.0.0.1")?;
            put("x-forwarded-proto", "https")?;
        }
        if let Some(cookie) = &config.egames_cookie {
            put("cookie", cookie)?;
        }

        Ok(Self {
            http,
            base_url: config.panel_url.trim_end_matches('/').to_string(),
            defaults,
        })
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    fn request(&self, method: Method, path: &str) -> reqwest::RequestBuilder {
        let url = format!("{}/{}", self.base_url, path.trim_start_matches('/'));
        self.http
            .request(method, url)
            .headers(self.defaults.clone())
    }

    async fn get_json(&self, rb: reqwest::RequestBuilder) -> Result<Value, PanelError> {
        let resp = rb.send().await?;
        let status = resp.status();
        if !status.is_success() {
            return Err(PanelError::Status(status));
        }
        Ok(resp.json::<Value>().await?)
    }

    pub async fn get_metadata_version(&self) -> Result<String, PanelError> {
        let v = self
            .get_json(self.request(Method::GET, "/api/system/metadata"))
            .await?;
        v.pointer("/response/version")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or(PanelError::Shape("metadata.response.version"))
    }

    pub async fn get_user_by_username(
        &self,
        client_ip: &str,
        username: &str,
    ) -> Result<PanelUser, PanelError> {
        let path = format!("/api/users/by-username/{}", encode_component(username));
        let rb = self
            .request(Method::GET, &path)
            .header(REAL_IP_HEADER, header_value(client_ip)?);
        let v = self.get_json(rb).await?;

        let user = v
            .get("response")
            .ok_or(PanelError::Shape("user.response"))?;
        let short_uuid = user
            .get("shortUuid")
            .and_then(Value::as_str)
            .ok_or(PanelError::Shape("user.shortUuid"))?
            .to_owned();
        // `subRevokedAt !== null` in the original: a missing field counts as revoked too.
        let sub_revoked = !matches!(user.get("subRevokedAt"), Some(Value::Null));
        Ok(PanelUser {
            short_uuid,
            sub_revoked,
        })
    }

    pub async fn get_subpage_config_by_uuid(&self, uuid: &str) -> Result<Value, PanelError> {
        let path = format!("/api/subscription-page-configs/{}", encode_component(uuid));
        let v = self.get_json(self.request(Method::GET, &path)).await?;
        v.pointer("/response/config")
            .cloned()
            .ok_or(PanelError::Shape("subpage config.response.config"))
    }

    pub async fn get_subpage_config_uuids(&self) -> Result<Vec<String>, PanelError> {
        let v = self
            .get_json(self.request(Method::GET, "/api/subscription-page-configs"))
            .await?;
        v.pointer("/response/configs")
            .and_then(Value::as_array)
            .ok_or(PanelError::Shape("subpage configs.response.configs"))?
            .iter()
            .map(|c| {
                c.get("uuid")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .ok_or(PanelError::Shape("subpage config.uuid"))
            })
            .collect()
    }

    /// Returns the panel's JSON body untouched (`{ "response": { isFound, user, links, ... } }`).
    pub async fn get_subscription_info(
        &self,
        client_ip: &str,
        short_uuid: &str,
    ) -> Result<Value, PanelError> {
        let path = format!("/api/sub/{}/info", encode_component(short_uuid));
        let rb = self
            .request(Method::GET, &path)
            .header(REAL_IP_HEADER, header_value(client_ip)?);
        self.get_json(rb).await
    }

    pub async fn get_subpage_config(
        &self,
        short_uuid: &str,
        request_headers: &HeaderMap,
    ) -> Result<SubpageConfigRef, PanelError> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Inner {
            subpage_config_uuid: Option<String>,
            webpage_allowed: Option<bool>,
        }
        #[derive(Deserialize)]
        struct Outer {
            response: Inner,
        }

        let mut headers = serde_json::Map::new();
        for name in request_headers.keys() {
            let joined = request_headers
                .get_all(name)
                .iter()
                .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
                .collect::<Vec<_>>()
                .join(", ");
            headers.insert(name.as_str().to_owned(), Value::String(joined));
        }

        let path = format!(
            "/api/subscriptions/subpage-config/{}",
            encode_component(short_uuid)
        );
        let rb = self
            .request(Method::GET, &path)
            .json(&json!({ "requestHeaders": headers }));
        let v = self.get_json(rb).await?;
        let outer: Outer =
            serde_json::from_value(v).map_err(|_| PanelError::Shape("subpage-config response"))?;
        Ok(SubpageConfigRef {
            subpage_config_uuid: outer.response.subpage_config_uuid,
            // `webpageAllowed === false` is the only value that blocks the page.
            webpage_allowed: outer.response.webpage_allowed != Some(false),
        })
    }

    /// Proxies the raw subscription. `client_headers` must already be filtered.
    pub async fn get_subscription(
        &self,
        client_ip: &str,
        short_uuid: &str,
        client_headers: &HeaderMap,
        client_type: Option<&str>,
    ) -> Result<SubscriptionResponse, PanelError> {
        let mut path = format!("/api/sub/{}", encode_component(short_uuid));
        if let Some(ct) = client_type {
            path.push('/');
            path.push_str(&encode_component(ct));
        }

        // The panel token must not be sent on this public endpoint.
        let mut headers = self.defaults.clone();
        headers.remove("authorization");
        for (name, value) in client_headers {
            headers.insert(name.clone(), value.clone());
        }
        headers.insert("accept", HeaderValue::from_static("*/*"));
        headers.insert(
            "cache-control",
            HeaderValue::from_static("no-cache, no-store, must-revalidate, private, max-age=0"),
        );
        headers.insert("pragma", HeaderValue::from_static("no-cache"));
        headers.insert("expires", HeaderValue::from_static("0"));
        headers.insert(REAL_IP_HEADER, header_value(client_ip)?);

        let url = format!("{}{}", self.base_url, path);
        let resp = self.http.get(url).headers(headers).send().await?;
        let status = resp.status();
        if !status.is_success() {
            return Err(PanelError::Status(status));
        }

        let mut out = HeaderMap::new();
        for (name, value) in resp.headers() {
            if !is_ignored_header(name.as_str()) {
                out.append(name.clone(), value.clone());
            }
        }
        let body = resp.bytes().await?;
        Ok(SubscriptionResponse { body, headers: out })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_component_matches_js() {
        assert_eq!(encode_component("abc-DEF_1.~!*'()"), "abc-DEF_1.~!*'()");
        assert_eq!(encode_component("a b/c?d"), "a%20b%2Fc%3Fd");
        assert_eq!(encode_component("юзер"), "%D1%8E%D0%B7%D0%B5%D1%80");
    }
}
