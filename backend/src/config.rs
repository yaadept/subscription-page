//! Environment configuration (replacement for the zod `configSchema`).

use std::collections::HashMap;
use std::path::PathBuf;

use rand::RngCore;

use crate::constants::SUBPAGE_DEFAULT_CONFIG_UUID;
use crate::trust_proxy::TrustProxy;

const API_TOKEN_MESSAGE: &str = "Remnawave Dashboard → Remnawave Settings → API Tokens. Create a new API Token and set it in the .env file.";

#[derive(Debug, Clone)]
pub struct Config {
    pub app_port: u16,
    pub panel_url: String,
    pub api_token: String,
    pub subpage_config_uuid: String,
    pub custom_sub_prefix: Option<String>,
    pub trust_proxy: TrustProxy,
    pub caddy_auth_api_token: Option<String>,
    pub cloudflare_client_id: Option<String>,
    pub cloudflare_client_secret: Option<String>,
    pub marzban_enabled: bool,
    pub marzban_secret_keys: Vec<String>,
    pub marzban_valid_from: Option<String>,
    pub marzban_drop_revoked: bool,
    pub internal_jwt_secret: String,
    pub egames_cookie: Option<String>,
    pub development: bool,
    pub debug_logs: bool,
    pub frontend_dir: PathBuf,
}

impl Config {
    pub fn from_process_env() -> Result<Self, String> {
        let vars: HashMap<String, String> = std::env::vars().collect();
        Self::from_map(&vars)
    }

    /// Mirrors the zod schema: collects every problem and reports them together.
    pub fn from_map(env: &HashMap<String, String>) -> Result<Self, String> {
        let mut errors: Vec<String> = Vec::new();

        // Empty strings behave like unset variables (as in the .env.sample defaults).
        let get = |key: &str| env.get(key).map(|v| v.as_str()).filter(|v| !v.is_empty());
        let get_owned = |key: &str| get(key).map(str::to_owned);

        let mut boolean = |key: &str| -> bool {
            match get(key) {
                None | Some("false") => false,
                Some("true") => true,
                Some(_) => {
                    errors.push(format!("{key}: Must be \"true\" or \"false\"."));
                    false
                }
            }
        };
        let marzban_enabled = boolean("MARZBAN_LEGACY_LINK_ENABLED");
        let marzban_drop_revoked = boolean("MARZBAN_LEGACY_DROP_REVOKED_SUBSCRIPTIONS");

        let app_port = match get("APP_PORT") {
            None => 3010,
            Some(p) => p.trim().parse::<u16>().unwrap_or_else(|_| {
                errors.push(format!("APP_PORT: '{p}' is not a valid port"));
                3010
            }),
        };

        let panel_url = get_owned("REMNAWAVE_PANEL_URL").unwrap_or_else(|| {
            errors.push("REMNAWAVE_PANEL_URL: Required".into());
            String::new()
        });
        if !panel_url.is_empty()
            && !panel_url.starts_with("http://")
            && !panel_url.starts_with("https://")
        {
            errors.push(
                "REMNAWAVE_PANEL_URL: REMNAWAVE_PANEL_URL must start with http:// or https://"
                    .into(),
            );
        }

        let api_token = get_owned("REMNAWAVE_API_TOKEN").unwrap_or_else(|| {
            errors.push(format!("REMNAWAVE_API_TOKEN: {API_TOKEN_MESSAGE}"));
            String::new()
        });

        let trust_proxy = match TrustProxy::parse(get("TRUST_PROXY").unwrap_or("1")) {
            Ok(tp) => tp,
            Err(e) => {
                errors.push(format!(
                    "TRUST_PROXY: must be \"true\"/\"false\", a non-negative integer (number of trusted \
                     reverse-proxy hops), or a comma-separated list of preset names \
                     (loopback, linklocal, uniquelocal) and/or IP addresses / CIDR subnets ({e})."
                ));
                TrustProxy::None
            }
        };

        let marzban_secret_keys: Vec<String> = get("MARZBAN_LEGACY_SECRET_KEY")
            .map(|v| v.split(',').map(|k| k.trim().to_string()).collect())
            .unwrap_or_default();
        if marzban_enabled && marzban_secret_keys.is_empty() {
            errors.push(
                "MARZBAN_LEGACY_SECRET_KEY is required when MARZBAN_LEGACY_LINK_ENABLED is true"
                    .into(),
            );
        }

        let development = env.get("NODE_ENV").map(String::as_str) == Some("development");
        let debug_logs = env.get("ENABLE_DEBUG_LOGS").map(String::as_str) == Some("true");

        // The Node version generated this in docker-entrypoint.sh; we do it in-process.
        let internal_jwt_secret = get_owned("INTERNAL_JWT_SECRET").unwrap_or_else(|| {
            let mut bytes = [0u8; 64];
            rand::thread_rng().fill_bytes(&mut bytes);
            bytes.iter().map(|b| format!("{b:02x}")).collect()
        });

        let frontend_dir = get_owned("FRONTEND_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                if development {
                    std::env::current_dir()
                        .unwrap_or_default()
                        .join("dev_frontend")
                } else {
                    PathBuf::from("/opt/app/frontend")
                }
            });

        if !errors.is_empty() {
            let formatted = errors
                .iter()
                .map(|e| format!("❌ {e}"))
                .collect::<Vec<_>>()
                .join("\n");
            return Err(format!(
                "\n🔧 Environment Configuration Errors:\n{formatted}\n\nPlease fix your .env file and restart the application."
            ));
        }

        Ok(Self {
            app_port,
            panel_url,
            api_token,
            subpage_config_uuid: get_owned("SUBPAGE_CONFIG_UUID")
                .unwrap_or_else(|| SUBPAGE_DEFAULT_CONFIG_UUID.to_string()),
            custom_sub_prefix: get_owned("CUSTOM_SUB_PREFIX"),
            trust_proxy,
            caddy_auth_api_token: get_owned("CADDY_AUTH_API_TOKEN"),
            cloudflare_client_id: get_owned("CLOUDFLARE_ZERO_TRUST_CLIENT_ID"),
            cloudflare_client_secret: get_owned("CLOUDFLARE_ZERO_TRUST_CLIENT_SECRET"),
            marzban_enabled,
            marzban_secret_keys,
            marzban_valid_from: get_owned("MARZBAN_LEGACY_SUBSCRIPTION_VALID_FROM"),
            marzban_drop_revoked,
            internal_jwt_secret,
            egames_cookie: get_owned("EGAMES_COOKIE"),
            development,
            debug_logs,
            frontend_dir,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn minimal_config_gets_defaults() {
        let c = Config::from_map(&env(&[
            ("REMNAWAVE_PANEL_URL", "https://panel.example.com"),
            ("REMNAWAVE_API_TOKEN", "t"),
            ("CUSTOM_SUB_PREFIX", ""),
            ("TRUST_PROXY", ""),
        ]))
        .unwrap();
        assert_eq!(c.app_port, 3010);
        assert!(c.custom_sub_prefix.is_none());
        assert!(matches!(c.trust_proxy, TrustProxy::Hops(1)));
        assert_eq!(c.subpage_config_uuid, SUBPAGE_DEFAULT_CONFIG_UUID);
        assert_eq!(c.internal_jwt_secret.len(), 128);
    }

    #[test]
    fn reports_all_problems_at_once() {
        let err = Config::from_map(&env(&[
            ("REMNAWAVE_PANEL_URL", "panel.local"),
            ("MARZBAN_LEGACY_LINK_ENABLED", "true"),
            ("TRUST_PROXY", "wat"),
        ]))
        .unwrap_err();
        assert!(err.contains("REMNAWAVE_PANEL_URL must start with http"));
        assert!(err.contains("REMNAWAVE_API_TOKEN"));
        assert!(err.contains("MARZBAN_LEGACY_SECRET_KEY is required"));
        assert!(err.contains("TRUST_PROXY"));
    }
}
