//! Subpage config store and the HTML page rendering (replacement for `WebpageService`).

use std::collections::HashMap;
use std::path::Path;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use regex::{Captures, Regex};
use serde_json::{json, Map, Value};

use crate::constants::SUBPAGE_DEFAULT_CONFIG_UUID;
use crate::crypto::{decrypt_uuid, encrypt_uuid};
use crate::panel::PanelClient;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseSettings {
    pub meta_title: String,
    pub meta_description: String,
    pub show_connection_keys: bool,
    pub hide_get_link_button: bool,
}

impl BaseSettings {
    fn fallback() -> Self {
        Self {
            meta_title: "Subscription Page".into(),
            meta_description: "Subscription Page".into(),
            show_connection_keys: false,
            hide_get_link_button: false,
        }
    }
}

struct StoredConfig {
    /// Config as served to the SPA (unknown top-level keys stripped, `baseSettings` defaulted).
    value: Value,
    base: BaseSettings,
}

pub struct Webpage {
    secret: String,
    configured_uuid: String,
    configs: HashMap<String, StoredConfig>,
    template: Template,
}

/// Top-level keys of `SubscriptionPageRawConfigSchema`; zod strips everything else.
const CONFIG_KEYS: [&str; 8] = [
    "version",
    "locales",
    "brandingSettings",
    "uiConfig",
    "baseSettings",
    "baseTranslations",
    "svgLibrary",
    "platforms",
];

/// Shallow equivalent of `SubscriptionPageRawConfigSchema.safeParse`: the panel validates the
/// full schema when a config is saved, here we only guard what this service depends on and
/// apply the `baseSettings` defaults.
fn parse_config(raw: &Value) -> Result<StoredConfig, String> {
    let obj = raw.as_object().ok_or("config is not an object")?;

    for key in CONFIG_KEYS
        .iter()
        .filter(|k| **k != "baseSettings" && **k != "platforms")
    {
        if !obj.contains_key(*key) {
            return Err(format!("missing required key '{key}'"));
        }
    }
    match obj.get("locales").and_then(Value::as_array) {
        Some(l) if !l.is_empty() => {}
        _ => return Err("locales: at least one locale must be specified".into()),
    }

    let bs_in = match obj.get("baseSettings") {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(m)) => m.clone(),
        Some(_) => return Err("baseSettings: expected object".into()),
    };
    let string_field = |k: &str| -> Result<String, String> {
        match bs_in.get(k) {
            None | Some(Value::Null) => Ok("Subscription".into()),
            Some(Value::String(s)) => Ok(s.clone()),
            Some(_) => Err(format!("baseSettings.{k}: expected string")),
        }
    };
    let bool_field = |k: &str| -> Result<bool, String> {
        match bs_in.get(k) {
            None | Some(Value::Null) => Ok(false),
            Some(Value::Bool(b)) => Ok(*b),
            Some(_) => Err(format!("baseSettings.{k}: expected boolean")),
        }
    };
    let base = BaseSettings {
        meta_title: string_field("metaTitle")?,
        meta_description: string_field("metaDescription")?,
        show_connection_keys: bool_field("showConnectionKeys")?,
        hide_get_link_button: bool_field("hideGetLinkButton")?,
    };

    let mut out = Map::new();
    for key in CONFIG_KEYS {
        if let Some(v) = obj.get(key) {
            out.insert(key.to_string(), v.clone());
        }
    }
    out.insert(
        "baseSettings".into(),
        json!({
            "metaTitle": base.meta_title,
            "metaDescription": base.meta_description,
            "showConnectionKeys": base.show_connection_keys,
            "hideGetLinkButton": base.hide_get_link_button,
        }),
    );

    Ok(StoredConfig {
        value: Value::Object(out),
        base,
    })
}

impl Webpage {
    /// Loads `index.html` and every subpage config from the panel; any problem is fatal.
    pub async fn bootstrap(
        panel: &PanelClient,
        frontend_dir: &Path,
        configured_uuid: String,
        secret: String,
    ) -> Result<Self, String> {
        let index = std::fs::read_to_string(frontend_dir.join("index.html")).map_err(|e| {
            format!(
                "cannot read {}: {e}",
                frontend_dir.join("index.html").display()
            )
        })?;
        let template = Template::compile(&index);

        let uuids = match panel.get_subpage_config_uuids().await {
            Ok(u) => u,
            Err(e) => {
                if e.is_not_found() {
                    tracing::error!("Request failed with 404 status code.");
                    tracing::error!(
                        "This version of Subscription Page requires Remnawave Panel version >=2.4.0. Please upgrade Remnawave Panel to the latest version or downgrade Subscription Page."
                    );
                } else {
                    tracing::error!("Subpage Config List Request failed: {e}");
                }
                tracing::error!("Subscription page config list cannot be fetched");
                Vec::new()
            }
        };
        if uuids.is_empty() {
            return Err("[FATAL] Subscription page config list is empty, exiting...".into());
        }
        tracing::info!("Found {} subscription page configs.", uuids.len());

        let mut configs = HashMap::new();
        for uuid in uuids {
            let raw = panel.get_subpage_config_by_uuid(&uuid).await.map_err(|e| {
                format!(
                    "[FATAL] Error while fetching one of subpage config: {uuid} ({e}), exiting..."
                )
            })?;
            let parsed =
                parse_config(&raw).map_err(|e| format!("[FATAL] {uuid} is not valid: {e}"))?;
            tracing::info!("[OK] {uuid}");
            configs.insert(uuid, parsed);
        }
        if configs.is_empty() {
            return Err("[FAILED] At least one SubPage config must be valid!".into());
        }
        tracing::info!("[OK] Subpage configs are loaded successfully.");

        Ok(Self {
            secret,
            configured_uuid,
            configs,
            template,
        })
    }

    #[cfg(test)]
    pub fn for_tests(
        index_html: &str,
        secret: &str,
        configured_uuid: &str,
        configs: &[(&str, Value)],
    ) -> Self {
        Self {
            secret: secret.into(),
            configured_uuid: configured_uuid.into(),
            configs: configs
                .iter()
                .map(|(k, v)| (k.to_string(), parse_config(v).unwrap()))
                .collect(),
            template: Template::compile(index_html),
        }
    }

    /// The `SUBPAGE_CONFIG_UUID` env pins one config; with the default value the user's own
    /// config (chosen in the panel's response rules) wins.
    fn final_uuid<'a>(&'a self, from_panel: Option<&'a str>) -> &'a str {
        match from_panel {
            Some(u) if self.configured_uuid == SUBPAGE_DEFAULT_CONFIG_UUID => u,
            _ => &self.configured_uuid,
        }
    }

    pub fn encrypted_config_uuid(&self, from_panel: Option<&str>) -> String {
        encrypt_uuid(self.final_uuid(from_panel), &self.secret)
    }

    pub fn base_settings(&self, from_panel: Option<&str>) -> BaseSettings {
        self.configs
            .get(self.final_uuid(from_panel))
            .map_or_else(BaseSettings::fallback, |c| c.base.clone())
    }

    /// Body for `/assets/.app-config-v2.json`; `None` means "pretend it does not exist".
    pub fn config_for_session(&self, encrypted_uuid: &str) -> Option<&Value> {
        let Some(uuid) = decrypt_uuid(encrypted_uuid, &self.secret) else {
            tracing::error!("[FATAL] SubPage config {encrypted_uuid} is not valid");
            return None;
        };
        let cfg = self.configs.get(&uuid);
        if cfg.is_none() {
            tracing::error!("[FATAL] SubPage config {uuid} not found");
        }
        cfg.map(|c| &c.value)
    }

    pub fn render_index(&self, base: &BaseSettings, panel_data: &Value) -> String {
        let panel_b64 = STANDARD.encode(panel_data.to_string());
        self.template
            .render(&base.meta_title, &base.meta_description, &panel_b64)
    }
}

/// Minimal EJS replacement: the built `index.html` only uses `<%- metaTitle %>`,
/// `<%- metaDescription %>` and `<%- panelData %>`.
struct Template {
    source: String,
    re: Regex,
}

impl Template {
    fn compile(source: &str) -> Self {
        Self {
            source: source.to_string(),
            re: Regex::new(r"<%[-=]\s*(metaTitle|metaDescription|panelData)\s*%>").unwrap(),
        }
    }

    /// Unlike EJS' raw `<%-`, user-controlled meta values are HTML-escaped.
    fn render(&self, title: &str, description: &str, panel_data: &str) -> String {
        self.re
            .replace_all(&self.source, |caps: &Captures| match &caps[1] {
                "metaTitle" => escape_html(title),
                "metaDescription" => escape_html(description),
                _ => escape_html(panel_data),
            })
            .into_owned()
    }
}

fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config(title: Option<&str>) -> Value {
        let mut v = json!({
            "version": "1", "locales": ["en"], "brandingSettings": {}, "uiConfig": {},
            "baseTranslations": {}, "svgLibrary": {}, "platforms": {}, "junk": 1
        });
        if let Some(t) = title {
            v["baseSettings"] = json!({ "metaTitle": t, "showConnectionKeys": true });
        }
        v
    }

    #[test]
    fn parse_applies_defaults_and_strips_unknown_keys() {
        let c = parse_config(&sample_config(None)).unwrap();
        assert_eq!(c.base.meta_title, "Subscription");
        assert!(!c.base.show_connection_keys);
        assert!(c.value.get("junk").is_none());
        assert_eq!(c.value["baseSettings"]["hideGetLinkButton"], json!(false));

        let c = parse_config(&sample_config(Some("Hi"))).unwrap();
        assert_eq!(c.base.meta_title, "Hi");
        assert!(c.base.show_connection_keys);
    }

    #[test]
    fn config_key_order_is_preserved() {
        let raw: Value = serde_json::from_str(
            r#"{"version":"1","locales":["en"],"brandingSettings":{},"uiConfig":{},
            "baseTranslations":{},"svgLibrary":{},"platforms":{"windows":{},"android":{},"ios":{}}}"#,
        )
        .unwrap();
        let c = parse_config(&raw).unwrap();
        let platforms: Vec<_> = c.value["platforms"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        assert_eq!(platforms, ["windows", "android", "ios"]);
        assert!(c
            .value
            .to_string()
            .starts_with(r#"{"version":"1","locales""#));
    }

    #[test]
    fn parse_rejects_bad_configs() {
        assert!(parse_config(&json!([])).is_err());
        assert!(parse_config(&json!({ "locales": ["en"] })).is_err());
        let mut v = sample_config(None);
        v["locales"] = json!([]);
        assert!(parse_config(&v).is_err());
        let mut v = sample_config(None);
        v["baseSettings"] = json!({ "metaTitle": 5 });
        assert!(parse_config(&v).is_err());
    }

    #[test]
    fn template_escapes_and_substitutes_once() {
        let html = "<title><%- metaTitle %></title><meta content=\"<%- metaDescription %>\"><div data-panel=\"<%- panelData %>\">";
        let t = Template::compile(html);
        let out = t.render("<b>\"x\"</b>", "a&b", "<%- metaTitle %>");
        assert!(out.contains("<title>&lt;b&gt;&quot;x&quot;&lt;/b&gt;</title>"));
        assert!(out.contains("content=\"a&amp;b\""));
        assert!(out.contains("data-panel=\"&lt;%- metaTitle %&gt;\""));
    }

    #[test]
    fn config_selection_follows_default_uuid_rule() {
        let a = "11111111-1111-1111-1111-111111111111";
        let b = "22222222-2222-2222-2222-222222222222";
        let cfgs = [(a, sample_config(Some("A"))), (b, sample_config(Some("B")))];

        let w = Webpage::for_tests("", "s", SUBPAGE_DEFAULT_CONFIG_UUID, &cfgs);
        assert_eq!(w.base_settings(Some(b)).meta_title, "B");
        // default-uuid pin and no per-user config -> unknown uuid -> fallback
        assert_eq!(w.base_settings(None).meta_title, "Subscription Page");

        let w = Webpage::for_tests("", "s", a, &cfgs);
        assert_eq!(w.base_settings(Some(b)).meta_title, "A");
        let enc = w.encrypted_config_uuid(Some(b));
        assert_eq!(
            w.config_for_session(&enc).unwrap()["baseSettings"]["metaTitle"],
            "A"
        );
        assert!(w.config_for_session("garbage").is_none());
    }
}
