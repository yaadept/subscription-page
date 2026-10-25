//! Constants shared with the Remnawave panel contract
//! (`@remnawave/backend-contract`, `@remnawave/subscription-page-types`).

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub const REAL_IP_HEADER: &str = "x-remnawave-real-ip";
pub const SUBPAGE_VERSION_HEADER: &str = "x-subpage-version";

pub const APP_CONFIG_ROUTE: &str = "/assets/.app-config-v2.json";
pub const SUBPAGE_DEFAULT_CONFIG_UUID: &str = "00000000-0000-0000-0000-000000000000";

pub const REQUEST_TEMPLATE_TYPES: [&str; 6] =
    ["stash", "singbox", "mihomo", "json", "v2ray-json", "clash"];

/// Headers that are never forwarded to the panel and never copied back from its response.
pub const IGNORED_HEADERS: &[&str] = &[
    "accept-encoding",
    "alt-svc",
    "authorization",
    "cache-control",
    "cf-access-client-id",
    "cf-access-client-secret",
    "cf-cache-status",
    "cf-connecting-ip",
    "cf-ray",
    "connection",
    "content-length",
    "content-security-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "expires",
    "fastly-client-ip",
    "forwarded",
    "forwarded-for",
    "host",
    "keep-alive",
    "nel",
    "origin-agent-cluster",
    "pragma",
    "proxy-authenticate",
    "proxy-authorization",
    "report-to",
    "server",
    "te",
    "trailer",
    "transfer-encoding",
    "true-client-ip",
    "upgrade",
    "x-api-key",
    "x-client-ip",
    "x-cluster-client-ip",
    "x-forwarded",
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-forwarded-scheme",
    "x-real-ip",
    "x-remnawave-client-type",
    "x-remnawave-real-ip",
    "x-subpage-version",
    "etag",
    "last-modified",
];

pub fn is_ignored_header(name: &str) -> bool {
    IGNORED_HEADERS.contains(&name)
}

/// User-Agent substrings that make a request be treated as a browser (HTML page is served).
const BROWSER_KEYWORDS: [&str; 10] = [
    "Mozilla",
    "Chrome",
    "Safari",
    "Firefox",
    "Opera",
    "Edge",
    "TelegramBot",
    "WhatsApp",
    "facebookexternalhit",
    "SteamChat",
];

pub fn is_browser(user_agent: Option<&str>) -> bool {
    match user_agent {
        Some(ua) if !ua.is_empty() => BROWSER_KEYWORDS.iter().any(|k| ua.contains(k)),
        _ => false,
    }
}
