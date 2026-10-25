//! End-to-end tests: the real service against a mock Remnawave panel.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use rw_subpage::config::Config;
use rw_subpage::{app, init_state, server};

const DEFAULT_UUID: &str = "00000000-0000-0000-0000-000000000000";
const INDEX_HTML: &str = "<!doctype html><html><head><title><%- metaTitle %></title>\
<meta name=\"description\" content=\"<%- metaDescription %>\"></head>\
<body><div id=\"root\"></div><div id=\"sbpg\" data-panel=\"<%- panelData %>\"></div></body></html>";

#[derive(Debug, Clone)]
struct Recorded {
    path: String,
    headers: HashMap<String, String>,
    body: String,
}

#[derive(Clone, Default)]
struct Panel {
    log: Arc<Mutex<Vec<Recorded>>>,
    revoked_user: bool,
}

impl Panel {
    fn record(&self, path: String, headers: &HeaderMap, body: String) {
        let headers = headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        self.log.lock().unwrap().push(Recorded {
            path,
            headers,
            body,
        });
    }
    fn last(&self, prefix: &str) -> Recorded {
        self.log
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|r| r.path.starts_with(prefix))
            .cloned()
            .unwrap_or_else(|| panic!("no panel request starting with {prefix}"))
    }
    fn count(&self, prefix: &str) -> usize {
        self.log
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.path.starts_with(prefix))
            .count()
    }
}

fn page_config() -> Value {
    json!({
        "version": "1",
        "locales": ["en"],
        "brandingSettings": { "title": "x" },
        "uiConfig": {},
        "baseSettings": { "metaTitle": "My <Sub>", "metaDescription": "Desc & more", "showConnectionKeys": false },
        "baseTranslations": {},
        "svgLibrary": {},
        "platforms": {},
        "leaked": "must be stripped"
    })
}

async fn start_panel(panel: Panel) -> SocketAddr {
    async fn metadata(State(p): State<Panel>, h: HeaderMap) -> Json<Value> {
        p.record("/api/system/metadata".into(), &h, String::new());
        Json(json!({ "response": { "version": "2.7.0", "build": {}, "git": {} } }))
    }
    async fn configs(State(p): State<Panel>, h: HeaderMap) -> Json<Value> {
        p.record("/api/subscription-page-configs".into(), &h, String::new());
        Json(json!({ "response": { "total": 1, "configs": [{ "uuid": DEFAULT_UUID }] } }))
    }
    async fn config(State(p): State<Panel>, h: HeaderMap, Path(u): Path<String>) -> Json<Value> {
        p.record(
            format!("/api/subscription-page-configs/{u}"),
            &h,
            String::new(),
        );
        Json(json!({ "response": { "uuid": u, "config": page_config() } }))
    }
    async fn info(
        State(p): State<Panel>,
        h: HeaderMap,
        Path(s): Path<String>,
    ) -> axum::response::Response {
        p.record(format!("/api/sub/{s}/info"), &h, String::new());
        if s == "missing" {
            return StatusCode::NOT_FOUND.into_response();
        }
        Json(json!({ "response": {
            "isFound": true,
            "user": { "shortUuid": s, "username": "alice" },
            "links": ["vless://secret"],
            "ssConfLinks": { "a": "ss://secret" },
            "subscriptionUrl": "https://sub.example/x"
        } }))
        .into_response()
    }
    async fn subpage_cfg(
        State(p): State<Panel>,
        h: HeaderMap,
        Path(s): Path<String>,
        body: String,
    ) -> Json<Value> {
        p.record(format!("/api/subscriptions/subpage-config/{s}"), &h, body);
        Json(json!({ "response": { "subpageConfigUuid": null, "webpageAllowed": s != "blocked" } }))
    }
    async fn sub(
        State(p): State<Panel>,
        h: HeaderMap,
        Path(path): Path<String>,
    ) -> axum::response::Response {
        p.record(format!("/api/sub/{path}"), &h, String::new());
        if path.starts_with("missing") {
            return StatusCode::NOT_FOUND.into_response();
        }
        (
            [
                ("profile-title", "My profile"),
                ("subscription-userinfo", "upload=1; download=2"),
                ("etag", "\"abc\""),
                ("x-api-key", "leak"),
            ],
            format!("vless://sub-for/{path}"),
        )
            .into_response()
    }
    async fn by_username(
        State(p): State<Panel>,
        h: HeaderMap,
        Path(u): Path<String>,
    ) -> axum::response::Response {
        p.record(format!("/api/users/by-username/{u}"), &h, String::new());
        if u == "ghost_" {
            return StatusCode::NOT_FOUND.into_response();
        }
        let revoked = if p.revoked_user {
            json!("2025-01-01T00:00:00.000Z")
        } else {
            Value::Null
        };
        Json(json!({ "response": { "shortUuid": format!("short-of-{u}"), "subRevokedAt": revoked } }))
            .into_response()
    }

    let router =
        Router::new()
            .route("/api/system/metadata", get(metadata))
            .route("/api/subscription-page-configs", get(configs))
            .route("/api/subscription-page-configs/{uuid}", get(config))
            .route("/api/sub/{short}/info", get(info))
            .route("/api/sub/{short}", get(sub))
            .route(
                "/api/subscriptions/subpage-config/{short}",
                get(subpage_cfg),
            )
            .route("/api/users/by-username/{u}", get(by_username))
            .route(
                "/api/sub/{short}/{ct}",
                get(
                    |State(p): State<Panel>,
                     h: HeaderMap,
                     Path((s, ct)): Path<(String, String)>| async move {
                        p.record(format!("/api/sub/{s}/{ct}"), &h, String::new());
                        format!("vless://sub-for/{s}/{ct}")
                    },
                ),
            )
            .fallback(
                |State(p): State<Panel>, uri: axum::http::Uri, h: HeaderMap| async move {
                    p.record(format!("UNROUTED {}", uri.path()), &h, String::new());
                    StatusCode::NOT_FOUND
                },
            )
            .with_state(panel);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    addr
}

struct Harness {
    addr: SocketAddr,
    panel: Panel,
    client: reqwest::Client,
    _dir: tempfile::TempDir,
}

async fn harness(extra_env: &[(&str, &str)], panel: Panel) -> Harness {
    let panel_addr = start_panel(panel.clone()).await;

    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("assets")).unwrap();
    std::fs::write(dir.path().join("index.html"), INDEX_HTML).unwrap();
    std::fs::write(dir.path().join("assets/app.js"), "console.log(1)").unwrap();

    let mut env: HashMap<String, String> = [
        ("REMNAWAVE_PANEL_URL", format!("http://{panel_addr}")),
        ("REMNAWAVE_API_TOKEN", "panel-token".into()),
        ("FRONTEND_DIR", dir.path().display().to_string()),
        ("INTERNAL_JWT_SECRET", "test-secret".into()),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect();
    for (k, v) in extra_env {
        env.insert(k.to_string(), v.to_string());
    }

    let state = init_state(Config::from_map(&env).unwrap()).await.unwrap();
    let listener = server::bind(0).unwrap();
    let addr = SocketAddr::from(([127, 0, 0, 1], listener.local_addr().unwrap().port()));
    tokio::spawn(server::serve(
        listener,
        app::build_service(state),
        std::future::pending(),
    ));

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    Harness {
        addr,
        panel,
        client,
        _dir: dir,
    }
}

impl Harness {
    fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }
    /// A request as it arrives from a TLS-terminating reverse proxy.
    fn get(&self, path: &str, ua: Option<&str>) -> reqwest::RequestBuilder {
        let rb = self
            .client
            .get(self.url(path))
            .header("x-forwarded-for", "203.0.113.7")
            .header("x-forwarded-proto", "https");
        match ua {
            Some(ua) => rb.header("user-agent", ua),
            None => rb,
        }
    }
    async fn is_dropped(&self, rb: reqwest::RequestBuilder) -> bool {
        match rb.send().await {
            Err(e) => !e.is_timeout(),
            Ok(_) => false,
        }
    }
    /// Raw HTTP/1.1 exchange; returns everything the server sent before closing.
    async fn raw(&self, request: &str) -> String {
        let mut s = TcpStream::connect(self.addr).await.unwrap();
        s.write_all(request.as_bytes()).await.unwrap();
        let mut out = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(3), s.read_to_end(&mut out)).await;
        String::from_utf8_lossy(&out).into_owned()
    }
}

const BROWSER: &str = "Mozilla/5.0 (X11; Linux x86_64) Chrome/120";

#[tokio::test]
async fn health_probe_only_for_loopback_without_forwarding() {
    let h = harness(&[], Panel::default()).await;
    let ok = h
        .client
        .get(h.url("/internal/health"))
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);
    assert_eq!(ok.text().await.unwrap(), "OK");

    // Same probe through a "reverse proxy" is not answered by the health handler.
    assert!(h.is_dropped(h.get("/internal/health", Some("x"))).await);
}

#[tokio::test]
async fn requests_without_https_reverse_proxy_are_dropped() {
    let h = harness(&[], Panel::default()).await;
    let plain = h.client.get(h.url("/abc")).header("user-agent", "Happ/1.0");
    assert!(h.is_dropped(plain).await);
    let no_proto = h
        .client
        .get(h.url("/abc"))
        .header("user-agent", "Happ/1.0")
        .header("x-forwarded-for", "1.1.1.1");
    assert!(h.is_dropped(no_proto).await);
    // Nothing leaked to the panel
    assert_eq!(h.panel.count("/api/sub/"), 0);
}

#[tokio::test]
async fn proxies_subscription_for_non_browser_clients() {
    let h = harness(&[], Panel::default()).await;
    let resp = h
        .get("/abc123", Some("Happ/1.0"))
        .header("x-hwid", "device-1")
        .header("authorization", "Bearer attacker")
        .header("x-real-ip", "6.6.6.6")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let hd = resp.headers().clone();
    assert_eq!(hd["profile-title"], "My profile");
    assert_eq!(hd["subscription-userinfo"], "upload=1; download=2");
    assert!(
        hd.get("etag").is_none(),
        "ignored headers must not be copied back"
    );
    assert!(hd.get("x-api-key").is_none());
    assert!(hd["x-robots-tag"].to_str().unwrap().contains("noindex"));
    assert_eq!(hd["access-control-allow-origin"], "*");
    assert_eq!(hd["x-content-type-options"], "nosniff");
    assert_eq!(hd["x-frame-options"], "SAMEORIGIN");
    assert!(hd.get("x-powered-by").is_none());
    assert_eq!(resp.text().await.unwrap(), "vless://sub-for/abc123");

    let seen = h.panel.last("/api/sub/abc123");
    assert!(
        !seen.headers.contains_key("authorization"),
        "panel token must not reach /api/sub"
    );
    assert_eq!(seen.headers["x-hwid"], "device-1");
    assert_eq!(seen.headers["user-agent"], "Happ/1.0");
    assert_eq!(seen.headers["x-remnawave-real-ip"], "203.0.113.7");
    assert_eq!(seen.headers["accept"], "*/*");
    assert_eq!(seen.headers["pragma"], "no-cache");
    assert_ne!(
        seen.headers.get("x-real-ip").map(String::as_str),
        Some("6.6.6.6")
    );
    assert_eq!(seen.headers["x-subpage-version"], env!("CARGO_PKG_VERSION"));
}

#[tokio::test]
async fn client_type_route_validates_type() {
    let h = harness(&[], Panel::default()).await;
    let ok = h.get("/abc/clash", Some("Happ/1.0")).send().await.unwrap();
    assert_eq!(ok.status(), 200);
    assert_eq!(ok.text().await.unwrap(), "vless://sub-for/abc/clash");

    assert!(h.is_dropped(h.get("/abc/bogus", Some("Happ/1.0"))).await);
    assert_eq!(h.panel.count("/api/sub/abc/bogus"), 0);
}

#[tokio::test]
async fn unknown_subscription_missing_ua_and_unknown_routes_are_dropped() {
    let h = harness(&[], Panel::default()).await;
    assert!(h.is_dropped(h.get("/missing", Some("Happ/1.0"))).await);
    assert!(h.is_dropped(h.get("/abc", None)).await);
    assert!(
        h.is_dropped(h.get("/a/clash/extra", Some("Happ/1.0")))
            .await
    );
    assert!(
        h.is_dropped(
            h.client
                .post(h.url("/abc"))
                .header("x-forwarded-for", "1.1.1.1")
                .header("x-forwarded-proto", "https")
                .header("user-agent", "x")
        )
        .await
    );
}

#[tokio::test]
async fn dot_segments_never_reach_the_panel() {
    let h = harness(&[], Panel::default()).await;
    let before = h.panel.log.lock().unwrap().len();
    let reply = h
        .raw("GET /%2e%2e HTTP/1.1\r\nHost: x\r\nUser-Agent: Happ\r\nX-Forwarded-For: 1.1.1.1\r\nX-Forwarded-Proto: https\r\nConnection: close\r\n\r\n")
        .await;
    assert!(
        reply.is_empty(),
        "expected dropped connection, got {reply:?}"
    );
    assert_eq!(h.panel.log.lock().unwrap().len(), before);
}

#[tokio::test]
async fn dropped_requests_get_no_bytes_at_all() {
    let h = harness(&[], Panel::default()).await;
    let reply = h
        .raw("GET /whatever HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await;
    assert!(reply.is_empty(), "got {reply:?}");
}

#[tokio::test]
async fn browser_flow_serves_page_cookie_config_and_assets() {
    let h = harness(&[], Panel::default()).await;
    let resp = h.get("/user42", Some(BROWSER)).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["content-type"], "text/html; charset=utf-8");
    let cookie = resp.headers()["set-cookie"].to_str().unwrap().to_string();
    assert!(cookie.starts_with("session="));
    assert!(cookie.contains("HttpOnly") && cookie.contains("Secure") && cookie.contains("Path=/"));
    assert!(cookie.contains("Max-Age=1800"));
    let session = cookie.split(';').next().unwrap().to_string();
    let html = resp.text().await.unwrap();

    // meta values are escaped, panel data is base64 JSON without connection keys
    assert!(html.contains("<title>My &lt;Sub&gt;</title>"), "{html}");
    assert!(html.contains("content=\"Desc &amp; more\""));
    let b64 = html
        .split("data-panel=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    let panel_data: Value = serde_json::from_slice(&STANDARD.decode(b64).unwrap()).unwrap();
    assert_eq!(panel_data["response"]["user"]["username"], "alice");
    assert_eq!(panel_data["response"]["links"], json!([]));
    assert_eq!(panel_data["response"]["ssConfLinks"], json!({}));
    assert_eq!(
        panel_data["response"]["subscriptionUrl"],
        "https://sub.example/x"
    );

    // The panel gets the (filtered) request headers in the body, GET + JSON
    let cfg_req = h.panel.last("/api/subscriptions/subpage-config/user42");
    let body: Value = serde_json::from_str(&cfg_req.body).unwrap();
    assert_eq!(body["requestHeaders"]["user-agent"], BROWSER);
    assert!(body["requestHeaders"].get("x-forwarded-for").is_none());
    assert_eq!(cfg_req.headers["authorization"], "Bearer panel-token");
    assert_eq!(
        h.panel.last("/api/sub/user42/info").headers["x-remnawave-real-ip"],
        "203.0.113.7"
    );

    // App config with the session cookie; unknown keys stripped
    let cfg = h
        .get("/assets/.app-config-v2.json?v=1", Some(BROWSER))
        .header("cookie", &session)
        .send()
        .await
        .unwrap();
    assert_eq!(cfg.status(), 200);
    assert!(cfg.headers()["content-type"]
        .to_str()
        .unwrap()
        .starts_with("application/json"));
    assert_eq!(cfg.headers()["x-frame-options"], "SAMEORIGIN");
    let cfg: Value = cfg.json().await.unwrap();
    assert_eq!(cfg["baseSettings"]["metaTitle"], "My <Sub>");
    assert!(cfg.get("leaked").is_none());

    // Static asset: immutable caching, no helmet headers (as with sirv)
    let js = h
        .get("/assets/app.js", Some(BROWSER))
        .header("cookie", &session)
        .send()
        .await
        .unwrap();
    assert_eq!(js.status(), 200);
    assert_eq!(
        js.headers()["cache-control"],
        "public,max-age=604800,immutable"
    );
    assert!(js.headers().get("etag").is_none());
    assert!(js.headers().get("x-frame-options").is_none());
    assert_eq!(js.text().await.unwrap(), "console.log(1)");

    // Without / with a bad session, or a missing file -> dropped
    assert!(h.is_dropped(h.get("/assets/app.js", Some(BROWSER))).await);
    assert!(
        h.is_dropped(
            h.get("/assets/app.js", Some(BROWSER))
                .header("cookie", "session=nope")
        )
        .await
    );
    assert!(
        h.is_dropped(
            h.get("/assets/nope.js", Some(BROWSER))
                .header("cookie", &session)
        )
        .await
    );
    for traversal in [
        "/assets/../index.html",
        "/assets/%2e%2e/index.html",
        "/assets/..%2findex.html",
    ] {
        let reply = h
            .raw(&format!("GET {traversal} HTTP/1.1\r\nHost: x\r\nUser-Agent: {BROWSER}\r\nX-Forwarded-For: 1.1.1.1\r\nX-Forwarded-Proto: https\r\nCookie: {session}\r\nConnection: close\r\n\r\n"))
            .await;
        assert!(
            !reply.contains("<!doctype html"),
            "path traversal leaked a file via {traversal}: {reply}"
        );
    }
    assert!(
        h.is_dropped(h.get("/assets/", Some(BROWSER)).header("cookie", &session))
            .await
    );
}

#[tokio::test]
async fn webpage_not_allowed_or_unknown_user_is_dropped() {
    let h = harness(&[], Panel::default()).await;
    assert!(h.is_dropped(h.get("/blocked", Some(BROWSER))).await);
    assert!(h.is_dropped(h.get("/missing", Some(BROWSER))).await);
}

#[tokio::test]
async fn custom_prefix_moves_routes_but_not_assets() {
    let h = harness(&[("CUSTOM_SUB_PREFIX", "sub")], Panel::default()).await;
    let ok = h.get("/sub/abc", Some("Happ/1.0")).send().await.unwrap();
    assert_eq!(ok.status(), 200);
    assert_eq!(
        h.get("/sub/abc/clash", Some("Happ/1.0"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert!(h.is_dropped(h.get("/abc", Some("Happ/1.0"))).await);

    let page = h.get("/sub/abc", Some(BROWSER)).send().await.unwrap();
    let cookie = page.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let cfg = h
        .get("/assets/.app-config-v2.json", Some(BROWSER))
        .header("cookie", cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(cfg.status(), 200);
}

#[tokio::test]
async fn trailing_slash_is_tolerated_like_express() {
    let h = harness(&[], Panel::default()).await;
    assert_eq!(
        h.get("/abc/", Some("Happ/1.0"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
}

#[tokio::test]
async fn trust_proxy_controls_the_forwarded_client_ip() {
    let h = harness(&[("TRUST_PROXY", "false")], Panel::default()).await;
    h.get("/abc", Some("Happ/1.0")).send().await.unwrap();
    assert_eq!(
        h.panel.last("/api/sub/abc").headers["x-remnawave-real-ip"],
        "127.0.0.1"
    );

    let h = harness(&[("TRUST_PROXY", "2")], Panel::default()).await;
    h.get("/abc", Some("Happ/1.0"))
        .header("x-forwarded-for", "198.51.100.9, 203.0.113.7")
        .send()
        .await
        .unwrap();
    // reqwest folds the duplicate header names; the leftmost of the 2 trusted hops wins
    assert!(["198.51.100.9", "203.0.113.7"]
        .contains(&h.panel.last("/api/sub/abc").headers["x-remnawave-real-ip"].as_str()));
}

fn legacy_marzban_token(username: &str, created_at: i64, key: &str) -> String {
    let u = URL_SAFE_NO_PAD.encode(format!("{username},{created_at}"));
    let mut hasher = Sha256::new();
    hasher.update(u.as_bytes());
    hasher.update(key.as_bytes());
    let sig: String = URL_SAFE_NO_PAD
        .encode(hasher.finalize())
        .chars()
        .take(10)
        .collect();
    format!("{u}{sig}")
}

#[tokio::test]
async fn marzban_links_are_resolved_to_short_uuids() {
    let h = harness(
        &[
            ("MARZBAN_LEGACY_LINK_ENABLED", "true"),
            ("MARZBAN_LEGACY_SECRET_KEY", "old,mz-secret"),
        ],
        Panel::default(),
    )
    .await;

    let token = legacy_marzban_token("bob", 1_700_000_000, "mz-secret");
    let resp = h
        .get(&format!("/{token}"), Some("Happ/1.0"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    // `bob` is sanitized to 6 chars before the lookup
    assert_eq!(
        h.panel.last("/api/users/by-username/").path,
        "/api/users/by-username/bob___"
    );
    assert_eq!(
        resp.text().await.unwrap(),
        "vless://sub-for/short-of-bob___"
    );

    // Regular short UUIDs pass through untouched
    let plain = h
        .get("/plain-short-uuid", Some("Happ/1.0"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        plain.text().await.unwrap(),
        "vless://sub-for/plain-short-uuid"
    );

    // Valid signature but user unknown in Remnawave -> dropped
    let ghost = legacy_marzban_token("ghost", 1_700_000_000, "old");
    assert!(
        h.is_dropped(h.get(&format!("/{ghost}"), Some("Happ/1.0")))
            .await
    );
}

#[tokio::test]
async fn marzban_revoked_subscriptions_can_be_dropped() {
    let panel = Panel {
        revoked_user: true,
        ..Panel::default()
    };
    let h = harness(
        &[
            ("MARZBAN_LEGACY_LINK_ENABLED", "true"),
            ("MARZBAN_LEGACY_SECRET_KEY", "k"),
            ("MARZBAN_LEGACY_DROP_REVOKED_SUBSCRIPTIONS", "true"),
        ],
        panel,
    )
    .await;
    let token = legacy_marzban_token("carol", 1_700_000_000, "k");
    assert!(
        h.is_dropped(h.get(&format!("/{token}"), Some("Happ/1.0")))
            .await
    );
}

#[tokio::test]
async fn cors_preflight_is_answered() {
    let h = harness(&[], Panel::default()).await;
    let resp = h
        .client
        .request(reqwest::Method::OPTIONS, h.url("/abc"))
        .header("x-forwarded-for", "1.1.1.1")
        .header("x-forwarded-proto", "https")
        .header("user-agent", BROWSER)
        .header("origin", "https://example.com")
        .header("access-control-request-method", "GET")
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    assert_eq!(resp.headers()["access-control-allow-origin"], "*");
    assert!(resp.headers()["access-control-allow-methods"]
        .to_str()
        .unwrap()
        .contains("GET"));
}

#[tokio::test]
async fn startup_fails_when_panel_is_unreachable() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("index.html"), INDEX_HTML).unwrap();
    let env: HashMap<String, String> = [
        ("REMNAWAVE_PANEL_URL", "http://127.0.0.1:1"),
        ("REMNAWAVE_API_TOKEN", "t"),
        ("FRONTEND_DIR", dir.path().to_str().unwrap()),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    let err = init_state(Config::from_map(&env).unwrap())
        .await
        .err()
        .unwrap();
    assert!(
        err.contains("Connection to Remnawave Panel failed"),
        "{err}"
    );
}
