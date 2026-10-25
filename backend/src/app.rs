//! Router, middleware chain and request handlers.
//!
//! The chain mirrors the original Express pipeline: health probe → proxy check → assets
//! cookie check → real IP / header filter → static assets → (helmet, CORS, access log) →
//! routes. "Destroying the socket" is expressed as a [`DropConnection`] response that the
//! server layer turns into an aborted connection.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use axum::body::Body;
use axum::extract::rejection::PathRejection;
use axum::extract::{Path, Request, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Router};
use tower_http::cors::{AllowHeaders, Any, CorsLayer};
use tower_http::normalize_path::NormalizePath;
use tower_http::services::fs::ServeFileSystemResponseBody;
use tower_http::services::ServeDir;

use crate::config::Config;
use crate::constants::{is_browser, is_ignored_header, APP_CONFIG_ROUTE, REQUEST_TEMPLATE_TYPES};
use crate::marzban::{MarzbanResolver, Resolution};
use crate::panel::PanelClient;
use crate::session::{self, Claims};
use crate::webpage::Webpage;

pub struct AppState {
    pub config: Config,
    pub panel: PanelClient,
    pub webpage: Webpage,
    pub marzban: Option<MarzbanResolver>,
}

/// Peer address of the TCP connection, inserted by the server layer.
#[derive(Debug, Clone, Copy)]
pub struct RemoteAddr(pub SocketAddr);

/// Marker extension: the server must abort the connection without sending a response.
#[derive(Debug, Clone, Copy)]
pub struct DropConnection;

#[derive(Debug, Clone)]
pub struct ClientIp(pub String);

pub fn drop_response() -> Response {
    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    resp.extensions_mut().insert(DropConnection);
    resp
}

async fn drop_handler() -> Response {
    drop_response()
}

fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4 == Ipv4Addr::LOCALHOST,
        IpAddr::V6(v6) => {
            v6 == Ipv6Addr::LOCALHOST || v6.to_ipv4_mapped() == Some(Ipv4Addr::LOCALHOST)
        }
    }
}

fn header_present(headers: &HeaderMap, name: &str) -> bool {
    headers.get(name).is_some_and(|v| !v.is_empty())
}

fn joined_header(headers: &HeaderMap, name: &str) -> Option<String> {
    let values: Vec<&str> = headers
        .get_all(name)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    (!values.is_empty()).then(|| values.join(", "))
}

fn path_is_assets(path: &str) -> bool {
    path == "/assets" || path.starts_with("/assets/")
}

/// Outermost middleware: everything that must run before routing and static files.
async fn gate(State(st): State<Arc<AppState>>, mut req: Request, next: Next) -> Response {
    let remote = req.extensions().get::<RemoteAddr>().map(|r| r.0.ip());
    let path = req.uri().path().to_owned();

    // Docker health probe: loopback only, never through a reverse proxy.
    if (path == "/internal/health" || path == "/internal/health/")
        && remote.is_some_and(is_loopback)
        && !header_present(req.headers(), "x-forwarded-for")
    {
        return (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            "OK",
        )
            .into_response();
    }

    // A reverse proxy terminating HTTPS is mandatory in production.
    if !st.config.development {
        let proxied = header_present(req.headers(), "x-forwarded-for");
        let https = req
            .headers()
            .get("x-forwarded-proto")
            .is_some_and(|v| v.as_bytes() == b"https");
        if !proxied || !https {
            tracing::debug!(
                "X-Forwarded-For: {:?}, X-Forwarded-Proto: {:?}",
                req.headers().get("x-forwarded-for"),
                req.headers().get("x-forwarded-proto")
            );
            tracing::error!("Reverse proxy and HTTPS are required.");
            return drop_response();
        }
    }

    if path_is_assets(&path) {
        // sirv does not serve dotfiles; the only dot-path under /assets is the app config route.
        if path != APP_CONFIG_ROUTE
            && path
                .split('/')
                .any(|seg| seg.starts_with('.') || seg.to_ascii_lowercase().starts_with("%2e"))
        {
            return drop_response();
        }
        let cookies = req
            .headers()
            .get_all(header::COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok());
        let Some(token) = session::cookie_value(cookies, session::COOKIE_NAME) else {
            tracing::debug!("No session cookie found");
            return drop_response();
        };
        match session::verify(&token, &st.config.internal_jwt_secret) {
            Ok(claims) => {
                req.extensions_mut().insert(claims);
            }
            Err(e) => {
                tracing::debug!("{e}");
                return drop_response();
            }
        }
    }

    // Real client IP (resolved before the proxy headers are stripped below).
    let socket_ip = remote.map(|ip| ip.to_string()).unwrap_or_default();
    let xff = joined_header(req.headers(), "x-forwarded-for");
    let mut ip = st.config.trust_proxy.resolve(&socket_ip, xff.as_deref());
    if ip.is_empty() {
        ip = socket_ip;
    }
    if ip.is_empty() {
        ip = "0.0.0.0".into();
    }
    let ip = ip.strip_prefix("::ffff:").map_or(ip.clone(), str::to_owned);
    req.extensions_mut().insert(ClientIp(ip));

    // Header filter: nothing hop-specific or credential-like reaches the panel.
    let to_remove: Vec<HeaderName> = req
        .headers()
        .keys()
        .filter(|k| is_ignored_header(k.as_str()))
        .cloned()
        .collect();
    for name in to_remove {
        req.headers_mut().remove(name);
    }
    if !header_present(req.headers(), "user-agent") {
        return drop_response();
    }

    let mut resp = next.run(req).await;
    if resp.extensions().get::<DropConnection>().is_none() {
        resp.headers_mut()
            .entry("x-robots-tag")
            .or_insert(HeaderValue::from_static(
                "noindex, nofollow, noarchive, nosnippet, noimageindex",
            ));
    }
    resp
}

/// Defaults of `helmet({ contentSecurityPolicy: false })`; headers set by a handler win.
async fn security_headers(mut resp: Response) -> Response {
    const HELMET: [(&str, &str); 10] = [
        ("cross-origin-opener-policy", "same-origin"),
        ("cross-origin-resource-policy", "same-origin"),
        ("origin-agent-cluster", "?1"),
        ("referrer-policy", "no-referrer"),
        (
            "strict-transport-security",
            "max-age=31536000; includeSubDomains",
        ),
        ("x-content-type-options", "nosniff"),
        ("x-dns-prefetch-control", "off"),
        ("x-download-options", "noopen"),
        ("x-frame-options", "SAMEORIGIN"),
        ("x-permitted-cross-domain-policies", "none"),
    ];
    let headers = resp.headers_mut();
    for (name, value) in HELMET {
        headers
            .entry(HeaderName::from_static(name))
            .or_insert(HeaderValue::from_static(value));
    }
    headers
        .entry(HeaderName::from_static("x-xss-protection"))
        .or_insert(HeaderValue::from_static("0"));
    resp
}

/// morgan: `:remote-addr - ":method :url HTTP/:http-version" :status :res[content-length] ":referrer" ":user-agent"`
async fn access_log(req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let version = match req.version() {
        axum::http::Version::HTTP_09 => "0.9",
        axum::http::Version::HTTP_10 => "1.0",
        axum::http::Version::HTTP_2 => "2.0",
        axum::http::Version::HTTP_3 => "3.0",
        _ => "1.1",
    };
    let (referrer, ua, ip) = {
        let hdr = |name: &str| {
            req.headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("-")
                .to_owned()
        };
        let ip = req
            .extensions()
            .get::<ClientIp>()
            .map(|c| c.0.clone())
            .unwrap_or_default();
        (hdr("referer"), hdr("user-agent"), ip)
    };

    let resp = next.run(req).await;
    if !path_is_assets(uri.path()) && resp.extensions().get::<DropConnection>().is_none() {
        let len = resp
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-");
        tracing::info!(
            target: "http",
            "{ip} - \"{method} {uri} HTTP/{version}\" {} {len} \"{referrer}\" \"{ua}\"",
            resp.status().as_u16()
        );
    }
    resp
}

/// `GET /assets/.app-config-v2.json`: the config belonging to the caller's session.
async fn app_config(
    State(st): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
) -> Response {
    match st.webpage.config_for_session(&claims.su) {
        Some(cfg) => (
            [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
            cfg.to_string(),
        )
            .into_response(),
        None => drop_response(),
    }
}

/// `GET [/prefix]/{short_uuid}[/{client_type}]`
async fn subscription(
    State(st): State<Arc<AppState>>,
    Extension(ClientIp(client_ip)): Extension<ClientIp>,
    params: Result<Path<HashMap<String, String>>, PathRejection>,
    headers: HeaderMap,
) -> Response {
    let Ok(Path(params)) = params else {
        return drop_response();
    };
    let Some(short_uuid) = params.get("short_uuid") else {
        return drop_response();
    };
    let client_type = params.get("client_type").map(String::as_str);

    if let Some(ct) = client_type {
        if !REQUEST_TEMPLATE_TYPES.contains(&ct) {
            tracing::error!("Invalid client type: {ct}");
            return drop_response();
        }
    }

    let short_uuid = match &st.marzban {
        Some(m) => match m.resolve_short_uuid(short_uuid, &client_ip).await {
            Resolution::Drop => return drop_response(),
            Resolution::Resolved(resolved) => resolved,
            Resolution::PassThrough => short_uuid.clone(),
        },
        None => short_uuid.clone(),
    };

    // `.` / `..` would be collapsed by URL normalisation and address other panel endpoints.
    if short_uuid == "." || short_uuid == ".." {
        return drop_response();
    }

    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok());
    if is_browser(ua) {
        serve_webpage(&st, &client_ip, &headers, &short_uuid).await
    } else {
        serve_subscription(&st, &client_ip, &headers, &short_uuid, client_type).await
    }
}

async fn serve_subscription(
    st: &AppState,
    client_ip: &str,
    headers: &HeaderMap,
    short_uuid: &str,
    client_type: Option<&str>,
) -> Response {
    match st
        .panel
        .get_subscription(client_ip, short_uuid, headers, client_type)
        .await
    {
        Ok(sub) => {
            let mut resp = Response::new(Body::from(sub.body));
            *resp.headers_mut() = sub.headers;
            resp
        }
        Err(e) => {
            if !e.is_not_found() {
                tracing::error!("Error in GetSubscription Request: {e}");
            }
            drop_response()
        }
    }
}

async fn serve_webpage(
    st: &AppState,
    client_ip: &str,
    headers: &HeaderMap,
    short_uuid: &str,
) -> Response {
    let mut info = match st.panel.get_subscription_info(client_ip, short_uuid).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("Error in GetSubscriptionInfo Request: {e}");
            return drop_response();
        }
    };
    let subpage = match st.panel.get_subpage_config(short_uuid, headers).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("Error in GetSubpageConfig Request: {e}");
            return drop_response();
        }
    };
    if !subpage.webpage_allowed {
        tracing::info!("Webpage access is not allowed by Remnawave's SRR.");
        return drop_response();
    }

    let panel_uuid = subpage.subpage_config_uuid.as_deref();
    let base = st.webpage.base_settings(panel_uuid);

    if !base.show_connection_keys {
        if let Some(resp) = info.get_mut("response").and_then(|r| r.as_object_mut()) {
            resp.insert("links".into(), serde_json::json!([]));
            resp.insert("ssConfLinks".into(), serde_json::json!({}));
        }
    }

    let token = match session::sign(
        st.webpage.encrypted_config_uuid(panel_uuid),
        &st.config.internal_jwt_secret,
    ) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("Error in returnWebpage: {e}");
            return drop_response();
        }
    };
    let cookie = session::set_cookie_header(&token, !st.config.development);
    let html = st.webpage.render_index(&base, &info);

    let mut resp = ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], html).into_response();
    if let Ok(v) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().insert(header::SET_COOKIE, v);
    }
    resp
}

/// Static files of the SPA (`sirv(..., { maxAge: 7d, immutable, etag: false })`).
/// Served without helmet/CORS headers, like the original.
fn static_router(st: &AppState) -> Router<Arc<AppState>> {
    let dir = st.config.frontend_dir.join("assets");
    let serve = tower::ServiceBuilder::new()
        .map_response(|resp: Response<ServeFileSystemResponseBody>| {
            let mut resp = resp.map(Body::new);
            if resp.status().is_success() {
                resp.headers_mut().insert(
                    header::CACHE_CONTROL,
                    HeaderValue::from_static("public,max-age=604800,immutable"),
                );
                resp
            } else {
                // 404 / 405 / anything unusual: behave like an unknown route.
                drop_response()
            }
        })
        .service(ServeDir::new(dir).append_index_html_on_directories(false));
    Router::new().nest_service("/assets", serve)
}

/// Full application service. Trailing slashes are trimmed before routing (Express is not strict
/// about them).
pub fn build_service(state: Arc<AppState>) -> NormalizePath<Router> {
    NormalizePath::trim_trailing_slash(build_router(state))
}

pub fn build_router(state: Arc<AppState>) -> Router {
    let prefix = state.config.custom_sub_prefix.as_deref().unwrap_or("");
    let base = if prefix.is_empty() {
        String::new()
    } else {
        format!(
            "/{}",
            prefix
                .trim_matches('/')
                .replace('{', "{{")
                .replace('}', "}}")
        )
    };

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET])
        .allow_headers(AllowHeaders::mirror_request());

    // Unknown routes and wrong methods are dropped inside the CORS/helmet/log layers so that
    // preflight requests are still answered.
    let dynamic = Router::new()
        .route(APP_CONFIG_ROUTE, get(app_config))
        .route(&format!("{base}/{{short_uuid}}"), get(subscription))
        .route(
            &format!("{base}/{{short_uuid}}/{{client_type}}"),
            get(subscription),
        )
        .fallback(drop_handler)
        .method_not_allowed_fallback(drop_handler)
        .layer(cors)
        .layer(middleware::map_response(security_headers))
        .layer(middleware::from_fn(access_log));

    dynamic
        .merge(static_router(&state))
        .layer(middleware::from_fn_with_state(state.clone(), gate))
        .with_state(state)
}
