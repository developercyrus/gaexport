//! A small local HTTP server with a browser UI.
//!
//! Design rules, because this handles 2FA secrets:
//!   * binds to loopback by default and refuses anything else without an
//!     explicit `--allow-remote` plus a token,
//!   * keeps nothing: no database, no files, no request logging of payloads,
//!   * shuts itself down after an idle period so a forgotten tab is not a
//!     standing decryption service,
//!   * OTP codes are computed in the browser, so the server stays stateless.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Multipart, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use clap::Args;
use serde::Deserialize;

use crate::input::{self, InputSpec};
use crate::migration;
use crate::otp::{now_unix, OtpEntry};
use crate::qr;

const INDEX_HTML: &str = include_str!("../assets/index.html");
const APP_CSS: &str = include_str!("../assets/app.css");
const APP_JS: &str = include_str!("../assets/app.js");
const I18N_JS: &str = include_str!("../assets/i18n.js");

/// 25 MB is plenty for a phone photo of a QR code.
const MAX_BODY: usize = 25 * 1024 * 1024;
const TOKEN_HEADER: &str = "x-gaexport-token";

#[derive(Args, Debug, Clone)]
pub struct ServeArgs {
    /// Address to bind to
    #[arg(long, default_value = "127.0.0.1", value_name = "ADDR")]
    pub host: String,

    /// Port to listen on
    #[arg(short, long, default_value_t = 8765)]
    pub port: u16,

    /// Require this token (as `?token=…` or an `x-gaexport-token` header).
    /// Generated automatically when not binding to loopback
    #[arg(long, env = "GAEXPORT_TOKEN", value_name = "TOKEN")]
    pub token: Option<String>,

    /// Allow a non-loopback bind. Secrets would then travel over the network —
    /// only do this behind TLS on a host you trust
    #[arg(long)]
    pub allow_remote: bool,

    /// Exit after this many seconds with no requests (0 disables)
    #[arg(long, default_value_t = 900, value_name = "SECS")]
    pub idle_timeout: u64,
}

struct AppState {
    token: Option<String>,
    last_activity: AtomicU64,
    shutdown: tokio::sync::Notify,
}

pub fn run(args: ServeArgs, quiet: bool) -> Result<()> {
    let ip: IpAddr = args
        .host
        .parse()
        .with_context(|| format!("`{}` is not an IP address", args.host))?;
    if !ip.is_loopback() && !args.allow_remote {
        bail!(
            "refusing to bind {ip}: the UI decodes 2FA secrets, so it listens on loopback only.\n\
             Use an SSH tunnel (`ssh -L 8765:localhost:8765 host`), or pass --allow-remote if you \
             really mean to expose it (a token will be required, and you should put TLS in front)."
        );
    }
    let token = match (&args.token, ip.is_loopback()) {
        (Some(t), _) if !t.trim().is_empty() => Some(t.trim().to_string()),
        (_, false) => Some(uuid::Uuid::new_v4().simple().to_string()),
        _ => None,
    };

    let state = Arc::new(AppState {
        token: token.clone(),
        last_activity: AtomicU64::new(now_unix()),
        shutdown: tokio::sync::Notify::new(),
    });

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting the async runtime")?;
    runtime.block_on(serve(
        SocketAddr::new(ip, args.port),
        state,
        args,
        quiet,
        token,
    ))
}

async fn serve(
    addr: SocketAddr,
    state: Arc<AppState>,
    args: ServeArgs,
    quiet: bool,
    token: Option<String>,
) -> Result<()> {
    let app = Router::new()
        .route("/", get(index))
        .route("/app.css", get(app_css))
        .route("/app.js", get(app_js))
        .route("/i18n.js", get(i18n_js))
        .route("/healthz", get(|| async { "ok\n" }))
        .route("/api/decode", post(api_decode))
        .route("/api/decode/upload", post(api_decode_upload))
        .route("/api/qr", post(api_qr))
        .route("/api/encode", post(api_encode))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .layer(axum::middleware::from_fn_with_state(state.clone(), gate))
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("cannot bind {addr} (already in use?)"))?;
    let local = listener.local_addr().unwrap_or(addr);

    if !quiet {
        let url = match &token {
            Some(t) => format!("http://{local}/?token={t}"),
            None => format!("http://{local}/"),
        };
        eprintln!("\x1b[1mgaexport\x1b[0m  {url}");
        eprintln!("  · QR decoding runs in this process; OTP codes are computed in your browser");
        eprintln!("  · nothing is stored: no database, no files, no request logging");
        if args.idle_timeout > 0 {
            eprintln!("  · exits automatically after {}s idle", args.idle_timeout);
        }
        if !local.ip().is_loopback() {
            eprintln!("  · \x1b[33mreachable from the network — token required, use TLS\x1b[0m");
        }
        eprintln!("  Ctrl-C to stop");
    }

    if args.idle_timeout > 0 {
        let watchdog = state.clone();
        let limit = args.idle_timeout;
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                let idle =
                    now_unix().saturating_sub(watchdog.last_activity.load(Ordering::Relaxed));
                if idle >= limit {
                    eprintln!("gaexport: idle for {idle}s, shutting down");
                    watchdog.shutdown.notify_waiters();
                    return;
                }
            }
        });
    }

    let shutdown_state = state.clone();
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = shutdown_state.shutdown.notified() => {}
            }
        })
        .await
        .context("server error")?;
    Ok(())
}


/// Token check plus idle-timer bookkeeping.
async fn gate(
    State(state): State<Arc<AppState>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    state.last_activity.store(now_unix(), Ordering::Relaxed);

    let path = request.uri().path();

    if path == "/healthz" || state.token.is_none() {
        return next.run(request).await;
    }

    let expected = state.token.as_deref().unwrap_or_default();

    // 1. Read token from the request header.
    let header_token = request
        .headers()
        .get(TOKEN_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    // 2. Read token from the initial URL.
    let query_token = request.uri().query().and_then(|q| {
        q.split('&').find_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            (k == "token").then(|| v.to_string())
        })
    });

    // 3. Read token from the HttpOnly cookie.
    let cookie_token = request
        .headers()
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';').find_map(|part| {
                let (name, value) = part.trim().split_once('=')?;
                (name == "__Host-gaexport").then(|| value.to_string())
            })
        });

    let presented = header_token
        .or_else(|| query_token.clone())
        .or(cookie_token)
        .unwrap_or_default();

    if !constant_time_eq(presented.as_bytes(), expected.as_bytes()) {
        return (
            StatusCode::UNAUTHORIZED,
            "missing or wrong token\n",
        )
            .into_response();
    }

    // 4. Valid URL token: establish a session cookie and
    //    redirect to remove the token from the browser URL.
    if path == "/" && query_token.as_deref() == Some(expected) {
        let cookie = format!(
            "__Host-gaexport={expected}; Path=/; HttpOnly; SameSite=Strict; Secure"
        );

        let cookie = match header::HeaderValue::from_str(&cookie) {
            Ok(value) => value,
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "could not create authentication cookie\n",
                )
                    .into_response();
            }
        };

        let mut headers = no_store();

        headers.insert(
            header::LOCATION,
            header::HeaderValue::from_static("/"),
        );

        headers.insert(header::SET_COOKIE, cookie);

        return (StatusCode::SEE_OTHER, headers).into_response();
    }

    next.run(request).await
}



fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

async fn index() -> impl IntoResponse {
    (no_store(), Html(INDEX_HTML))
}

async fn app_css() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], APP_CSS)
}

async fn app_js() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        APP_JS,
    )
}

async fn i18n_js() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        I18N_JS,
    )
}

/// Responses carry secrets: never let a proxy or the browser cache them.
fn no_store() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store, max-age=0"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        header::HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::HeaderName::from_static("x-content-type-options"),
        header::HeaderValue::from_static("nosniff"),
    );
    // The UI is entirely self-hosted; block anything else outright.
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        header::HeaderValue::from_static(
            "default-src 'self'; img-src 'self' data: blob:; media-src 'self' blob:; \
             style-src 'self'; script-src 'self'; connect-src 'self'; base-uri 'none'; \
             form-action 'none'; frame-ancestors 'none'",
        ),
    );
    headers
}

#[derive(Deserialize, Default)]
struct DecodeRequest {
    /// Pasted URIs, base64 payload, or any text containing them.
    #[serde(default)]
    text: String,
}

/// `application/json {"text": …}` — pasted URIs or a bare base64 payload.
async fn api_decode(body: Bytes) -> Response {
    match decode_json(&body) {
        Ok(payload) => (no_store(), Json(payload)).into_response(),
        Err(err) => error_response(StatusCode::BAD_REQUEST, &format!("{err:#}")),
    }
}

/// `multipart/form-data` — one or more QR screenshots/photos.
async fn api_decode_upload(multipart: Multipart) -> Response {
    match decode_multipart(multipart).await {
        Ok(payload) => (no_store(), Json(payload)).into_response(),
        Err(err) => error_response(StatusCode::BAD_REQUEST, &format!("{err:#}")),
    }
}

fn decode_json(body: &Bytes) -> Result<serde_json::Value> {
    let request: DecodeRequest = if body.is_empty() {
        DecodeRequest::default()
    } else {
        serde_json::from_slice(body).context("body is not valid JSON")?
    };
    if request.text.trim().is_empty() {
        bail!("nothing to decode: paste an export URI or drop a QR image");
    }
    let collected = input::collect(&InputSpec {
        uris: vec![request.text],
        ..Default::default()
    })?;
    respond(collected)
}

async fn decode_multipart(mut multipart: Multipart) -> Result<serde_json::Value> {
    let mut texts: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut entries: Vec<OtpEntry> = Vec::new();
    let mut sources = 0usize;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| anyhow::anyhow!("bad upload: {e}"))?
    {
        let name = field.file_name().map(str::to_string);
        let data = field
            .bytes()
            .await
            .map_err(|e| anyhow::anyhow!("upload interrupted: {e}"))?;
        if data.is_empty() {
            continue;
        }
        let label = name.unwrap_or_else(|| "upload".to_string());
        if qr::looks_like_image_bytes(&data) {
            match qr::decode_image_bytes(&data) {
                Ok(contents) => texts.extend(contents),
                Err(e) => warnings.push(format!("{label}: {e}")),
            }
        } else {
            texts.push(String::from_utf8_lossy(&data).into_owned());
        }
    }

    for text in texts {
        match input::collect(&InputSpec {
            uris: vec![text],
            ..Default::default()
        }) {
            Ok(mut collected) => {
                sources += collected.sources;
                warnings.append(&mut collected.warnings);
                entries.append(&mut collected.entries);
            }
            Err(e) => warnings.push(format!("{e:#}")),
        }
    }

    if entries.is_empty() {
        let detail = if warnings.is_empty() {
            "no QR code or otpauth data found in the upload".to_string()
        } else {
            warnings.join("; ")
        };
        bail!("{detail}");
    }
    let duplicates = input::dedupe(&mut entries);
    respond(input::Collected {
        entries,
        warnings,
        sources,
        duplicates,
    })
}

fn respond(collected: input::Collected) -> Result<serde_json::Value> {
    collected.to_json()
}

#[derive(Deserialize)]
struct QrRequest {
    data: String,
    #[serde(default = "default_scale")]
    scale: u32,
    #[serde(default)]
    svg: bool,
}

fn default_scale() -> u32 {
    8
}

async fn api_qr(Json(request): Json<QrRequest>) -> Response {
    if request.data.trim().is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "empty payload");
    }
    let opts = qr::RenderOptions {
        scale: request.scale.clamp(1, 32),
        ..Default::default()
    };
    if request.svg {
        return match qr::render_svg(&request.data, opts) {
            Ok(svg) => (no_store(), [(header::CONTENT_TYPE, "image/svg+xml")], svg).into_response(),
            Err(e) => error_response(StatusCode::BAD_REQUEST, &format!("{e:#}")),
        };
    }
    match qr::render_png(&request.data, opts) {
        Ok(png) => (no_store(), [(header::CONTENT_TYPE, "image/png")], png).into_response(),
        Err(e) => error_response(StatusCode::BAD_REQUEST, &format!("{e:#}")),
    }
}

#[derive(Deserialize)]
struct EncodeRequest {
    /// `otpauth://` URIs to pack into export QR codes.
    uris: Vec<String>,
    #[serde(default = "default_per_batch")]
    per_batch: usize,
}

fn default_per_batch() -> usize {
    migration::DEFAULT_MAX_PER_BATCH
}

async fn api_encode(Json(request): Json<EncodeRequest>) -> Response {
    let mut entries = Vec::new();
    for uri in &request.uris {
        match OtpEntry::from_uri(uri) {
            Ok(entry) => entries.push(entry),
            Err(e) => {
                return error_response(StatusCode::BAD_REQUEST, &format!("{e:#}"));
            }
        }
    }
    match migration::build_uris(
        &entries,
        request.per_batch,
        migration::DEFAULT_MAX_URI_BYTES,
    ) {
        Ok(uris) => (no_store(), Json(serde_json::json!({ "uris": uris }))).into_response(),
        Err(e) => error_response(StatusCode::BAD_REQUEST, &format!("{e:#}")),
    }
}

fn error_response(status: StatusCode, message: &str) -> Response {
    (
        status,
        no_store(),
        Json(serde_json::json!({ "error": message })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_behaves_like_eq() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn loopback_bind_needs_no_token() {
        let args = ServeArgs {
            host: "127.0.0.1".into(),
            port: 0,
            token: None,
            allow_remote: false,
            idle_timeout: 0,
        };
        assert!(args.host.parse::<IpAddr>().unwrap().is_loopback());
    }

    #[test]
    fn remote_bind_is_refused_without_opt_in() {
        let args = ServeArgs {
            host: "0.0.0.0".into(),
            port: 0,
            token: None,
            allow_remote: false,
            idle_timeout: 0,
        };
        let err = run(args, true).unwrap_err().to_string();
        assert!(err.contains("refusing to bind"), "{err}");
    }

    #[test]
    fn json_decode_returns_entries() {
        let body = Bytes::from(
            serde_json::json!({"text": "otpauth://totp/ACME:alice?secret=GEZDGNBVGY3TQOJQ&issuer=ACME"})
                .to_string(),
        );
        let value = decode_json(&body).unwrap();
        assert_eq!(value["entries"].as_array().unwrap().len(), 1);
        assert_eq!(value["entries"][0]["issuer"], "ACME");
        assert_eq!(value["entries"][0]["secret"], "GEZDGNBVGY3TQOJQ");
    }

    #[test]
    fn json_decode_rejects_empty_text() {
        let err = decode_json(&Bytes::from("{}")).unwrap_err().to_string();
        assert!(err.contains("nothing to decode"), "{err}");
    }

    #[test]
    fn security_headers_are_present() {
        let headers = no_store();
        assert_eq!(headers[header::CACHE_CONTROL], "no-store, max-age=0");
        assert!(headers.contains_key(header::CONTENT_SECURITY_POLICY));
    }

    #[test]
    fn embedded_assets_are_present() {
        assert!(INDEX_HTML.contains("<html"));
        assert!(APP_JS.contains("function"));
        assert!(I18N_JS.contains("GAEXPORT_I18N"));
        assert!(!APP_CSS.trim().is_empty());
    }
}
