//! WebAssembly bindings for the hosted, fully client-side build.
//!
//! The same decoder that powers the CLI is compiled to WASM and called straight
//! from the page, so the hosted version can be a plain static site: no backend
//! receives your export, because there is no backend. Values cross the boundary
//! as JSON strings, which keeps the ABI trivial and the glue code obvious.
//!
//! Exported names deliberately avoid `decodeText`, `encodeString` and friends:
//! wasm-bindgen generates internal helpers with those names, and a collision is
//! a module-level syntax error rather than a compile error. `build-web.sh`
//! checks the generated glue for exactly that.

use wasm_bindgen::prelude::*;

use crate::input::{self, InputSpec};
use crate::migration;
use crate::otp::OtpEntry;
use crate::qr;

fn js_err(error: anyhow::Error) -> JsValue {
    // `{:#}` includes the whole context chain, which is what the UI shows.
    JsValue::from_str(&format!("{error:#}"))
}

fn json(collected: input::Collected) -> Result<String, JsValue> {
    let value = collected.to_json().map_err(js_err)?;
    serde_json::to_string(&value).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Decodes pasted text: export URIs, plain `otpauth://` URIs or a bare base64
/// payload. Returns the same JSON the HTTP API returns.
#[wasm_bindgen(js_name = readText)]
pub fn decode_text(text: &str) -> Result<String, JsValue> {
    let collected = input::collect(&InputSpec {
        uris: vec![text.to_string()],
        ..Default::default()
    })
    .map_err(js_err)?;
    json(collected)
}

/// Decodes an uploaded image file (PNG/JPEG/GIF/WebP/…).
#[wasm_bindgen(js_name = readImage)]
pub fn decode_image(bytes: &[u8]) -> Result<String, JsValue> {
    let contents = qr::decode_image_bytes(bytes).map_err(js_err)?;
    collect_all(&contents)
}

/// Decodes one camera frame straight from canvas RGBA pixels.
#[wasm_bindgen(js_name = readFrame)]
pub fn decode_rgba(pixels: &[u8], width: u32, height: u32) -> Result<String, JsValue> {
    let contents = qr::decode_rgba(pixels, width, height).map_err(js_err)?;
    collect_all(&contents)
}

fn collect_all(contents: &[String]) -> Result<String, JsValue> {
    let mut merged = input::Collected::default();
    for content in contents {
        match input::collect(&InputSpec {
            uris: vec![content.clone()],
            ..Default::default()
        }) {
            Ok(mut collected) => {
                merged.sources += collected.sources;
                merged.warnings.append(&mut collected.warnings);
                merged.entries.append(&mut collected.entries);
            }
            Err(error) => merged.warnings.push(format!("{error:#}")),
        }
    }
    if merged.entries.is_empty() {
        let detail = if merged.warnings.is_empty() {
            "no otpauth data in the QR code".to_string()
        } else {
            merged.warnings.join("; ")
        };
        return Err(JsValue::from_str(&detail));
    }
    merged.duplicates = input::dedupe(&mut merged.entries);
    json(merged)
}

/// Renders a QR code for one `otpauth://` URI as standalone SVG markup.
#[wasm_bindgen(js_name = renderQrSvg)]
pub fn qr_svg(data: &str) -> Result<String, JsValue> {
    qr::render_svg(data, qr::RenderOptions::default()).map_err(js_err)
}

/// Packs newline-separated `otpauth://` URIs back into Google Authenticator
/// export URIs, one per line (one line = one QR code to render).
#[wasm_bindgen(js_name = packMigration)]
pub fn encode_migration(uris: &str) -> Result<String, JsValue> {
    let entries = uris
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(OtpEntry::from_uri)
        .collect::<anyhow::Result<Vec<_>>>()
        .map_err(js_err)?;
    let packed = migration::build_uris(
        &entries,
        migration::DEFAULT_MAX_PER_BATCH,
        migration::DEFAULT_MAX_URI_BYTES,
    )
    .map_err(js_err)?;
    Ok(packed.join("\n"))
}

/// The crate version, so the page can show which build it is running.
#[wasm_bindgen(js_name = buildVersion)]
pub fn version() -> String {
    crate::VERSION.to_string()
}
