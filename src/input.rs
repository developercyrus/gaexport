//! Turning whatever the user points us at — QR screenshots, photos, pasted
//! URIs, a directory, stdin — into a de-duplicated list of OTP keys.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::migration;
use crate::otp::{redact_uri, OtpEntry};
use crate::qr;

/// Where to read from. Empty means "stdin", so `gaexport decode < codes.txt`
/// works without flags.
#[derive(Debug, Default, Clone)]
pub struct InputSpec {
    pub paths: Vec<PathBuf>,
    pub uris: Vec<String>,
    pub stdin: bool,
}

impl InputSpec {
    pub fn is_empty(&self) -> bool {
        self.paths.is_empty() && self.uris.is_empty() && !self.stdin
    }
}

#[derive(Debug, Default)]
pub struct Collected {
    pub entries: Vec<OtpEntry>,
    /// Non-fatal problems worth telling the user about (never contain secrets).
    pub warnings: Vec<String>,
    /// How many QR codes / URIs actually produced keys.
    pub sources: usize,
    pub duplicates: usize,
}

impl Collected {
    /// The wire shape shared by the HTTP API and the WebAssembly build, so the
    /// browser UI sees identical JSON no matter which backend decoded.
    pub fn to_json(&self) -> anyhow::Result<serde_json::Value> {
        Ok(serde_json::json!({
            "entries": crate::output::entries_to_value(
                &self.entries,
                crate::output::RenderOptions::default(),
            )?,
            "warnings": self.warnings,
            "sources": self.sources,
            "duplicates": self.duplicates,
        }))
    }
}

#[derive(Debug, Clone, Copy)]
struct BatchMark {
    id: i32,
    size: i32,
    index: i32,
}

/// Max directory recursion depth. Deep enough for `~/Pictures/Screenshots/2024`,
/// shallow enough not to crawl a whole home directory by accident.
const MAX_DEPTH: usize = 3;

pub fn collect(spec: &InputSpec) -> Result<Collected> {
    let mut out = Collected::default();
    let mut batches: Vec<BatchMark> = Vec::new();

    for uri in &spec.uris {
        ingest_text(uri, "argument", &mut out, &mut batches);
    }

    for path in &spec.paths {
        if path.as_os_str() == "-" {
            read_stdin(&mut out, &mut batches)?;
            continue;
        }
        let meta =
            std::fs::metadata(path).with_context(|| format!("cannot read {}", path.display()))?;
        if meta.is_dir() {
            let files = walk(path, MAX_DEPTH)?;
            if files.is_empty() {
                out.warnings
                    .push(format!("{}: no images or text files found", path.display()));
            }
            for file in files {
                ingest_file(&file, &mut out, &mut batches);
            }
        } else {
            ingest_file(path, &mut out, &mut batches);
        }
    }

    if spec.stdin {
        read_stdin(&mut out, &mut batches)?;
    }

    check_batches(&batches, &mut out);
    out.duplicates = dedupe(&mut out.entries);

    if out.entries.is_empty() {
        let detail = if out.warnings.is_empty() {
            String::new()
        } else {
            format!("\n  - {}", out.warnings.join("\n  - "))
        };
        bail!("no OTP keys found in the given input{detail}");
    }
    Ok(out)
}

fn read_stdin(out: &mut Collected, batches: &mut Vec<BatchMark>) -> Result<()> {
    let mut buf = Vec::new();
    std::io::stdin()
        .read_to_end(&mut buf)
        .context("reading stdin")?;
    if buf.is_empty() {
        out.warnings.push("stdin was empty".to_string());
        return Ok(());
    }
    if qr::looks_like_image_bytes(&buf) {
        match qr::decode_image_bytes(&buf) {
            Ok(contents) => {
                for content in contents {
                    ingest_text(&content, "stdin (image)", out, batches);
                }
            }
            Err(e) => out.warnings.push(format!("stdin (image): {e}")),
        }
        return Ok(());
    }
    let text = String::from_utf8_lossy(&buf).into_owned();
    ingest_text(&text, "stdin", out, batches);
    Ok(())
}

fn ingest_file(path: &Path, out: &mut Collected, batches: &mut Vec<BatchMark>) {
    let label = path.display().to_string();
    if qr::looks_like_image_path(path) {
        match qr::decode_image_file(path) {
            Ok(contents) => {
                for content in contents {
                    ingest_text(&content, &label, out, batches);
                }
            }
            Err(e) => out.warnings.push(format!("{label}: {e}")),
        }
        return;
    }
    match std::fs::read(path) {
        Ok(bytes) if qr::looks_like_image_bytes(&bytes) => match qr::decode_image_bytes(&bytes) {
            Ok(contents) => {
                for content in contents {
                    ingest_text(&content, &label, out, batches);
                }
            }
            Err(e) => out.warnings.push(format!("{label}: {e}")),
        },
        Ok(bytes) => {
            let text = String::from_utf8_lossy(&bytes).into_owned();
            ingest_text(&text, &label, out, batches);
        }
        Err(e) => out.warnings.push(format!("{label}: {e}")),
    }
}

/// Pulls every OTP key out of a blob of text: export URIs, plain `otpauth://`
/// URIs, or a bare base64 payload.
fn ingest_text(text: &str, source: &str, out: &mut Collected, batches: &mut Vec<BatchMark>) {
    let mut produced = false;
    for uri in scan_uris(text) {
        if migration::is_migration_uri(&uri) {
            match migration::parse_uri(&uri) {
                Ok(payload) => {
                    if payload.batch_size > 1 {
                        batches.push(BatchMark {
                            id: payload.batch_id,
                            size: payload.batch_size,
                            index: payload.batch_index,
                        });
                    }
                    out.sources += 1;
                    produced = true;
                    out.entries.extend(payload.entries);
                }
                Err(e) => out
                    .warnings
                    .push(format!("{source}: bad export URI: {e:#}")),
            }
        } else {
            match OtpEntry::from_uri(&uri) {
                Ok(entry) => {
                    out.sources += 1;
                    produced = true;
                    out.entries.push(entry);
                }
                Err(e) => out
                    .warnings
                    .push(format!("{source}: skipping `{}`: {e:#}", redact_uri(&uri))),
            }
        }
    }
    if produced {
        return;
    }

    // No URI in there — maybe it is a bare base64 payload, or `data=…`.
    let candidate = text
        .trim()
        .trim_start_matches("data=")
        .trim_matches(|c: char| c == '"' || c == '\'');
    if candidate.len() >= 8 {
        if let Ok(bytes) = migration::decode_base64_tolerant(candidate) {
            if let Ok(payload) = migration::decode_payload(&bytes) {
                if payload.batch_size > 1 {
                    batches.push(BatchMark {
                        id: payload.batch_id,
                        size: payload.batch_size,
                        index: payload.batch_index,
                    });
                }
                out.sources += 1;
                out.entries.extend(payload.entries);
                return;
            }
        }
    }
    if !text.trim().is_empty() {
        out.warnings.push(format!(
            "{source}: no otpauth:// or {}:// data found",
            migration::SCHEME
        ));
    }
}

/// Finds URIs embedded anywhere in a text blob (logs, notes, HTML, JSON).
pub fn scan_uris(text: &str) -> Vec<String> {
    const MIGRATION_PREFIX: &str = "otpauth-migration://";
    const OTPAUTH_PREFIX: &str = "otpauth://";
    let mut found = Vec::new();
    let mut cursor = 0usize;
    while cursor < text.len() {
        if !text.is_char_boundary(cursor) {
            cursor += 1;
            continue;
        }
        let rest = &text[cursor..];
        let head: String = rest
            .chars()
            .take(MIGRATION_PREFIX.len())
            .collect::<String>()
            .to_ascii_lowercase();
        let matched = if head.starts_with(MIGRATION_PREFIX) {
            Some(MIGRATION_PREFIX.len())
        } else if head.starts_with(OTPAUTH_PREFIX) {
            Some(OTPAUTH_PREFIX.len())
        } else {
            None
        };
        match matched {
            Some(prefix_len) => {
                let end = rest
                    .char_indices()
                    .find(|(i, c)| {
                        *i >= prefix_len
                            && (c.is_whitespace()
                                || matches!(c, '"' | '\'' | '<' | '>' | '`' | '|'))
                    })
                    .map(|(i, _)| i)
                    .unwrap_or(rest.len());
                let uri = rest[..end].trim_end_matches([',', ';', ')', ']', '}', '.']);
                if !uri.is_empty() {
                    found.push(uri.to_string());
                }
                cursor += end.max(1);
            }
            None => {
                cursor += rest.chars().next().map(char::len_utf8).unwrap_or(1);
            }
        }
    }
    found
}

/// Warns when an export was split across several QR codes and some are missing.
fn check_batches(batches: &[BatchMark], out: &mut Collected) {
    let mut groups: BTreeMap<i32, (i32, Vec<i32>)> = BTreeMap::new();
    for mark in batches {
        let slot = groups.entry(mark.id).or_insert((mark.size, Vec::new()));
        slot.0 = slot.0.max(mark.size);
        if !slot.1.contains(&mark.index) {
            slot.1.push(mark.index);
        }
    }
    for (_batch_id, (size, mut seen)) in groups {
        seen.sort_unstable();
        if (seen.len() as i32) < size {
            let missing: Vec<String> = (0..size)
                .filter(|i| !seen.contains(i))
                .map(|i| (i + 1).to_string())
                .collect();
            out.warnings.push(format!(
                "this export is split across {size} QR codes and {} {} still missing \
                 — swipe to the next code in Google Authenticator's export screen and add {} too",
                if missing.len() == 1 {
                    format!("code {}", missing[0])
                } else {
                    format!("codes {}", missing.join(", "))
                },
                if missing.len() == 1 { "is" } else { "are" },
                if missing.len() == 1 { "it" } else { "them" },
            ));
        }
    }
}

/// Removes exact duplicates, keeping first-seen order. Returns how many went.
pub fn dedupe(entries: &mut Vec<OtpEntry>) -> usize {
    let mut seen = std::collections::HashSet::new();
    let before = entries.len();
    entries.retain(|e| seen.insert(e.fingerprint()));
    before - entries.len()
}

fn walk(dir: &Path, depth: usize) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let mut dirs = Vec::new();
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue;
        }
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            dirs.push(path);
        } else if qr::looks_like_image_path(&path) || is_text_path(&path) {
            files.push(path);
        }
    }
    files.sort();
    dirs.sort();
    if depth > 0 {
        for sub in dirs {
            files.extend(walk(&sub, depth - 1)?);
        }
    }
    Ok(files)
}

fn is_text_path(path: &Path) -> bool {
    matches!(
        path.extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase())
            .as_deref(),
        Some("txt" | "text" | "uri" | "uris" | "md" | "json" | "csv" | "log")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scans_uris_out_of_prose() {
        let text = "here it is: otpauth://totp/a?secret=GEZDGNBVGY3TQOJQ, and \
                    \"otpauth-migration://offline?data=AAA%3D\" done";
        let found = scan_uris(text);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0], "otpauth://totp/a?secret=GEZDGNBVGY3TQOJQ");
        assert_eq!(found[1], "otpauth-migration://offline?data=AAA%3D");
    }

    #[test]
    fn scanning_is_case_insensitive_and_handles_unicode() {
        let found = scan_uris("日本語 OTPAUTH://TOTP/x?secret=GEZDGNBVGY3TQOJQ ok");
        assert_eq!(found.len(), 1);
        assert!(found[0].to_lowercase().starts_with("otpauth://"));
    }

    #[test]
    fn collects_from_uri_arguments_and_dedupes() {
        let uri = "otpauth://totp/ACME:alice?secret=GEZDGNBVGY3TQOJQ&issuer=ACME";
        let spec = InputSpec {
            uris: vec![uri.to_string(), uri.to_string()],
            ..Default::default()
        };
        let collected = collect(&spec).unwrap();
        assert_eq!(collected.entries.len(), 1);
        assert_eq!(collected.duplicates, 1);
        assert_eq!(collected.sources, 2);
    }

    #[test]
    fn accepts_a_bare_base64_payload() {
        let entries = vec![OtpEntry {
            secret: zeroize::Zeroizing::new(b"12345678901234567890".to_vec()),
            name: "alice".into(),
            issuer: "ACME".into(),
            ..Default::default()
        }];
        let uri = migration::build_uris(&entries, 10, migration::DEFAULT_MAX_URI_BYTES).unwrap()[0]
            .clone();
        let data = uri.split("data=").nth(1).unwrap().to_string();
        let raw = percent_encoding::percent_decode_str(&data)
            .decode_utf8()
            .unwrap()
            .into_owned();
        let spec = InputSpec {
            uris: vec![raw],
            ..Default::default()
        };
        let collected = collect(&spec).unwrap();
        assert_eq!(collected.entries.len(), 1);
        assert_eq!(collected.entries[0].name, "alice");
    }

    #[test]
    fn missing_batch_produces_a_warning() {
        let entries: Vec<_> = (0..4)
            .map(|i| OtpEntry {
                secret: zeroize::Zeroizing::new(b"12345678901234567890".to_vec()),
                name: format!("user{i}"),
                issuer: "ACME".into(),
                ..Default::default()
            })
            .collect();
        let uris = migration::build_uris(&entries, 2, migration::DEFAULT_MAX_URI_BYTES).unwrap();
        assert_eq!(uris.len(), 2);
        let spec = InputSpec {
            uris: vec![uris[0].clone()], // only the first QR code
            ..Default::default()
        };
        let collected = collect(&spec).unwrap();
        assert_eq!(collected.entries.len(), 2);
        assert!(
            collected
                .warnings
                .iter()
                .any(|w| w.contains("split across 2 QR codes")),
            "{:?}",
            collected.warnings
        );
    }

    #[test]
    fn empty_input_is_an_error_with_context() {
        let spec = InputSpec {
            uris: vec!["hello world".to_string()],
            ..Default::default()
        };
        let err = collect(&spec).unwrap_err().to_string();
        assert!(err.contains("no OTP keys found"), "{err}");
    }

    #[test]
    fn secrets_never_leak_into_warnings() {
        let spec = InputSpec {
            // Missing `secret` is fine to show; a bad digits value must not echo the secret.
            uris: vec!["otpauth://totp/a?secret=GEZDGNBVGY3TQOJQ&digits=abc".to_string()],
            ..Default::default()
        };
        let err = collect(&spec).unwrap_err().to_string();
        assert!(!err.contains("GEZDGNBVGY3TQOJQ"), "{err}");
    }
}
