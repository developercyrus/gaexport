//! Output formats. Every renderer takes the same entries so `--format` never
//! changes *what* was decoded, only how it is presented.

use std::fmt::Write as _;

use anyhow::{Context, Result};
use serde::Serialize;

use crate::otp::{now_unix, OtpEntry, OtpType};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// One `otpauth://` URI per line — the lingua franca of 2FA apps.
    Uri,
    Json,
    JsonPretty,
    Csv,
    /// Human-readable aligned table.
    Table,
    /// Aegis Authenticator plain-JSON import file.
    Aegis,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RenderOptions {
    /// Replace secrets with a placeholder (safe for sharing a screenshot).
    pub redact: bool,
    /// Include the current OTP code in table/JSON output.
    pub with_codes: bool,
}

const REDACTED: &str = "<redacted>";

#[derive(Serialize)]
struct EntryDto {
    issuer: String,
    name: String,
    #[serde(rename = "type")]
    otp_type: String,
    secret: String,
    algorithm: String,
    digits: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    period: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    counter: Option<u64>,
    uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    seconds_remaining: Option<u64>,
}

fn dto(entry: &OtpEntry, opts: RenderOptions) -> Result<EntryDto> {
    // Only read the clock when a code is actually wanted: the wasm build has no
    // business asking for the time just to serialise an entry.
    let (code, remaining) = if opts.with_codes {
        let now = now_unix();
        (
            Some(entry.code_at(now)?),
            match entry.otp_type {
                OtpType::Totp => Some(entry.seconds_remaining_at(now)),
                OtpType::Hotp => None,
            },
        )
    } else {
        (None, None)
    };
    Ok(EntryDto {
        issuer: entry.issuer.clone(),
        name: entry.name.clone(),
        otp_type: entry.otp_type.as_str().to_string(),
        secret: if opts.redact {
            REDACTED.to_string()
        } else {
            entry.secret_base32()
        },
        algorithm: entry.algorithm.as_str().to_string(),
        digits: entry.digits,
        period: match entry.otp_type {
            OtpType::Totp => Some(entry.period),
            OtpType::Hotp => None,
        },
        counter: match entry.otp_type {
            OtpType::Hotp => Some(entry.counter),
            OtpType::Totp => None,
        },
        uri: if opts.redact {
            crate::otp::redact_uri(&entry.to_uri())
        } else {
            entry.to_uri()
        },
        code,
        seconds_remaining: remaining,
    })
}

/// The entries as a JSON array — used by the JSON renderer and the HTTP API so
/// both speak exactly the same shape.
pub fn entries_to_value(entries: &[OtpEntry], opts: RenderOptions) -> Result<serde_json::Value> {
    let dtos = entries
        .iter()
        .map(|e| dto(e, opts))
        .collect::<Result<Vec<_>>>()?;
    Ok(serde_json::to_value(dtos)?)
}

pub fn render(entries: &[OtpEntry], format: Format, opts: RenderOptions) -> Result<String> {
    match format {
        Format::Uri => render_uris(entries, opts),
        Format::Json => render_json(entries, opts, false),
        Format::JsonPretty => render_json(entries, opts, true),
        Format::Csv => render_csv(entries, opts),
        Format::Table => render_table(entries, opts),
        Format::Aegis => render_aegis(entries, opts),
    }
}

fn render_uris(entries: &[OtpEntry], opts: RenderOptions) -> Result<String> {
    let mut out = String::new();
    for entry in entries {
        let uri = entry.to_uri();
        let line = if opts.redact {
            crate::otp::redact_uri(&uri)
        } else {
            uri
        };
        out.push_str(&line);
        out.push('\n');
    }
    Ok(out)
}

fn render_json(entries: &[OtpEntry], opts: RenderOptions, pretty: bool) -> Result<String> {
    let value = serde_json::json!({
        "generator": format!("gaexport {}", env!("CARGO_PKG_VERSION")),
        "count": entries.len(),
        "entries": entries_to_value(entries, opts)?,
    });
    let text = if pretty {
        serde_json::to_string_pretty(&value)?
    } else {
        serde_json::to_string(&value)?
    };
    Ok(format!("{text}\n"))
}

fn render_csv(entries: &[OtpEntry], opts: RenderOptions) -> Result<String> {
    let mut writer = csv::Writer::from_writer(Vec::new());
    writer.write_record([
        "issuer",
        "name",
        "type",
        "secret",
        "algorithm",
        "digits",
        "period",
        "counter",
        "uri",
    ])?;
    for entry in entries {
        let d = dto(entry, opts)?;
        writer.write_record([
            d.issuer,
            d.name,
            d.otp_type,
            d.secret,
            d.algorithm,
            d.digits.to_string(),
            d.period.map(|p| p.to_string()).unwrap_or_default(),
            d.counter.map(|c| c.to_string()).unwrap_or_default(),
            d.uri,
        ])?;
    }
    let bytes = writer.into_inner().context("finishing CSV")?;
    String::from_utf8(bytes).context("CSV was not UTF-8")
}

fn render_table(entries: &[OtpEntry], opts: RenderOptions) -> Result<String> {
    let mut headers = vec!["#", "ISSUER", "ACCOUNT", "TYPE", "ALGO", "DIG"];
    if opts.with_codes {
        headers.push("CODE");
        headers.push("TTL");
    }
    headers.push("SECRET");

    let mut rows: Vec<Vec<String>> = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let d = dto(entry, opts)?;
        let mut row = vec![
            (index + 1).to_string(),
            if d.issuer.is_empty() {
                "-".into()
            } else {
                d.issuer
            },
            if d.name.is_empty() {
                "-".into()
            } else {
                d.name
            },
            d.otp_type,
            d.algorithm,
            d.digits.to_string(),
        ];
        if opts.with_codes {
            row.push(d.code.unwrap_or_else(|| "-".into()));
            row.push(match d.seconds_remaining {
                Some(secs) => format!("{secs}s"),
                None => format!("c={}", d.counter.unwrap_or(0)),
            });
        }
        row.push(d.secret);
        rows.push(row);
    }

    let widths: Vec<usize> = headers
        .iter()
        .enumerate()
        .map(|(col, header)| {
            rows.iter()
                .map(|r| display_width(&r[col]))
                .chain(std::iter::once(display_width(header)))
                .max()
                .unwrap_or(0)
        })
        .collect();

    let mut out = String::new();
    for (col, header) in headers.iter().enumerate() {
        pad(&mut out, header, widths[col], col + 1 == headers.len());
    }
    out.push('\n');
    for (col, width) in widths.iter().enumerate() {
        pad(
            &mut out,
            &"─".repeat(*width),
            *width,
            col + 1 == widths.len(),
        );
    }
    out.push('\n');
    for row in &rows {
        for (col, cell) in row.iter().enumerate() {
            pad(&mut out, cell, widths[col], col + 1 == row.len());
        }
        out.push('\n');
    }
    Ok(out)
}

fn pad(out: &mut String, cell: &str, width: usize, last: bool) {
    out.push_str(cell);
    if !last {
        let gap = width.saturating_sub(display_width(cell)) + 2;
        out.push_str(&" ".repeat(gap));
    }
}

/// Approximate terminal width: CJK and emoji occupy two cells.
fn display_width(s: &str) -> usize {
    s.chars()
        .map(|c| {
            let cp = c as u32;
            let wide = (0x1100..=0x115F).contains(&cp)
                || (0x2E80..=0xA4CF).contains(&cp)
                || (0xAC00..=0xD7A3).contains(&cp)
                || (0xF900..=0xFAFF).contains(&cp)
                || (0xFE30..=0xFE6F).contains(&cp)
                || (0xFF00..=0xFF60).contains(&cp)
                || (0xFFE0..=0xFFE6).contains(&cp)
                || (0x1F300..=0x1FAFF).contains(&cp);
            if wide {
                2
            } else {
                1
            }
        })
        .sum()
}

/// Aegis Authenticator's unencrypted export format (`db.version` 3), which it
/// accepts directly on import.
fn render_aegis(entries: &[OtpEntry], opts: RenderOptions) -> Result<String> {
    let items: Vec<serde_json::Value> = entries
        .iter()
        .map(|entry| {
            let mut info = serde_json::json!({
                "secret": if opts.redact { REDACTED.to_string() } else { entry.secret_base32() },
                "algo": entry.algorithm.as_str(),
                "digits": entry.digits,
            });
            match entry.otp_type {
                OtpType::Totp => info["period"] = serde_json::json!(entry.period),
                OtpType::Hotp => info["counter"] = serde_json::json!(entry.counter),
            }
            serde_json::json!({
                "type": entry.otp_type.as_str(),
                "uuid": stable_uuid(&entry.fingerprint()),
                "name": entry.name,
                "issuer": entry.issuer,
                "note": "",
                "favorite": false,
                "icon": serde_json::Value::Null,
                "info": info,
            })
        })
        .collect();
    let doc = serde_json::json!({
        "version": 1,
        "header": { "slots": serde_json::Value::Null, "params": serde_json::Value::Null },
        "db": { "version": 3, "entries": items },
    });
    let mut text = serde_json::to_string_pretty(&doc)?;
    text.push('\n');
    Ok(text)
}

/// A UUID derived from the entry itself rather than from a random source.
///
/// Aegis only needs the id to be unique, and deriving it keeps exports
/// reproducible (re-running the tool produces a byte-identical file) and keeps
/// the WebAssembly build free of a random-number backend.
fn stable_uuid(seed: &str) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(seed.as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4 shape
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // RFC 4122 variant
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// Writes to a file with owner-only permissions, because the contents are keys.
pub fn write_secret_file(path: &std::path::Path, contents: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    file.write_all(contents)
        .with_context(|| format!("writing {}", path.display()))?;
    file.flush()?;
    Ok(())
}

/// A one-line summary for stderr — counts only, never secrets.
pub fn summary(entries: &[OtpEntry]) -> String {
    let totp = entries
        .iter()
        .filter(|e| e.otp_type == OtpType::Totp)
        .count();
    let hotp = entries.len() - totp;
    let mut s = format!(
        "{} key{}",
        entries.len(),
        if entries.len() == 1 { "" } else { "s" }
    );
    let _ = write!(s, " ({totp} TOTP");
    if hotp > 0 {
        let _ = write!(s, ", {hotp} HOTP");
    }
    s.push(')');
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::otp::Algorithm;

    fn entries() -> Vec<OtpEntry> {
        vec![
            OtpEntry {
                secret: zeroize::Zeroizing::new(b"12345678901234567890".to_vec()),
                name: "alice@example.com".into(),
                issuer: "ACME Co".into(),
                ..Default::default()
            },
            OtpEntry {
                secret: zeroize::Zeroizing::new(b"12345678901234567890".to_vec()),
                name: "运维账号".into(),
                issuer: "Bank".into(),
                algorithm: Algorithm::Sha512,
                digits: 8,
                otp_type: OtpType::Hotp,
                counter: 3,
                period: 30,
            },
        ]
    }

    #[test]
    fn uri_output_is_one_line_each() {
        let out = render(&entries(), Format::Uri, RenderOptions::default()).unwrap();
        assert_eq!(out.lines().count(), 2);
        assert!(out.lines().all(|l| l.starts_with("otpauth://")));
    }

    #[test]
    fn json_output_is_parseable_and_complete() {
        let out = render(&entries(), Format::Json, RenderOptions::default()).unwrap();
        let value: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(value["count"], 2);
        let first = &value["entries"][0];
        assert_eq!(first["issuer"], "ACME Co");
        assert_eq!(first["period"], 30);
        assert!(first["counter"].is_null());
        let second = &value["entries"][1];
        assert_eq!(second["counter"], 3);
        assert_eq!(second["algorithm"], "SHA512");
    }

    #[test]
    fn redaction_removes_every_secret() {
        let secret = entries()[0].secret_base32();
        for format in [
            Format::Uri,
            Format::Json,
            Format::JsonPretty,
            Format::Csv,
            Format::Table,
            Format::Aegis,
        ] {
            let out = render(
                &entries(),
                format,
                RenderOptions {
                    redact: true,
                    with_codes: true,
                },
            )
            .unwrap();
            assert!(!out.contains(&secret), "{format:?} leaked the secret");
        }
    }

    #[test]
    fn csv_has_a_header_and_a_row_per_entry() {
        let out = render(&entries(), Format::Csv, RenderOptions::default()).unwrap();
        let mut reader = csv::Reader::from_reader(out.as_bytes());
        let headers = reader.headers().unwrap().clone();
        assert_eq!(&headers[0], "issuer");
        assert_eq!(reader.records().count(), 2);
    }

    #[test]
    fn table_columns_line_up_with_wide_characters() {
        let out = render(
            &entries(),
            Format::Table,
            RenderOptions {
                with_codes: true,
                ..Default::default()
            },
        )
        .unwrap();
        // The final column is ragged by design, so compare where it starts:
        // that offset must be identical on every line, CJK account names
        // included.
        let offsets: Vec<usize> = out
            .lines()
            .map(|line| {
                let gap = line.rfind("  ").expect("every line has a column gap");
                display_width(&line[..gap])
            })
            .collect();
        assert!(
            offsets.windows(2).all(|w| w[0] == w[1]),
            "{out}\n{offsets:?}"
        );
        assert!(out.contains("CODE"));
    }

    #[test]
    fn aegis_export_matches_the_import_schema() {
        let out = render(&entries(), Format::Aegis, RenderOptions::default()).unwrap();
        let value: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(value["db"]["version"], 3);
        let first = &value["db"]["entries"][0];
        assert_eq!(first["type"], "totp");
        assert_eq!(first["info"]["algo"], "SHA1");
        assert_eq!(first["info"]["period"], 30);
        assert!(first["uuid"].as_str().unwrap().len() >= 36);
        assert_eq!(value["db"]["entries"][1]["info"]["counter"], 3);
    }

    #[test]
    fn summary_counts_both_types() {
        assert_eq!(summary(&entries()), "2 keys (1 TOTP, 1 HOTP)");
    }

    #[test]
    fn stable_uuids_are_wellformed_and_deterministic() {
        let a = stable_uuid("account-one");
        let b = stable_uuid("account-two");
        assert_eq!(a, stable_uuid("account-one"));
        assert_ne!(a, b);
        assert_eq!(a.len(), 36);
        assert_eq!(a.chars().filter(|c| *c == '-').count(), 4);
        assert_eq!(&a[14..15], "4", "version nibble: {a}");
        assert!("89ab".contains(&a[19..20]), "variant nibble: {a}");
    }

    #[cfg(unix)]
    #[test]
    fn secret_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("gaexport-test-{}", stable_uuid("perm-test")));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("keys.txt");
        write_secret_file(&path, b"secret data").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "mode was {:o}", mode & 0o777);
        std::fs::remove_dir_all(&dir).ok();
    }
}
