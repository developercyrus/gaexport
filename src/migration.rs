//! Google Authenticator's export format: `otpauth-migration://offline?data=…`
//!
//! The `data` parameter is a base64-encoded protobuf `MigrationPayload`:
//!
//! ```proto
//! message MigrationPayload {
//!   message OtpParameters {
//!     bytes  secret    = 1;
//!     string name      = 2;
//!     string issuer    = 3;
//!     Algorithm  algorithm = 4;   // 1=SHA1 2=SHA256 3=SHA512 4=MD5
//!     DigitCount digits    = 5;   // 1=six 2=eight
//!     OtpType    type      = 6;   // 1=HOTP 2=TOTP
//!     int64  counter   = 7;
//!   }
//!   repeated OtpParameters otp_parameters = 1;
//!   int32 version     = 2;
//!   int32 batch_size  = 3;
//!   int32 batch_index = 4;
//!   int32 batch_id    = 5;
//! }
//! ```

use anyhow::{anyhow, bail, Context, Result};
use data_encoding::{BASE64, BASE64URL, BASE64URL_NOPAD, BASE64_NOPAD};
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};

use crate::otp::{Algorithm, OtpEntry, OtpType, SplitUri, DEFAULT_PERIOD};
use crate::proto::{Reader, Writer, WIRE_LEN, WIRE_VARINT};

pub const SCHEME: &str = "otpauth-migration";
/// Google Authenticator only ever emits `offline`, but we accept any authority.
pub const DEFAULT_AUTHORITY: &str = "offline";
/// Conservative payload budget per QR code. A version-40 code holds 2953 bytes
/// at the lowest error correction level; staying well below that keeps codes
/// scannable from a phone camera on a normal screen.
pub const DEFAULT_MAX_URI_BYTES: usize = 1800;
pub const DEFAULT_MAX_PER_BATCH: usize = 10;

/// `data` is percent-encoded aggressively so `+`, `/` and `=` survive copy-paste.
const DATA_ENCODE: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'_').remove(b'.');

#[derive(Debug, Default)]
pub struct MigrationPayload {
    pub entries: Vec<OtpEntry>,
    pub version: i32,
    pub batch_size: i32,
    pub batch_index: i32,
    pub batch_id: i32,
}

/// Decodes a raw protobuf `MigrationPayload`.
pub fn decode_payload(bytes: &[u8]) -> Result<MigrationPayload> {
    let mut payload = MigrationPayload::default();
    let mut reader = Reader::new(bytes);
    while !reader.is_empty() {
        let (field, wire) = reader.tag()?;
        match (field, wire) {
            (1, WIRE_LEN) => {
                let body = reader.bytes()?;
                payload
                    .entries
                    .push(decode_parameters(body).context("decoding otp_parameters")?);
            }
            (2, WIRE_VARINT) => payload.version = reader.varint()? as i32,
            (3, WIRE_VARINT) => payload.batch_size = reader.varint()? as i32,
            (4, WIRE_VARINT) => payload.batch_index = reader.varint()? as i32,
            (5, WIRE_VARINT) => payload.batch_id = reader.varint()? as i32,
            (_, wire) => reader.skip(wire)?,
        }
    }
    if payload.entries.is_empty() {
        bail!("payload decoded but contained no OTP parameters");
    }
    Ok(payload)
}

fn decode_parameters(bytes: &[u8]) -> Result<OtpEntry> {
    let mut entry = OtpEntry {
        period: DEFAULT_PERIOD, // never present in the payload; TOTP is always 30s here
        ..Default::default()
    };
    let mut reader = Reader::new(bytes);
    while !reader.is_empty() {
        let (field, wire) = reader.tag()?;
        match (field, wire) {
            (1, WIRE_LEN) => entry.secret = zeroize::Zeroizing::new(reader.bytes()?.to_vec()),
            (2, WIRE_LEN) => entry.name = reader.string()?,
            (3, WIRE_LEN) => entry.issuer = reader.string()?,
            (4, WIRE_VARINT) => entry.algorithm = Algorithm::from_proto(reader.varint()?),
            (5, WIRE_VARINT) => {
                entry.digits = if reader.varint()? == 2 { 8 } else { 6 };
            }
            (6, WIRE_VARINT) => entry.otp_type = OtpType::from_proto(reader.varint()?),
            (7, WIRE_VARINT) => entry.counter = reader.varint()?,
            (_, wire) => reader.skip(wire)?,
        }
    }
    // Exported labels are often already `Issuer:account`; split so downstream
    // output does not double up the issuer.
    if entry.issuer.is_empty() {
        if let Some((issuer, name)) = entry.name.clone().split_once(':') {
            entry.issuer = issuer.trim().to_string();
            entry.name = name.trim().to_string();
        }
    } else if let Some(rest) = entry
        .name
        .strip_prefix(&format!("{}:", entry.issuer))
        .map(str::to_string)
    {
        entry.name = rest.trim().to_string();
    }
    entry.validate()?;
    Ok(entry)
}

/// Encodes one batch into a raw protobuf `MigrationPayload`.
pub fn encode_payload(
    entries: &[OtpEntry],
    batch_size: i32,
    batch_index: i32,
    batch_id: i32,
) -> Vec<u8> {
    let mut w = Writer::new();
    for entry in entries {
        let mut inner = Writer::new();
        inner.bytes_field(1, &entry.secret);
        inner.string_field(2, &entry.label());
        inner.string_field(3, &entry.issuer);
        inner.uint_field(4, entry.algorithm.proto_value());
        inner.uint_field(5, if entry.digits == 8 { 2 } else { 1 });
        inner.uint_field(6, entry.otp_type.proto_value());
        if entry.otp_type == OtpType::Hotp {
            inner.uint_field(7, entry.counter);
        }
        w.message_field(1, &inner.into_inner());
    }
    w.int_field(2, 1); // version
    w.int_field(3, i64::from(batch_size));
    w.int_field(4, i64::from(batch_index));
    w.int_field(5, i64::from(batch_id));
    w.into_inner()
}

/// True when the string looks like an export URI (cheap check for scanners).
pub fn is_migration_uri(s: &str) -> bool {
    s.trim_start().to_ascii_lowercase().starts_with(SCHEME)
}

/// Parses `otpauth-migration://offline?data=…` into a payload.
pub fn parse_uri(uri: &str) -> Result<MigrationPayload> {
    let parts = SplitUri::parse(uri)?;
    if parts.scheme != SCHEME {
        bail!(
            "expected an `{SCHEME}://` URI but got `{}://`",
            parts.scheme
        );
    }
    let raw = parts
        .raw_query_value("data")
        .ok_or_else(|| anyhow!("export URI has no `data` parameter"))?;
    let decoded = percent_encoding::percent_decode_str(raw)
        .decode_utf8()
        .context("`data` parameter is not valid percent-encoded UTF-8")?;
    let bytes = decode_base64_tolerant(&decoded)?;
    decode_payload(&bytes).context("`data` is not a Google Authenticator migration payload")
}

/// Accepts the base64 dialects (and copy-paste damage) seen in the wild:
/// standard/URL-safe alphabets, padded or not, and `+` turned into a space by
/// an over-eager form decoder.
pub fn decode_base64_tolerant(input: &str) -> Result<Vec<u8>> {
    let stripped: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    let candidates = [
        stripped.clone(),
        input.replace(' ', "+").replace(['\n', '\r', '\t'], ""),
    ];
    let mut last_err = None;
    for candidate in candidates.iter() {
        let trimmed = candidate.trim_end_matches('=');
        for attempt in [
            BASE64.decode(candidate.as_bytes()),
            BASE64_NOPAD.decode(trimmed.as_bytes()),
            BASE64URL.decode(candidate.as_bytes()),
            BASE64URL_NOPAD.decode(trimmed.as_bytes()),
        ] {
            match attempt {
                Ok(bytes) if !bytes.is_empty() => return Ok(bytes),
                Ok(_) => {}
                Err(e) => last_err = Some(e),
            }
        }
    }
    match last_err {
        Some(e) => Err(anyhow!("not valid base64: {e}")),
        None => Err(anyhow!("empty base64 payload")),
    }
}

/// Builds one or more export URIs, splitting into batches the same way Google
/// Authenticator does when a single QR code would not hold every account.
pub fn build_uris(
    entries: &[OtpEntry],
    max_per_batch: usize,
    max_uri_bytes: usize,
) -> Result<Vec<String>> {
    if entries.is_empty() {
        bail!("nothing to encode");
    }
    let max_per_batch = max_per_batch.max(1);
    let batches = pack_batches(entries, max_per_batch, max_uri_bytes)?;
    let batch_id = batch_id_for(entries);
    let total = batches.len() as i32;
    Ok(batches
        .iter()
        .enumerate()
        .map(|(index, batch)| {
            let bytes = encode_payload(batch, total, index as i32, batch_id);
            payload_to_uri(&bytes)
        })
        .collect())
}

/// Greedy packing: fill a batch until either the count or the byte budget is hit.
fn pack_batches(
    entries: &[OtpEntry],
    max_per_batch: usize,
    max_uri_bytes: usize,
) -> Result<Vec<Vec<OtpEntry>>> {
    let mut batches: Vec<Vec<OtpEntry>> = Vec::new();
    let mut current: Vec<OtpEntry> = Vec::new();
    for entry in entries {
        let single_len =
            payload_to_uri(&encode_payload(std::slice::from_ref(entry), 1, 0, i32::MAX)).len();
        if single_len > max_uri_bytes {
            bail!(
                "`{}` alone needs {single_len} bytes, more than the {max_uri_bytes}-byte QR budget \
                 (raise --max-bytes)",
                entry.display_name()
            );
        }
        current.push(entry.clone());
        let too_long =
            payload_to_uri(&encode_payload(&current, 1, 0, i32::MAX)).len() > max_uri_bytes;
        if too_long && current.len() > 1 {
            let overflow = current.pop().expect("just pushed");
            batches.push(std::mem::take(&mut current));
            current.push(overflow);
        }
        if current.len() >= max_per_batch {
            batches.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        batches.push(current);
    }
    Ok(batches)
}

pub fn payload_to_uri(payload: &[u8]) -> String {
    format!(
        "{SCHEME}://{DEFAULT_AUTHORITY}?data={}",
        utf8_percent_encode(&BASE64.encode(payload), DATA_ENCODE)
    )
}

/// Google Authenticator picks a random id to group the QR codes of one export;
/// we derive it from the accounts instead. It only needs to be stable across the
/// codes of a single export, and deriving it makes output reproducible.
fn batch_id_for(entries: &[OtpEntry]) -> i32 {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    for entry in entries {
        hasher.update(entry.fingerprint().as_bytes());
        hasher.update([0u8]);
    }
    let digest = hasher.finalize();
    let raw = i32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
    raw.saturating_abs().max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<OtpEntry> {
        vec![
            OtpEntry {
                secret: zeroize::Zeroizing::new(b"12345678901234567890".to_vec()),
                name: "alice@example.com".into(),
                issuer: "ACME Co".into(),
                ..Default::default()
            },
            OtpEntry {
                secret: zeroize::Zeroizing::new(b"hello!\xde\xad\xbe\xef".to_vec()),
                name: "bob".into(),
                issuer: "Bank".into(),
                algorithm: Algorithm::Sha256,
                digits: 8,
                otp_type: OtpType::Hotp,
                counter: 7,
                period: DEFAULT_PERIOD,
            },
        ]
    }

    #[test]
    fn payload_roundtrip() {
        let entries = sample();
        let bytes = encode_payload(&entries, 1, 0, 1234);
        let payload = decode_payload(&bytes).unwrap();
        assert_eq!(payload.version, 1);
        assert_eq!(payload.batch_size, 1);
        assert_eq!(payload.batch_id, 1234);
        assert_eq!(payload.entries.len(), 2);

        let a = &payload.entries[0];
        assert_eq!(a.issuer, "ACME Co");
        assert_eq!(a.name, "alice@example.com");
        assert_eq!(a.secret.as_slice(), entries[0].secret.as_slice());
        assert_eq!(a.digits, 6);
        assert_eq!(a.otp_type, OtpType::Totp);

        let b = &payload.entries[1];
        assert_eq!(b.issuer, "Bank");
        assert_eq!(b.name, "bob");
        assert_eq!(b.algorithm, Algorithm::Sha256);
        assert_eq!(b.digits, 8);
        assert_eq!(b.otp_type, OtpType::Hotp);
        assert_eq!(b.counter, 7);
    }

    #[test]
    fn uri_roundtrip() {
        let uris = build_uris(&sample(), DEFAULT_MAX_PER_BATCH, DEFAULT_MAX_URI_BYTES).unwrap();
        assert_eq!(uris.len(), 1);
        assert!(is_migration_uri(&uris[0]));
        let payload = parse_uri(&uris[0]).unwrap();
        assert_eq!(payload.entries.len(), 2);
        assert_eq!(payload.batch_size, 1);
        assert_eq!(payload.batch_index, 0);
    }

    #[test]
    fn batching_splits_by_count_and_marks_indices() {
        let mut entries = Vec::new();
        for i in 0..7 {
            entries.push(OtpEntry {
                secret: zeroize::Zeroizing::new(b"12345678901234567890".to_vec()),
                name: format!("user{i}@example.com"),
                issuer: "Example".into(),
                ..Default::default()
            });
        }
        let uris = build_uris(&entries, 3, DEFAULT_MAX_URI_BYTES).unwrap();
        assert_eq!(uris.len(), 3);
        let mut seen = Vec::new();
        let mut ids = Vec::new();
        for (i, uri) in uris.iter().enumerate() {
            let payload = parse_uri(uri).unwrap();
            assert_eq!(payload.batch_size, 3);
            assert_eq!(payload.batch_index, i as i32);
            ids.push(payload.batch_id);
            seen.extend(payload.entries.iter().map(|e| e.name.clone()));
        }
        assert_eq!(seen.len(), 7);
        assert!(
            ids.windows(2).all(|w| w[0] == w[1]),
            "batch id must be stable"
        );
    }

    #[test]
    fn batching_splits_by_byte_budget() {
        let entries: Vec<_> = (0..6)
            .map(|i| OtpEntry {
                secret: zeroize::Zeroizing::new(vec![0x41; 32]),
                name: format!("a-very-long-account-name-number-{i}@some-long-domain.example.com"),
                issuer: "Some Long Issuer Name".into(),
                ..Default::default()
            })
            .collect();
        let uris = build_uris(&entries, 100, 400).unwrap();
        assert!(uris.len() > 1, "expected the byte budget to force a split");
        assert!(uris.iter().all(|u| u.len() <= 400 + 64));
        let total: usize = uris
            .iter()
            .map(|u| parse_uri(u).unwrap().entries.len())
            .sum();
        assert_eq!(total, 6);
    }

    #[test]
    fn tolerates_base64_dialects() {
        let payload = encode_payload(&sample(), 1, 0, 9);
        let padded = BASE64.encode(&payload);
        let urlsafe = BASE64URL_NOPAD.encode(&payload);
        let plus_as_space = padded.replace('+', " ");
        for variant in [padded.clone(), urlsafe, plus_as_space] {
            let bytes = decode_base64_tolerant(&variant).unwrap();
            assert_eq!(decode_payload(&bytes).unwrap().entries.len(), 2);
        }
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_uri("otpauth-migration://offline?data=%%%").is_err());
        assert!(parse_uri("otpauth-migration://offline").is_err());
        assert!(parse_uri("otpauth://totp/a?secret=GEZDGNBVGY3TQOJQ").is_err());
        // Valid base64, but not a payload.
        assert!(parse_uri("otpauth-migration://offline?data=aGVsbG8gd29ybGQ%3D").is_err());
    }

    #[test]
    fn hand_built_payload_matches_expected_wire_format() {
        // field 1 (otp_parameters), len 21:
        //   field 1 secret = 4 bytes, field 2 name = "me", field 6 type = 2 (TOTP)
        let wire: &[u8] = &[
            0x0a, 0x0e, // otp_parameters, len 14
            0x0a, 0x04, 0x48, 0x65, 0x6c, 0x6c, // secret = "Hell"
            0x12, 0x02, 0x6d, 0x65, // name = "me"
            0x20, 0x01, // algorithm = SHA1
            0x28, 0x01, // digits = SIX
            0x30, 0x02, // type = TOTP
            0x10, 0x01, // version = 1
        ];
        let payload = decode_payload(wire).unwrap();
        assert_eq!(payload.version, 1);
        assert_eq!(payload.entries.len(), 1);
        let entry = &payload.entries[0];
        assert_eq!(entry.secret.as_slice(), b"Hell");
        assert_eq!(entry.name, "me");
        assert_eq!(entry.digits, 6);
        assert_eq!(entry.otp_type, OtpType::Totp);
        assert_eq!(entry.algorithm, Algorithm::Sha1);
    }
}
