//! The OTP key model: `otpauth://` URI parsing/building and RFC 4226 / RFC 6238
//! code generation.

use std::fmt;
#[cfg(not(all(target_arch = "wasm32", feature = "wasm")))]
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use zeroize::Zeroizing;

/// Characters we leave untouched when percent-encoding labels and query values.
const KEEP: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~')
    .remove(b'@');

pub const DEFAULT_PERIOD: u32 = 30;
pub const DEFAULT_DIGITS: u32 = 6;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Algorithm {
    #[default]
    Sha1,
    Sha256,
    Sha512,
    Md5,
}

impl Algorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Algorithm::Sha1 => "SHA1",
            Algorithm::Sha256 => "SHA256",
            Algorithm::Sha512 => "SHA512",
            Algorithm::Md5 => "MD5",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s
            .trim()
            .to_ascii_uppercase()
            .replace(['-', '_'], "")
            .as_str()
        {
            "SHA1" | "" => Ok(Algorithm::Sha1),
            "SHA256" => Ok(Algorithm::Sha256),
            "SHA512" => Ok(Algorithm::Sha512),
            "MD5" => Ok(Algorithm::Md5),
            other => bail!("unsupported algorithm `{other}` (want SHA1, SHA256, SHA512 or MD5)"),
        }
    }

    /// The `Algorithm` enum value used by the migration payload.
    pub fn proto_value(self) -> u64 {
        match self {
            Algorithm::Sha1 => 1,
            Algorithm::Sha256 => 2,
            Algorithm::Sha512 => 3,
            Algorithm::Md5 => 4,
        }
    }

    pub fn from_proto(value: u64) -> Self {
        match value {
            2 => Algorithm::Sha256,
            3 => Algorithm::Sha512,
            4 => Algorithm::Md5,
            // 0 (ALGO_INVALID) and 1 (ALGO_SHA1) both mean SHA1 in practice:
            // Google Authenticator omits the field for its default.
            _ => Algorithm::Sha1,
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OtpType {
    #[default]
    Totp,
    Hotp,
}

impl OtpType {
    pub fn as_str(self) -> &'static str {
        match self {
            OtpType::Totp => "totp",
            OtpType::Hotp => "hotp",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "totp" => Ok(OtpType::Totp),
            "hotp" => Ok(OtpType::Hotp),
            other => bail!("unsupported OTP type `{other}` (want totp or hotp)"),
        }
    }

    pub fn proto_value(self) -> u64 {
        match self {
            OtpType::Hotp => 1,
            OtpType::Totp => 2,
        }
    }

    pub fn from_proto(value: u64) -> Self {
        match value {
            1 => OtpType::Hotp,
            _ => OtpType::Totp,
        }
    }
}

impl fmt::Display for OtpType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One OTP key. `secret` holds the raw (already base32-decoded) shared secret
/// in a `Zeroizing` buffer, so it is wiped from memory when the entry is
/// dropped rather than left lying around in the allocator.
#[derive(Clone, Debug)]
pub struct OtpEntry {
    pub secret: Zeroizing<Vec<u8>>,
    pub name: String,
    pub issuer: String,
    pub algorithm: Algorithm,
    pub digits: u32,
    pub otp_type: OtpType,
    pub counter: u64,
    pub period: u32,
}

impl Default for OtpEntry {
    fn default() -> Self {
        OtpEntry {
            secret: Zeroizing::new(Vec::new()),
            name: String::new(),
            issuer: String::new(),
            algorithm: Algorithm::Sha1,
            digits: DEFAULT_DIGITS,
            otp_type: OtpType::Totp,
            counter: 0,
            period: DEFAULT_PERIOD,
        }
    }
}

impl OtpEntry {
    pub fn secret_base32(&self) -> String {
        BASE32_NOPAD.encode(&self.secret)
    }

    /// `Issuer:account`, or just the account when no issuer is known.
    pub fn label(&self) -> String {
        if self.issuer.is_empty() {
            self.name.clone()
        } else if self.name.is_empty() {
            self.issuer.clone()
        } else if self
            .name
            .to_lowercase()
            .starts_with(&format!("{}:", self.issuer.to_lowercase()))
        {
            // Some exports already carry `Issuer:account` in the name field.
            self.name.clone()
        } else {
            format!("{}:{}", self.issuer, self.name)
        }
    }

    /// A short human label used in tables and logs — never contains the secret.
    pub fn display_name(&self) -> String {
        let label = self.label();
        if label.is_empty() {
            "<unnamed>".to_string()
        } else {
            label
        }
    }

    /// Renders the standard Key-Uri-Format string.
    ///
    /// The `Issuer:account` separator stays a literal `:` — that is what Google
    /// Authenticator itself emits, and a few importers choke on `%3A`.
    pub fn to_uri(&self) -> String {
        let label = match (self.issuer.is_empty(), self.name.is_empty()) {
            (false, false) => format!(
                "{}:{}",
                utf8_percent_encode(&self.issuer, KEEP),
                utf8_percent_encode(&self.name, KEEP)
            ),
            _ => utf8_percent_encode(&self.label(), KEEP).to_string(),
        };
        let mut uri = format!(
            "otpauth://{}/{}?secret={}",
            self.otp_type.as_str(),
            label,
            self.secret_base32(),
        );
        if !self.issuer.is_empty() {
            uri.push_str("&issuer=");
            uri.push_str(&utf8_percent_encode(&self.issuer, KEEP).to_string());
        }
        if self.algorithm != Algorithm::Sha1 {
            uri.push_str("&algorithm=");
            uri.push_str(self.algorithm.as_str());
        }
        if self.digits != DEFAULT_DIGITS {
            uri.push_str(&format!("&digits={}", self.digits));
        }
        match self.otp_type {
            OtpType::Totp => {
                if self.period != DEFAULT_PERIOD {
                    uri.push_str(&format!("&period={}", self.period));
                }
            }
            OtpType::Hotp => uri.push_str(&format!("&counter={}", self.counter)),
        }
        uri
    }

    /// Parses an `otpauth://totp/...` / `otpauth://hotp/...` URI.
    pub fn from_uri(input: &str) -> Result<Self> {
        let parts = SplitUri::parse(input)?;
        if parts.scheme != "otpauth" {
            bail!("not an otpauth:// URI (scheme was `{}`)", parts.scheme);
        }
        let otp_type = OtpType::parse(&parts.authority)
            .with_context(|| format!("in URI `{}`", redact_uri(input)))?;

        let label = percent_decode_str(parts.path.trim_start_matches('/'))
            .decode_utf8_lossy()
            .into_owned();
        let (mut issuer, name) = match label.split_once(':') {
            Some((i, n)) => (i.trim().to_string(), n.trim().to_string()),
            None => (String::new(), label.trim().to_string()),
        };

        let mut entry = OtpEntry {
            name,
            otp_type,
            ..Default::default()
        };
        let mut has_secret = false;
        let mut has_counter = false;

        for (key, value) in parts.query_pairs() {
            match key.to_ascii_lowercase().as_str() {
                "secret" => {
                    entry.secret = Zeroizing::new(decode_secret(&value)?);
                    has_secret = true;
                }
                "issuer" => {
                    if !value.trim().is_empty() {
                        issuer = value.trim().to_string();
                    }
                }
                "algorithm" => entry.algorithm = Algorithm::parse(&value)?,
                "digits" => {
                    entry.digits = value
                        .trim()
                        .parse::<u32>()
                        .with_context(|| format!("invalid digits `{value}`"))?;
                }
                "period" => {
                    entry.period = value
                        .trim()
                        .parse::<u32>()
                        .with_context(|| format!("invalid period `{value}`"))?;
                }
                "counter" => {
                    entry.counter = value
                        .trim()
                        .parse::<u64>()
                        .with_context(|| format!("invalid counter `{value}`"))?;
                    has_counter = true;
                }
                // Unknown parameters (image=, encoder=, lock=, ...) are ignored.
                _ => {}
            }
        }

        entry.issuer = issuer;
        if !has_secret || entry.secret.is_empty() {
            bail!("URI has no `secret` parameter: {}", redact_uri(input));
        }
        if entry.otp_type == OtpType::Hotp && !has_counter {
            // RFC says counter is required; be forgiving and start at 0.
            entry.counter = 0;
        }
        entry.validate()?;
        Ok(entry)
    }

    pub fn validate(&self) -> Result<()> {
        if self.secret.is_empty() {
            bail!("`{}` has an empty secret", self.display_name());
        }
        if !(1..=10).contains(&self.digits) {
            bail!(
                "`{}` has an unsupported digit count {} (want 1-10)",
                self.display_name(),
                self.digits
            );
        }
        if self.otp_type == OtpType::Totp && self.period == 0 {
            bail!("`{}` has period 0", self.display_name());
        }
        Ok(())
    }

    /// The current code (TOTP: for the current time step; HOTP: for `counter`).
    pub fn code(&self) -> Result<String> {
        self.code_at(now_unix())
    }

    pub fn code_at(&self, unix_secs: u64) -> Result<String> {
        let counter = match self.otp_type {
            OtpType::Totp => unix_secs / u64::from(self.period.max(1)),
            OtpType::Hotp => self.counter,
        };
        Ok(hotp(self.algorithm, &self.secret, counter, self.digits))
    }

    /// Seconds until the current TOTP step rolls over (0 for HOTP).
    pub fn seconds_remaining_at(&self, unix_secs: u64) -> u64 {
        match self.otp_type {
            OtpType::Totp => {
                let period = u64::from(self.period.max(1));
                period - (unix_secs % period)
            }
            OtpType::Hotp => 0,
        }
    }

    pub fn seconds_remaining(&self) -> u64 {
        self.seconds_remaining_at(now_unix())
    }

    /// Identity used to de-duplicate entries collected from several QR codes.
    pub fn fingerprint(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}|{}|{}",
            self.otp_type.as_str(),
            self.secret_base32(),
            self.issuer.to_lowercase(),
            self.name.to_lowercase(),
            self.algorithm.as_str(),
            self.digits,
            self.period
        )
    }
}

/// Accepts base32 with or without padding, spaces, dashes or lowercase — the
/// shapes people actually paste.
pub fn decode_secret(raw: &str) -> Result<Vec<u8>> {
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '=')
        .collect::<String>()
        .to_ascii_uppercase();
    if cleaned.is_empty() {
        bail!("empty secret");
    }
    BASE32_NOPAD
        .decode(cleaned.as_bytes())
        .map_err(|e| anyhow!("secret is not valid base32: {e}"))
}

/// RFC 4226 HOTP with the truncation offset taken from the last nibble.
pub fn hotp(algorithm: Algorithm, key: &[u8], counter: u64, digits: u32) -> String {
    let mac = hmac_bytes(algorithm, key, &counter.to_be_bytes());
    let offset = (mac[mac.len() - 1] & 0x0f) as usize;
    let binary = (u64::from(mac[offset] & 0x7f) << 24)
        | (u64::from(mac[offset + 1]) << 16)
        | (u64::from(mac[offset + 2]) << 8)
        | u64::from(mac[offset + 3]);
    let digits = digits.clamp(1, 10);
    let modulus = 10u64.pow(digits);
    format!("{:0width$}", binary % modulus, width = digits as usize)
}

fn hmac_bytes(algorithm: Algorithm, key: &[u8], msg: &[u8]) -> Vec<u8> {
    // A macro rather than a generic function: spelling out the RustCrypto trait
    // bounds for "any digest usable with HMAC" is far noisier than four arms.
    macro_rules! run {
        ($digest:ty) => {{
            // `new_from_slice` only rejects key *sizes*, and HMAC accepts keys
            // of any length, so this cannot fail.
            let mut mac = Hmac::<$digest>::new_from_slice(key).expect("HMAC takes any key length");
            mac.update(msg);
            mac.finalize().into_bytes().to_vec()
        }};
    }
    match algorithm {
        Algorithm::Sha1 => run!(sha1::Sha1),
        Algorithm::Sha256 => run!(sha2::Sha256),
        Algorithm::Sha512 => run!(sha2::Sha512),
        Algorithm::Md5 => run!(md5::Md5),
    }
}

/// Seconds since the Unix epoch.
///
/// `wasm32-unknown-unknown` has no clock, so the wasm build reads the host
/// page's `Date` instead of panicking inside `SystemTime::now()`.
#[cfg(not(all(target_arch = "wasm32", feature = "wasm")))]
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
pub fn now_unix() -> u64 {
    let millis = js_sys::Date::now();
    if millis.is_finite() && millis > 0.0 {
        (millis / 1000.0) as u64
    } else {
        0
    }
}

/// Replaces the `secret=` value in a URI so errors can be logged safely.
pub fn redact_uri(uri: &str) -> String {
    let mut out = String::with_capacity(uri.len());
    let mut rest = uri;
    while let Some(idx) = rest.to_lowercase().find("secret=") {
        let (head, tail) = rest.split_at(idx + "secret=".len());
        out.push_str(head);
        out.push_str("<redacted>");
        rest = match tail.find('&') {
            Some(amp) => &tail[amp..],
            None => "",
        };
    }
    out.push_str(rest);
    out
}

/// A deliberately forgiving URI splitter. `url::Url` would work, but people
/// paste half-broken strings out of terminals and screenshots, and this keeps
/// `+` in query values intact (form decoding would turn it into a space).
pub struct SplitUri {
    pub scheme: String,
    pub authority: String,
    pub path: String,
    pub query: String,
}

impl SplitUri {
    pub fn parse(input: &str) -> Result<Self> {
        let trimmed = input.trim().trim_matches(|c| c == '"' || c == '\'');
        let (scheme, rest) = trimmed
            .split_once("://")
            .ok_or_else(|| anyhow!("`{}` is not a URI", truncate(trimmed, 40)))?;
        let (before_query, query) = match rest.split_once('?') {
            Some((a, b)) => (a, b),
            None => (rest, ""),
        };
        let (authority, path) = match before_query.split_once('/') {
            Some((a, b)) => (a, b),
            None => (before_query, ""),
        };
        Ok(SplitUri {
            scheme: scheme.trim().to_ascii_lowercase(),
            authority: authority.to_string(),
            path: path.to_string(),
            query: query.to_string(),
        })
    }

    /// Percent-decoded `key=value` pairs. Unlike form decoding, `+` is kept as
    /// a literal plus — base64 payloads depend on it.
    pub fn query_pairs(&self) -> Vec<(String, String)> {
        self.query
            .split('&')
            .filter(|s| !s.is_empty())
            .map(|pair| {
                let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
                (
                    percent_decode_str(k).decode_utf8_lossy().into_owned(),
                    percent_decode_str(v).decode_utf8_lossy().into_owned(),
                )
            })
            .collect()
    }

    /// Raw (still percent-encoded) value of a query parameter.
    pub fn raw_query_value(&self, key: &str) -> Option<&str> {
        self.query.split('&').find_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            (k.eq_ignore_ascii_case(key)).then_some(v)
        })
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(max).collect::<String>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC_SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn rfc4226_hotp_vectors() {
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        for (counter, want) in expected.iter().enumerate() {
            assert_eq!(
                &hotp(Algorithm::Sha1, RFC_SECRET, counter as u64, 6),
                want,
                "counter {counter}"
            );
        }
    }

    #[test]
    fn rfc6238_totp_sha1_vectors() {
        let entry = OtpEntry {
            secret: Zeroizing::new(RFC_SECRET.to_vec()),
            digits: 8,
            ..Default::default()
        };
        for (time, want) in [
            (59u64, "94287082"),
            (1_111_111_109, "07081804"),
            (1_111_111_111, "14050471"),
            (1_234_567_890, "89005924"),
            (2_000_000_000, "69279037"),
            (20_000_000_000, "65353130"),
        ] {
            assert_eq!(entry.code_at(time).unwrap(), want, "t={time}");
        }
    }

    #[test]
    fn rfc6238_totp_sha256_and_sha512_vectors() {
        let sha256 = OtpEntry {
            secret: Zeroizing::new(b"12345678901234567890123456789012".to_vec()),
            algorithm: Algorithm::Sha256,
            digits: 8,
            ..Default::default()
        };
        for (time, want) in [
            (59u64, "46119246"),
            (1_111_111_109, "68084774"),
            (20_000_000_000, "77737706"),
        ] {
            assert_eq!(sha256.code_at(time).unwrap(), want, "sha256 t={time}");
        }

        let sha512 = OtpEntry {
            secret: Zeroizing::new(
                b"1234567890123456789012345678901234567890123456789012345678901234".to_vec(),
            ),
            algorithm: Algorithm::Sha512,
            digits: 8,
            ..Default::default()
        };
        for (time, want) in [
            (59u64, "90693936"),
            (1_111_111_109, "25091201"),
            (20_000_000_000, "47863826"),
        ] {
            assert_eq!(sha512.code_at(time).unwrap(), want, "sha512 t={time}");
        }
    }

    #[test]
    fn label_separator_is_a_literal_colon() {
        let entry = OtpEntry {
            secret: Zeroizing::new(b"12345678901234567890".to_vec()),
            issuer: "ACME Co".into(),
            name: "alice@example.com".into(),
            ..Default::default()
        };
        let uri = entry.to_uri();
        assert!(uri.contains("/ACME%20Co:alice@example.com?"), "{uri}");
        assert_eq!(OtpEntry::from_uri(&uri).unwrap().name, "alice@example.com");
    }

    #[test]
    fn uri_roundtrip() {
        let uri = "otpauth://totp/ACME%20Co:john.doe%40email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60";
        let entry = OtpEntry::from_uri(uri).unwrap();
        assert_eq!(entry.issuer, "ACME Co");
        assert_eq!(entry.name, "john.doe@email.com");
        assert_eq!(entry.algorithm, Algorithm::Sha256);
        assert_eq!(entry.digits, 8);
        assert_eq!(entry.period, 60);

        let again = OtpEntry::from_uri(&entry.to_uri()).unwrap();
        assert_eq!(again.fingerprint(), entry.fingerprint());
    }

    #[test]
    fn hotp_uri_keeps_counter() {
        let entry = OtpEntry::from_uri("otpauth://hotp/Bank:me?secret=GEZDGNBVGY3TQOJQ&counter=42")
            .unwrap();
        assert_eq!(entry.otp_type, OtpType::Hotp);
        assert_eq!(entry.counter, 42);
        assert!(entry.to_uri().contains("counter=42"));
        assert_eq!(entry.code_at(0).unwrap(), entry.code_at(999).unwrap());
    }

    #[test]
    fn tolerant_secret_decoding() {
        let spaced = decode_secret("gezd gnbv-gy3t qojq==").unwrap();
        let plain = decode_secret("GEZDGNBVGY3TQOJQ").unwrap();
        assert_eq!(spaced, plain);
        assert!(decode_secret("not base32 !!").is_err());
    }

    #[test]
    fn label_without_issuer() {
        let entry = OtpEntry::from_uri("otpauth://totp/alice?secret=GEZDGNBVGY3TQOJQ").unwrap();
        assert_eq!(entry.issuer, "");
        assert_eq!(entry.name, "alice");
        assert_eq!(entry.label(), "alice");
    }

    #[test]
    fn redaction_hides_secret() {
        let out = redact_uri("otpauth://totp/a?secret=SUPERSECRET&issuer=x");
        assert!(!out.contains("SUPERSECRET"), "{out}");
        assert!(out.contains("issuer=x"));
    }

    #[test]
    fn rejects_missing_secret() {
        assert!(OtpEntry::from_uri("otpauth://totp/a?issuer=x").is_err());
        assert!(OtpEntry::from_uri("https://example.com").is_err());
    }
}
