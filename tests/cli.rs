//! End-to-end tests that drive the actual binary, the way a user does.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_gaexport");

const KEYS: &str = "\
otpauth://totp/ACME%20Co:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co
otpauth://totp/GitHub:cluas?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=GitHub&algorithm=SHA256&digits=8
otpauth://hotp/Bank:主账号?secret=KRSXG5CTMVRXEZLU&issuer=Bank&counter=7
";

/// A throwaway directory, named after the test so failures are traceable.
struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("gaexport-it-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        Scratch(dir)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    fn write(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.path(name);
        std::fs::write(&path, contents).expect("write fixture");
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .output()
        .expect("failed to run gaexport")
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn assert_ok(output: &Output) {
    assert!(
        output.status.success(),
        "command failed:\nstdout: {}\nstderr: {}",
        stdout_of(output),
        stderr_of(output)
    );
}

fn png_files(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .expect("read output dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("png"))
        .collect();
    files.sort();
    files
}

#[test]
fn keys_survive_a_full_qr_round_trip() {
    let scratch = Scratch::new("roundtrip");
    let keys = scratch.write("keys.txt", KEYS);
    let out_dir = scratch.path("qr");

    // Pack into Google Authenticator export QR codes, two accounts per code…
    let encode = run(&[
        "encode",
        "-i",
        keys.to_str().unwrap(),
        "--out",
        out_dir.to_str().unwrap(),
        "--per-batch",
        "2",
    ]);
    assert_ok(&encode);
    let images = png_files(&out_dir);
    assert_eq!(images.len(), 2, "expected two batches, got {images:?}");

    // …then read the images back and compare against the input.
    let decode = run(&[
        "decode",
        out_dir.to_str().unwrap(),
        "--format",
        "json",
        "--sort",
    ]);
    assert_ok(&decode);
    let value: serde_json::Value = serde_json::from_str(&stdout_of(&decode)).expect("valid JSON");
    assert_eq!(value["count"], 3);

    let entries = value["entries"].as_array().unwrap();
    let acme = &entries[0];
    assert_eq!(acme["issuer"], "ACME Co");
    assert_eq!(acme["name"], "alice@example.com");
    assert_eq!(acme["secret"], "JBSWY3DPEHPK3PXP");

    let bank = entries
        .iter()
        .find(|e| e["issuer"] == "Bank")
        .expect("HOTP entry survived");
    assert_eq!(bank["type"], "hotp");
    assert_eq!(bank["counter"], 7);
    assert_eq!(bank["name"], "主账号", "non-ASCII names must survive");

    let github = entries
        .iter()
        .find(|e| e["issuer"] == "GitHub")
        .expect("SHA256 entry survived");
    assert_eq!(github["algorithm"], "SHA256");
    assert_eq!(github["digits"], 8);
}

#[test]
fn decode_reads_from_stdin_and_writes_uris() {
    let output = Command::new(BIN)
        .args(["decode", "--stdin", "--quiet"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child
                .stdin
                .as_mut()
                .expect("stdin")
                .write_all(KEYS.as_bytes())?;
            child.wait_with_output()
        })
        .expect("run with piped stdin");
    assert_ok(&output);
    let text = stdout_of(&output);
    let lines: Vec<&str> = text.lines().map(str::trim).collect();
    assert_eq!(lines.len(), 3);
    assert!(lines.iter().all(|l| l.starts_with("otpauth://")));
}

#[test]
fn redacted_output_never_contains_a_secret() {
    let scratch = Scratch::new("redact");
    let keys = scratch.write("keys.txt", KEYS);
    for format in ["uri", "json", "csv", "table", "aegis"] {
        let output = run(&[
            "decode",
            keys.to_str().unwrap(),
            "--redact",
            "--codes",
            "--format",
            format,
        ]);
        assert_ok(&output);
        let text = stdout_of(&output);
        assert!(
            !text.contains("JBSWY3DPEHPK3PXP"),
            "format {format} leaked a secret"
        );
        assert!(text.contains("redacted"), "format {format} lost the marker");
    }
}

#[test]
fn output_files_are_written_with_owner_only_permissions() {
    let scratch = Scratch::new("perms");
    let keys = scratch.write("keys.txt", KEYS);
    let target = scratch.path("out.json");
    let output = run(&[
        "decode",
        keys.to_str().unwrap(),
        "--format",
        "json-pretty",
        "-o",
        target.to_str().unwrap(),
    ]);
    assert_ok(&output);
    let text = std::fs::read_to_string(&target).unwrap();
    assert!(text.contains("JBSWY3DPEHPK3PXP"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&target).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "mode was {:o}", mode & 0o777);
    }
}

#[test]
fn per_account_qr_codes_are_written_and_scannable() {
    let scratch = Scratch::new("qr");
    let keys = scratch.write("keys.txt", KEYS);
    let out_dir = scratch.path("codes");
    let output = run(&[
        "qr",
        keys.to_str().unwrap(),
        "--out",
        out_dir.to_str().unwrap(),
    ]);
    assert_ok(&output);
    let images = png_files(&out_dir);
    assert_eq!(images.len(), 3);
    assert!(
        images[0]
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("01-"),
        "files should be ordered: {images:?}"
    );

    // Reading them back gives the same three accounts.
    let decode = run(&["decode", out_dir.to_str().unwrap(), "--format", "json"]);
    assert_ok(&decode);
    let value: serde_json::Value = serde_json::from_str(&stdout_of(&decode)).unwrap();
    assert_eq!(value["count"], 3);
}

#[test]
fn unreadable_input_fails_with_a_helpful_message() {
    let scratch = Scratch::new("bad");
    let junk = scratch.write("notes.txt", "just some notes, no keys here\n");
    let output = run(&["decode", junk.to_str().unwrap()]);
    assert!(!output.status.success(), "expected a non-zero exit");
    let stderr = stderr_of(&output);
    assert!(stderr.contains("no OTP keys found"), "{stderr}");

    let missing = run(&["decode", "/nonexistent/path.png"]);
    assert!(!missing.status.success());
    assert!(stderr_of(&missing).contains("cannot read"));
}

#[test]
fn a_partial_export_warns_about_the_missing_code() {
    let scratch = Scratch::new("partial");
    let keys = scratch.write("keys.txt", KEYS);
    let out_dir = scratch.path("qr");
    assert_ok(&run(&[
        "encode",
        "-i",
        keys.to_str().unwrap(),
        "--out",
        out_dir.to_str().unwrap(),
        "--per-batch",
        "1",
    ]));

    let first = png_files(&out_dir).remove(0);
    let output = run(&["decode", first.to_str().unwrap()]);
    assert_ok(&output);
    let stderr = stderr_of(&output);
    assert!(stderr.contains("split across 3 QR codes"), "{stderr}");
    assert_eq!(stdout_of(&output).lines().count(), 1);
}

#[test]
fn help_and_completions_work() {
    let help = run(&["--help"]);
    assert_ok(&help);
    let text = stdout_of(&help);
    for command in ["decode", "codes", "qr", "encode", "serve", "completions"] {
        assert!(text.contains(command), "`{command}` missing from --help");
    }

    let bash = run(&["completions", "bash"]);
    assert_ok(&bash);
    assert!(stdout_of(&bash).contains("gaexport"));

    let version = run(&["--version"]);
    assert_ok(&version);
    assert!(stdout_of(&version).contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn codes_are_stable_for_hotp_and_match_the_library() {
    let output = run(&[
        "codes",
        "-u",
        "otpauth://hotp/Bank:main?secret=KRSXG5CTMVRXEZLU&counter=7",
        "--show-secrets",
    ]);
    assert_ok(&output);
    let text = stdout_of(&output);
    // RFC 4226 vector for this key/counter — a fixed expectation, not a snapshot.
    assert!(text.contains("578164"), "{text}");
    assert!(text.contains("KRSXG5CTMVRXEZLU"), "{text}");
}
