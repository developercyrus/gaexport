//! Command-line surface and dispatch.

use std::io::{IsTerminal, Write};
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};

use crate::input::{self, InputSpec};
use crate::migration;
use crate::otp::OtpEntry;
use crate::output::{self, Format, RenderOptions};
use crate::qr;

const AFTER_HELP: &str = "\x1b[1mExamples\x1b[0m
  # Screenshot Google Authenticator's export QR code, then:
  gaexport decode ~/Desktop/export.png

  # Several codes at once (GA splits large exports), as a readable table:
  gaexport decode ~/Desktop/qr-*.png --format table

  # Paste the URI instead of a screenshot:
  gaexport decode -u 'otpauth-migration://offline?data=CjE...'

  # Live codes in the terminal, refreshing every second:
  gaexport codes export.png --watch

  # Browser UI on localhost (nothing is written to disk, nothing leaves the box):
  gaexport serve

  # Move keys into another app: per-account QR codes, or one import file
  gaexport qr export.png --out ./qrcodes
  gaexport decode export.png --format aegis -o aegis-import.json

  # Re-pack keys into Google Authenticator's own export codes:
  gaexport encode -i keys.txt --out ./ga-import

\x1b[1mHandling secrets\x1b[0m
  Output contains the raw 2FA secrets: anyone holding them can generate your
  codes forever. Prefer piping into a password manager over leaving files
  around, use --redact when sharing output, and remember shell history keeps
  whatever you pass to --uri.";

#[derive(Parser, Debug)]
#[command(
    name = "gaexport",
    version,
    about = "Export, inspect and re-import Google Authenticator OTP secrets",
    long_about = "Decodes Google Authenticator's `otpauth-migration://` export QR codes into \
plain otpauth:// URIs, JSON, CSV or an import file for another authenticator — and packs keys \
back into export QR codes. Runs entirely offline; it makes no network requests of its own.",
    after_long_help = AFTER_HELP,
    max_term_width = 100,
    // `gaexport shot.png` means `gaexport decode shot.png`: decoding is what
    // people came for, so it should not need a subcommand.
    args_conflicts_with_subcommands = true,
    subcommand_negates_reqs = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Decode arguments, used when no subcommand is given
    #[command(flatten)]
    pub decode: DecodeArgs,

    /// Suppress the progress/summary lines on stderr
    #[arg(short, long, global = true)]
    pub quiet: bool,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Decode export QR codes / URIs into OTP keys (the default when omitted)
    #[command(visible_alias = "export", visible_alias = "d")]
    Decode(DecodeArgs),

    /// Show live OTP codes for the decoded keys
    #[command(visible_alias = "totp")]
    Codes(CodesArgs),

    /// Write one QR code per account, for importing into any authenticator app
    Qr(QrArgs),

    /// Pack keys back into Google Authenticator export QR codes
    #[command(visible_alias = "import")]
    Encode(EncodeArgs),

    /// Serve the browser UI on localhost
    #[cfg(feature = "server")]
    Serve(crate::server::ServeArgs),

    /// Print a shell completion script
    Completions {
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
}

/// Input sources, shared by every command that reads keys.
#[derive(Args, Debug, Clone, Default)]
pub struct InputArgs {
    /// QR image, text file, directory, `otpauth…` URI, or `-` for stdin
    #[arg(value_name = "PATH|URI")]
    pub targets: Vec<String>,

    /// Explicit input path (repeatable); same as a positional path
    #[arg(short = 'i', long = "input", value_name = "PATH")]
    pub input: Vec<PathBuf>,

    /// Explicit URI (repeatable). Note: visible in shell history
    #[arg(short = 'u', long = "uri", value_name = "URI")]
    pub uri: Vec<String>,

    /// Read input from stdin even when paths are given
    #[arg(long)]
    pub stdin: bool,
}

impl InputArgs {
    /// True when the user named no input at all.
    pub fn is_bare(&self) -> bool {
        self.targets.is_empty() && self.input.is_empty() && self.uri.is_empty() && !self.stdin
    }

    /// Splits positionals into URIs and paths, and falls back to stdin when the
    /// command is on the receiving end of a pipe.
    pub fn to_spec(&self) -> InputSpec {
        let mut spec = InputSpec {
            paths: self.input.clone(),
            uris: self.uri.clone(),
            stdin: self.stdin,
        };
        for target in &self.targets {
            let lower = target.to_ascii_lowercase();
            if lower.starts_with("otpauth://") || lower.starts_with("otpauth-migration://") {
                spec.uris.push(target.clone());
            } else {
                spec.paths.push(PathBuf::from(target));
            }
        }
        if spec.is_empty() && !std::io::stdin().is_terminal() {
            spec.stdin = true;
        }
        spec
    }
}

#[derive(Args, Debug)]
pub struct DecodeArgs {
    #[command(flatten)]
    pub input: InputArgs,

    /// Output format
    #[arg(short, long, value_enum, default_value_t = OutFormat::Uri)]
    pub format: OutFormat,

    /// Write to a file (created with 0600) instead of stdout
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Replace secrets with `<redacted>` — safe to paste into a bug report
    #[arg(long)]
    pub redact: bool,

    /// Include the current OTP code (json/table formats)
    #[arg(long)]
    pub codes: bool,

    /// Sort by issuer, then account name
    #[arg(long)]
    pub sort: bool,
}

#[derive(Args, Debug)]
pub struct CodesArgs {
    #[command(flatten)]
    pub input: InputArgs,

    /// Refresh continuously until interrupted
    #[arg(short, long)]
    pub watch: bool,

    /// Only show accounts matching this text (issuer or account name)
    #[arg(short = 'g', long, value_name = "TEXT")]
    pub grep: Option<String>,

    /// Show the secrets alongside the codes
    #[arg(long)]
    pub show_secrets: bool,
}

#[derive(Args, Debug)]
pub struct QrArgs {
    #[command(flatten)]
    pub input: InputArgs,

    /// Directory to write QR codes into (defaults to printing in the terminal)
    #[arg(short, long, value_name = "DIR")]
    pub out: Option<PathBuf>,

    /// Image format
    #[arg(long, value_enum, default_value_t = QrFormat::Png)]
    pub image_format: QrFormat,

    /// Pixels per QR module
    #[arg(long, default_value_t = 8)]
    pub scale: u32,
}

#[derive(Args, Debug)]
pub struct EncodeArgs {
    #[command(flatten)]
    pub input: InputArgs,

    /// Directory to write the export QR codes into
    #[arg(short, long, value_name = "DIR")]
    pub out: Option<PathBuf>,

    /// Print the `otpauth-migration://` URIs to stdout
    #[arg(long)]
    pub print_uris: bool,

    /// Maximum accounts per QR code
    #[arg(long, default_value_t = migration::DEFAULT_MAX_PER_BATCH, value_name = "N")]
    pub per_batch: usize,

    /// Maximum URI bytes per QR code (lower = easier to scan)
    #[arg(long, default_value_t = migration::DEFAULT_MAX_URI_BYTES, value_name = "BYTES")]
    pub max_bytes: usize,

    /// Pixels per QR module
    #[arg(long, default_value_t = 8)]
    pub scale: u32,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum OutFormat {
    /// One otpauth:// URI per line
    Uri,
    Json,
    #[value(name = "json-pretty")]
    JsonPretty,
    Csv,
    /// Aligned, human-readable table
    Table,
    /// Aegis Authenticator import file
    Aegis,
}

impl From<OutFormat> for Format {
    fn from(value: OutFormat) -> Self {
        match value {
            OutFormat::Uri => Format::Uri,
            OutFormat::Json => Format::Json,
            OutFormat::JsonPretty => Format::JsonPretty,
            OutFormat::Csv => Format::Csv,
            OutFormat::Table => Format::Table,
            OutFormat::Aegis => Format::Aegis,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum QrFormat {
    Png,
    Svg,
    /// Print into the terminal
    Ansi,
}

pub fn run(cli: Cli) -> Result<()> {
    let quiet = cli.quiet;
    let command = match cli.command {
        Some(command) => command,
        // Bare `gaexport` prints help rather than silently waiting on stdin:
        // a hanging process with no output is the worst possible first run.
        None if cli.decode.input.is_bare() => {
            Cli::command().print_help()?;
            println!();
            return Ok(());
        }
        None => Command::Decode(cli.decode),
    };
    match command {
        Command::Decode(args) => cmd_decode(args, quiet),
        Command::Codes(args) => cmd_codes(args, quiet),
        Command::Qr(args) => cmd_qr(args, quiet),
        Command::Encode(args) => cmd_encode(args, quiet),
        #[cfg(feature = "server")]
        Command::Serve(args) => crate::server::run(args, quiet),
        Command::Completions { shell } => {
            let mut cmd = Cli::command();
            let name = cmd.get_name().to_string();
            clap_complete::generate(shell, &mut cmd, name, &mut std::io::stdout());
            Ok(())
        }
    }
}

/// Collects keys and reports what happened on stderr, keeping stdout pure so it
/// can be piped.
fn load(input: &InputArgs, quiet: bool) -> Result<Vec<OtpEntry>> {
    let spec = input.to_spec();
    if spec.is_empty() {
        bail!(
            "no input given — pass a QR screenshot, a URI, or pipe data in\n\
             try `gaexport decode ~/Desktop/export.png` or `gaexport --help`"
        );
    }
    let collected = input::collect(&spec)?;
    if !quiet {
        for warning in &collected.warnings {
            eprintln!("warning: {warning}");
        }
        let mut note = format!(
            "decoded {} from {} source{}",
            output::summary(&collected.entries),
            collected.sources,
            if collected.sources == 1 { "" } else { "s" }
        );
        if collected.duplicates > 0 {
            note.push_str(&format!(", {} duplicate(s) removed", collected.duplicates));
        }
        eprintln!("{note}");
    }
    Ok(collected.entries)
}

fn sort_entries(entries: &mut [OtpEntry]) {
    entries.sort_by_key(|e| (e.issuer.to_lowercase(), e.name.to_lowercase()));
}

fn cmd_decode(args: DecodeArgs, quiet: bool) -> Result<()> {
    let mut entries = load(&args.input, quiet)?;
    if args.sort {
        sort_entries(&mut entries);
    }
    let rendered = output::render(
        &entries,
        args.format.into(),
        RenderOptions {
            redact: args.redact,
            with_codes: args.codes,
        },
    )?;
    match &args.output {
        Some(path) => {
            output::write_secret_file(path, rendered.as_bytes())?;
            if !quiet {
                eprintln!(
                    "wrote {} ({} mode 0600){}",
                    path.display(),
                    entries.len(),
                    if args.redact {
                        ""
                    } else {
                        " — this file contains your 2FA secrets"
                    }
                );
            }
        }
        None => {
            let mut stdout = std::io::stdout().lock();
            stdout.write_all(rendered.as_bytes())?;
            stdout.flush()?;
        }
    }
    Ok(())
}

fn cmd_codes(args: CodesArgs, quiet: bool) -> Result<()> {
    let mut entries = load(&args.input, quiet)?;
    sort_entries(&mut entries);
    if let Some(needle) = &args.grep {
        let needle = needle.to_lowercase();
        entries.retain(|e| {
            e.issuer.to_lowercase().contains(&needle) || e.name.to_lowercase().contains(&needle)
        });
        if entries.is_empty() {
            bail!("no account matches `{needle}`");
        }
    }
    let opts = RenderOptions {
        redact: !args.show_secrets,
        with_codes: true,
    };

    if !args.watch {
        print!("{}", output::render(&entries, Format::Table, opts)?);
        return Ok(());
    }

    if !std::io::stdout().is_terminal() {
        bail!("--watch needs a terminal; drop it to print codes once");
    }
    let mut stdout = std::io::stdout();
    // Alternate screen + hidden cursor, restored on the way out.
    print!("\x1b[?1049h\x1b[?25l");
    let result = watch_loop(&entries, opts, &mut stdout);
    print!("\x1b[?25h\x1b[?1049l");
    stdout.flush()?;
    result
}

fn watch_loop(
    entries: &[OtpEntry],
    opts: RenderOptions,
    stdout: &mut std::io::Stdout,
) -> Result<()> {
    loop {
        let table = output::render(entries, Format::Table, opts)?;
        write!(
            stdout,
            "\x1b[H\x1b[2J{table}\n\x1b[2mCtrl-C to quit — codes refresh every second\x1b[0m\n"
        )?;
        stdout.flush()?;
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

fn cmd_qr(args: QrArgs, quiet: bool) -> Result<()> {
    let entries = load(&args.input, quiet)?;
    let opts = qr::RenderOptions {
        scale: args.scale,
        ..Default::default()
    };

    match &args.out {
        None => {
            for entry in &entries {
                println!("\n{}", entry.display_name());
                print!("{}", qr::render_ansi(&entry.to_uri(), opts.ec_level)?);
            }
            if !quiet {
                eprintln!("scan these with your new authenticator app");
            }
        }
        Some(dir) => {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
            for (index, entry) in entries.iter().enumerate() {
                let stem = format!("{:02}-{}", index + 1, slugify(&entry.display_name()));
                let (ext, bytes) = match args.image_format {
                    QrFormat::Png => ("png", qr::render_png(&entry.to_uri(), opts)?),
                    QrFormat::Svg => ("svg", qr::render_svg(&entry.to_uri(), opts)?.into_bytes()),
                    QrFormat::Ansi => (
                        "txt",
                        qr::render_ansi(&entry.to_uri(), opts.ec_level)?.into_bytes(),
                    ),
                };
                let path = dir.join(format!("{stem}.{ext}"));
                output::write_secret_file(&path, &bytes)?;
            }
            if !quiet {
                eprintln!(
                    "wrote {} QR code(s) to {} — each one embeds a live 2FA secret",
                    entries.len(),
                    dir.display()
                );
            }
        }
    }
    Ok(())
}

fn cmd_encode(args: EncodeArgs, quiet: bool) -> Result<()> {
    let entries = load(&args.input, quiet)?;
    let uris = migration::build_uris(&entries, args.per_batch, args.max_bytes)?;

    if args.print_uris || args.out.is_none() {
        for uri in &uris {
            println!("{uri}");
        }
    }
    if let Some(dir) = &args.out {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        let opts = qr::RenderOptions {
            scale: args.scale,
            ..Default::default()
        };
        for (index, uri) in uris.iter().enumerate() {
            let path = dir.join(format!("ga-export-{:02}.png", index + 1));
            output::write_secret_file(&path, &qr::render_png(uri, opts)?)?;
        }
        if !quiet {
            eprintln!(
                "wrote {} export QR code(s) to {} — scan with Google Authenticator ▸ \
                 Transfer accounts ▸ Import accounts ▸ Scan QR code",
                uris.len(),
                dir.display()
            );
        }
    } else if !quiet {
        eprintln!(
            "packed {} into {} export QR code(s); add --out DIR to write scannable images",
            output::summary(&entries),
            uris.len()
        );
    }
    Ok(())
}

/// Filesystem-safe, readable file stem.
fn slugify(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut last_dash = false;
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() || ch == '.' {
            out.push(ch.to_ascii_lowercase());
            last_dash = false;
        } else if ch.is_alphanumeric() {
            // Keep CJK and other scripts as-is; they are valid in filenames.
            out.push(ch);
            last_dash = false;
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
    }
    let trimmed = out.trim_matches('-').to_string();
    if trimmed.is_empty() {
        "account".to_string()
    } else {
        trimmed.chars().take(48).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn positionals_split_into_uris_and_paths() {
        let args = InputArgs {
            targets: vec![
                "otpauth://totp/a?secret=GEZDGNBVGY3TQOJQ".into(),
                "OTPAUTH-MIGRATION://offline?data=AA".into(),
                "shot.png".into(),
            ],
            ..Default::default()
        };
        let spec = args.to_spec();
        assert_eq!(spec.uris.len(), 2);
        assert_eq!(spec.paths, vec![PathBuf::from("shot.png")]);
    }

    #[test]
    fn slugify_is_filesystem_safe() {
        assert_eq!(
            slugify("ACME Co:alice@example.com"),
            "acme-co-alice-example.com"
        );
        assert_eq!(slugify("///"), "account");
        assert_eq!(slugify("银行:主账号"), "银行-主账号");
        assert!(slugify(&"x".repeat(200)).chars().count() <= 48);
    }

    #[test]
    fn bare_invocation_is_detected() {
        let cli = Cli::try_parse_from(["gaexport"]).unwrap();
        assert!(cli.command.is_none() && cli.decode.input.is_bare());
        let with_path = Cli::try_parse_from(["gaexport", "shot.png"]).unwrap();
        assert!(!with_path.decode.input.is_bare());
    }

    #[test]
    fn a_bare_path_defaults_to_decoding() {
        let cli = Cli::try_parse_from(["gaexport", "shot.png", "--format", "json"]).unwrap();
        assert!(cli.command.is_none(), "no subcommand should be required");
        assert_eq!(cli.decode.input.targets, vec!["shot.png"]);
        assert_eq!(cli.decode.format, OutFormat::Json);
    }

    #[test]
    fn subcommands_still_win_over_the_default() {
        let cli = Cli::try_parse_from(["gaexport", "codes", "shot.png", "--watch"]).unwrap();
        match cli.command {
            Some(Command::Codes(args)) => {
                assert!(args.watch);
                assert_eq!(args.input.targets, vec!["shot.png"]);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn decode_parses_expected_flags() {
        let cli = Cli::try_parse_from([
            "gaexport",
            "decode",
            "shot.png",
            "--format",
            "json-pretty",
            "--redact",
            "--sort",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Decode(args)) => {
                assert_eq!(args.format, OutFormat::JsonPretty);
                assert!(args.redact && args.sort);
                assert_eq!(args.input.targets, vec!["shot.png"]);
            }
            other => panic!("unexpected command {other:?}"),
        }
    }

    #[test]
    fn export_is_an_alias_for_decode() {
        let cli = Cli::try_parse_from(["gaexport", "export", "shot.png"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Decode(_))));
    }
}
