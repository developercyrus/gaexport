//! `gaexport` — export, inspect and re-import Google Authenticator OTP secrets.
//!
//! Google Authenticator's "Transfer accounts" screen encodes your accounts into
//! one or more `otpauth-migration://offline?data=…` QR codes. This crate reads
//! them (from a screenshot, a photo, a camera frame or a pasted URI), turns them
//! into the standard `otpauth://` Key-Uri-Format, and can pack keys back into
//! export QR codes for a new phone.
//!
//! Everything runs locally: no crate here opens a network connection, and the
//! optional HTTP server binds to loopback unless explicitly told otherwise.
//!
//! ```no_run
//! use gaexport::{input::{self, InputSpec}, output::{self, Format, RenderOptions}};
//!
//! let collected = input::collect(&InputSpec {
//!     paths: vec!["export.png".into()],
//!     ..Default::default()
//! })?;
//! print!("{}", output::render(&collected.entries, Format::Uri, RenderOptions::default())?);
//! # Ok::<(), anyhow::Error>(())
//! ```

#[cfg(feature = "cli")]
pub mod cli;
pub mod input;
pub mod migration;
pub mod otp;
pub mod output;
pub mod proto;
pub mod qr;
#[cfg(feature = "server")]
pub mod server;
#[cfg(target_arch = "wasm32")]
pub mod wasm;

pub use otp::{Algorithm, OtpEntry, OtpType};

/// The crate version, surfaced in output metadata and `--version`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
