//! Thin binary wrapper: everything lives in the library so the same code backs
//! the CLI, the HTTP server and the WASM build.

use clap::Parser;
use gaexport::cli;

fn main() -> std::process::ExitCode {
    match cli::run(cli::Cli::parse()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        // `gaexport decode … | head` closes stdout early; that is not an error
        // worth a message or a failing exit status.
        Err(err) if is_broken_pipe(&err) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn is_broken_pipe(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::BrokenPipe)
    })
}
