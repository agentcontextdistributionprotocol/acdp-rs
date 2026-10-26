//! `acdp-mcp-proxy` — the MCP signing proxy (RFC-ACDP-0019).
//!
//! ```text
//! acdp-mcp-proxy --config <proxy.json>     # run: MCP client on stdin/stdout
//! acdp-mcp-proxy --config <proxy.json> --print-did
//! acdp-mcp-proxy --version
//! ```
//!
//! Configure an MCP client to launch this binary in place of the
//! server; the config names the real server. stdout carries only the
//! relayed protocol; diagnostics go to stderr.

use std::{path::PathBuf, process::ExitCode, process::Stdio, sync::Arc};

use acdp::client::RegistryClient;
use acdp_mcp_proxy::Config;
use tokio::process::Command;

fn usage() {
    eprintln!(
        "acdp-mcp-proxy — MCP signing proxy (RFC-ACDP-0019)\n\
         \n\
         USAGE:\n\
         \tacdp-mcp-proxy --config <proxy.json>              # relay stdio\n\
         \tacdp-mcp-proxy --config <proxy.json> --print-did  # show the operator DID\n\
         \tacdp-mcp-proxy --version"
    );
}

#[tokio::main]
async fn main() -> ExitCode {
    let mut config: Option<PathBuf> = None;
    let mut print_did = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--config" => config = args.next().map(PathBuf::from),
            "--print-did" => print_did = true,
            "--version" => {
                println!("acdp-mcp-proxy {}", env!("CARGO_PKG_VERSION"));
                return ExitCode::SUCCESS;
            }
            _ => {
                usage();
                return ExitCode::from(1);
            }
        }
    }
    let Some(path) = config else {
        usage();
        return ExitCode::from(1);
    };
    match run(&path, print_did).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("acdp-mcp-proxy: {e}");
            ExitCode::from(2)
        }
    }
}

async fn run(path: &std::path::Path, print_did: bool) -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load(path)?;
    if print_did {
        println!("{}", config.operator_did()?);
        return Ok(());
    }
    let proxy = Arc::new(config.proxy(RegistryClient::new(&config.registry)?)?);
    let u = &config.upstream;
    let mut cmd = Command::new(&u.command);
    cmd.args(&u.args)
        .envs(&u.env)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);
    if let Some(dir) = &u.cwd {
        cmd.current_dir(dir);
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("cannot start upstream {}: {e}", u.command))?;
    let server_in = child.stdin.take().ok_or("upstream stdin unavailable")?;
    let server_out = child.stdout.take().ok_or("upstream stdout unavailable")?;
    proxy
        .run(
            tokio::io::stdin(),
            tokio::io::stdout(),
            server_in,
            server_out,
        )
        .await?;
    let _ = child.wait().await;
    Ok(())
}
