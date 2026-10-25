use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::process::ExitCode;
use std::time::Duration;

use rw_subpage::config::Config;
use rw_subpage::constants::VERSION;
use rw_subpage::{app, init_state, server};
use tracing_subscriber::EnvFilter;

/// `rw-subpage --healthcheck`: probes `/internal/health` on loopback (no curl in the image).
fn healthcheck() -> ExitCode {
    let port = std::env::var("APP_PORT")
        .ok()
        .and_then(|p| p.trim().parse::<u16>().ok())
        .unwrap_or(3010);
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let timeout = Duration::from_secs(2);

    let probe = || -> std::io::Result<bool> {
        let mut s = TcpStream::connect_timeout(&addr, timeout)?;
        s.set_read_timeout(Some(timeout))?;
        s.set_write_timeout(Some(timeout))?;
        s.write_all(b"GET /internal/health HTTP/1.0\r\nHost: localhost\r\n\r\n")?;
        let mut buf = [0u8; 32];
        let n = s.read(&mut buf)?;
        Ok(buf[..n].starts_with(b"HTTP/1.1 200") || buf[..n].starts_with(b"HTTP/1.0 200"))
    };
    if probe().unwrap_or(false) {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn banner() -> String {
    let title = format!("Remnawave Subscription Page v{VERSION}");
    let lines = [
        "Docs → https://docs.rw",
        "Community → https://t.me/remnawave",
    ];
    let width = 60;
    let line = "═".repeat(width);
    let center = |s: &str| format!("{s:^width$}");
    format!(
        "╔{line}╗\n║{}║\n╟{}╢\n║{}║\n║{}║\n╚{line}╝",
        center(&title),
        "─".repeat(width),
        center(lines[0]),
        center(lines[1]),
    )
}

async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
    tracing::info!("Shutting down...");
}

#[tokio::main]
async fn main() -> ExitCode {
    if std::env::args().any(|a| a == "--healthcheck") {
        return healthcheck();
    }

    let _ = dotenvy::dotenv();

    let config = match Config::from_process_env() {
        Ok(c) => c,
        Err(msg) => {
            eprintln!("{msg}");
            return ExitCode::FAILURE;
        }
    };

    let default_level = if config.development || config.debug_logs {
        "debug"
    } else {
        "info"
    };
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            EnvFilter::new(format!(
                "{default_level},hyper=warn,reqwest=warn,rustls=warn"
            ))
        }))
        .with_target(false)
        .init();

    match &config.custom_sub_prefix {
        Some(p) => tracing::info!("[CONFIG] CUSTOM_SUB_PREFIX: {p}"),
        None => tracing::info!("[CONFIG] CUSTOM_SUB_PREFIX: not set"),
    }
    let port = config.app_port;

    let state = match init_state(config).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("{e}");
            return ExitCode::FAILURE;
        }
    };

    let listener = match server::bind(port) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("cannot listen on port {port}: {e}");
            return ExitCode::FAILURE;
        }
    };
    tracing::info!("\n{}\n", banner());
    tracing::info!("Listening on port {port}");

    server::serve(listener, app::build_service(state), shutdown_signal()).await;
    ExitCode::SUCCESS
}
