//! `dove serve`: startup checks, process hardening, admin socket and HTTP listener.

use std::path::Path;
use std::sync::Arc;

use anyhow::Context;

use crate::app::App;
use crate::config::Config;

/// Disables core dumps so decrypted secrets cannot end up on disk (spec 6.4). Windows has no per-process switch for
/// Windows Error Reporting dumps; local mode's threat model accepts that (docs/deployment.md).
pub fn harden_process() -> anyhow::Result<()> {
    #[cfg(unix)]
    nix::sys::resource::setrlimit(nix::sys::resource::Resource::RLIMIT_CORE, 0, 0)
        .context("cannot disable core dumps")?;
    #[cfg(target_os = "linux")]
    nix::sys::prctl::set_dumpable(false).context("cannot clear the dumpable flag")?;
    Ok(())
}

pub async fn run(config_path: &Path) -> anyhow::Result<()> {
    run_with_log(config_path, None).await
}

/// [`run`] with the service log going to `log` instead of stderr (local mode's login items have no journal).
pub async fn run_with_log(config_path: &Path, log: Option<std::fs::File>) -> anyhow::Result<()> {
    match log {
        Some(f) => {
            let filter = tracing_subscriber::EnvFilter::try_from_env("DOVE_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
            crate::logging::install_service_logging(f, filter);
        }
        None => crate::logging::init_service_logging(),
    }
    harden_process()?;
    let cfg = Config::load(config_path)?;
    let app = App::from_config(cfg)?;
    crate::index::db::set_heap_limit(app.cfg.index.sql_heap_limit_mib);
    // Startup self-check of the encrypted index: SQLCipher, key, FTS5, memory-only temp storage (spec 7.9).
    let (_, index_key) = app.index_key.current();
    crate::index::db::open(&app.cfg.index_db_path(), index_key, &app.cfg.index).context("index self-check failed")?;
    #[cfg(unix)]
    if !app.cfg.is_local() && nix::unistd::getuid().as_raw() == app.cfg.admin.operator_uid {
        tracing::warn!("the service runs as the operator uid; run it as a dedicated service user (spec FR-C1)");
    }
    if app.proxy_secret.is_none() && !app.cfg.is_local() {
        tracing::warn!(
            "secrets.proxy_secret_file is not set: any local process can forge X-Forwarded-For and bypass allow_ip \
             lists and per-IP rate limits (docs/deployment.md, reverse proxy)"
        );
    }
    let admin = crate::admin::server::bind(&app.cfg.admin.socket_path)?;
    tokio::spawn(crate::admin::server::serve(app.clone(), admin));
    crate::index::start(app.clone());
    crate::index::imap_idle::start(app.clone());
    crate::watch::start(app.clone());
    tracing::info!(listen = %app.cfg.listen, "dove started");
    run_until_shutdown(app).await
}

async fn run_until_shutdown(app: Arc<App>) -> anyhow::Result<()> {
    let recovered = app.store.call(|c| crate::tools::drafts::recover_after_restart(c)).await?;
    if recovered > 0 {
        tracing::warn!(count = recovered, "sends interrupted by a restart are marked outcome-unknown");
    }
    let listener = tokio::net::TcpListener::bind(app.cfg.listen).await.context("cannot bind listen address")?;
    let signal = shutdown_signal();
    // Graceful shutdown finishes in-flight requests for up to 10 seconds (spec 8.2).
    serve_until(app.clone(), listener, signal, std::time::Duration::from_secs(10)).await
}

/// SIGINT or SIGTERM (Unix); Ctrl+C, Ctrl+Break, console close, logoff or shutdown (Windows).
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("signal handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = term.recv() => {},
        }
    }
    #[cfg(windows)]
    {
        use tokio::signal::windows;
        let mut brk = windows::ctrl_break().expect("signal handler");
        let mut close = windows::ctrl_close().expect("signal handler");
        let mut logoff = windows::ctrl_logoff().expect("signal handler");
        let mut shutdown = windows::ctrl_shutdown().expect("signal handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = brk.recv() => {},
            _ = close.recv() => {},
            _ = logoff.recv() => {},
            _ = shutdown.recv() => {},
        }
    }
}

/// Serves HTTP until `signal` resolves, then stops accepting and gives in-flight requests at most `grace` to finish.
/// Returns early with the error if the server fails on its own.
pub async fn serve_until(
    app: Arc<App>,
    listener: tokio::net::TcpListener,
    signal: impl std::future::Future<Output = ()>,
    grace: std::time::Duration,
) -> anyhow::Result<()> {
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let mut handle = tokio::spawn(crate::http::serve(app, listener, async {
        let _ = stop_rx.await;
    }));
    tokio::select! {
        r = &mut handle => return r?,
        () = signal => {}
    }
    tracing::info!("shutting down, finishing in-flight requests");
    let _ = stop_tx.send(());
    match tokio::time::timeout(grace, &mut handle).await {
        Ok(r) => r?,
        Err(_) => {
            tracing::warn!("shutdown grace period elapsed; dropping unfinished requests");
            handle.abort();
            Ok(())
        }
    }
}
