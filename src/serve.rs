//! `dove serve`: startup checks, process hardening, admin socket and HTTP listener.

use std::path::Path;
use std::sync::Arc;

use anyhow::Context;

use crate::app::App;
use crate::config::Config;

/// Disables core dumps so decrypted secrets cannot end up on disk (spec 6.4).
pub fn harden_process() -> anyhow::Result<()> {
    nix::sys::resource::setrlimit(nix::sys::resource::Resource::RLIMIT_CORE, 0, 0)
        .context("cannot disable core dumps")?;
    #[cfg(target_os = "linux")]
    nix::sys::prctl::set_dumpable(false).context("cannot clear the dumpable flag")?;
    Ok(())
}

pub async fn run(config_path: &Path) -> anyhow::Result<()> {
    crate::logging::init_service_logging();
    harden_process()?;
    let cfg = Config::load(config_path)?;
    let app = App::from_config(cfg)?;
    crate::index::db::set_heap_limit(app.cfg.index.sql_heap_limit_mib);
    // Startup self-check of the encrypted index: SQLCipher, key, FTS5, memory-only temp storage (spec 7.9).
    let (_, index_key) = app.index_key.current();
    crate::index::db::open(&app.cfg.index_db_path(), index_key, &app.cfg.index).context("index self-check failed")?;
    let uid = nix::unistd::getuid().as_raw();
    if uid == app.cfg.admin.operator_uid {
        tracing::warn!("the service runs as the operator uid; run it as a dedicated service user (spec FR-C1)");
    }
    if app.proxy_secret.is_none() {
        tracing::warn!(
            "secrets.proxy_secret_file is not set: any local process can forge X-Forwarded-For and bypass allow_ip \
             lists and per-IP rate limits (docs/deployment.md, reverse proxy)"
        );
    }
    let admin = crate::admin::server::bind(&app.cfg.admin.socket_path)?;
    tokio::spawn(crate::admin::server::serve(app.clone(), admin));
    crate::index::start(app.clone());
    tracing::info!(listen = %app.cfg.listen, "dove started");
    run_until_shutdown(app).await
}

async fn run_until_shutdown(app: Arc<App>) -> anyhow::Result<()> {
    let recovered = app.store.call(|c| crate::tools::drafts::recover_after_restart(c)).await?;
    if recovered > 0 {
        tracing::warn!(count = recovered, "sends interrupted by a restart are marked outcome-unknown");
    }
    let listener = tokio::net::TcpListener::bind(app.cfg.listen).await.context("cannot bind listen address")?;
    let signal = async {
        let mut term =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("signal handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = term.recv() => {},
        }
    };
    // Graceful shutdown finishes in-flight requests for up to 10 seconds (spec 8.2).
    serve_until(app.clone(), listener, signal, std::time::Duration::from_secs(10)).await
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
