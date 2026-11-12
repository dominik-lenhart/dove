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
    let admin = crate::admin::server::bind(&app.cfg.admin.socket_path)?;
    tokio::spawn(crate::admin::server::serve(app.clone(), admin));
    tracing::info!(listen = %app.cfg.listen, "dove started");
    run_until_shutdown(app).await
}

async fn run_until_shutdown(app: Arc<App>) -> anyhow::Result<()> {
    let recovered = app.store.call(|c| crate::tools::drafts::recover_after_restart(c)).await?;
    if recovered > 0 {
        tracing::warn!(count = recovered, "sends interrupted by a restart are marked outcome-unknown");
    }
    let listener = tokio::net::TcpListener::bind(app.cfg.listen).await.context("cannot bind listen address")?;
    let shutdown = async {
        let mut term =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("signal handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = term.recv() => {},
        }
        tracing::info!("shutting down, finishing in-flight requests");
    };
    // Graceful shutdown finishes in-flight requests for up to 10 seconds (spec 8.2).
    let server = crate::http::serve(app.clone(), listener, shutdown);
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        let r = server.await;
        let _ = tx.send(());
        r
    });
    let _ = rx.await;
    match tokio::time::timeout(std::time::Duration::from_secs(10), handle).await {
        Ok(r) => r??,
        Err(_) => tracing::warn!("shutdown timed out"),
    }
    Ok(())
}
