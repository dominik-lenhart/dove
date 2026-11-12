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
    let _ = app;
    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down");
    Ok(())
}
