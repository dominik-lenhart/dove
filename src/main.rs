use std::io::IsTerminal;

use clap::Parser;

fn main() -> std::process::ExitCode {
    let cli = dove::cli::Cli::parse();
    // Binaries renamed aside by an earlier `dove upgrade` while they were running (PLAN A58).
    #[cfg(windows)]
    dove::update::windows::cleanup_after_upgrade();
    if !matches!(cli.command, dove::cli::Command::Serve { .. }) {
        dove::logging::init_cli_logging();
    }
    // The daily new-version notice (stderr only, never for `serve`): looked up alongside the command, bounded by
    // NOTICE_BUDGET from the start, and printed after the command's own output.
    let notice = dove::cli::update_notice_applies(&cli.command)
        && dove::update::notice::enabled(
            |k| std::env::var_os(k),
            std::io::stderr().is_terminal(),
            dove::update::notice::Ids::current(),
        );
    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: cannot start runtime: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let (result, notice_line) = rt.block_on(async move {
        let deadline = tokio::time::Instant::now() + dove::update::notice::NOTICE_BUDGET;
        let check = notice.then(|| tokio::spawn(dove::update::notice::check()));
        let result = dove::cli::run(cli).await;
        let line = match check {
            Some(h) => tokio::time::timeout_at(deadline, h).await.ok().and_then(Result::ok).flatten(),
            None => None,
        };
        (result, line)
    });
    if notice {
        // A name lookup stuck in a blocking thread must not delay the exit.
        rt.shutdown_background();
    }
    let code = match result {
        Ok(code) => std::process::ExitCode::from(code),
        Err(e) => {
            eprintln!("error: {}", dove::logging::redact(&format!("{e:#}")));
            std::process::ExitCode::FAILURE
        }
    };
    if let Some(line) = notice_line {
        eprintln!("{line}");
    }
    code
}
