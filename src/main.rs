use clap::Parser;

fn main() -> std::process::ExitCode {
    let cli = dove::cli::Cli::parse();
    if !matches!(cli.command, dove::cli::Command::Serve { .. }) {
        dove::logging::init_cli_logging();
    }
    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: cannot start runtime: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    match rt.block_on(dove::cli::run(cli)) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {}", dove::logging::redact(&format!("{e:#}")));
            std::process::ExitCode::FAILURE
        }
    }
}
