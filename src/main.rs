use anyhow::Result;
use clap::Parser;
use soroban_debugger::cli::{Cli, Commands};
use soroban_debugger::ui::formatter::Formatter;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

fn main() -> Result<()> {
    Formatter::configure_colors_from_env();

    // Initialize logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "soroban_debugger=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Parse CLI arguments
    let cli = Cli::parse();

    // Execute command
    let result = match cli.command {
        Commands::Run(args) => soroban_debugger::cli::commands::run(args),
        Commands::Interactive(args) => soroban_debugger::cli::commands::interactive(args),
        Commands::Inspect(args) => soroban_debugger::cli::commands::inspect(args),
        Commands::Optimize(args) => soroban_debugger::cli::commands::optimize(args),
        Commands::UpgradeCheck(args) => soroban_debugger::cli::commands::upgrade_check(args),
    };

    if let Err(err) = result {
        eprintln!("{}", Formatter::error(format!("Error: {err:#}")));
        return Err(err);
    }

    Ok(())
}