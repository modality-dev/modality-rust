mod cmds;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "modality")]
#[command(version = "0.1.1")]
#[command(about = "Modality language CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[command(alias = "create_id")]
    CreateId(cmds::create_id::Opts),

    #[command(alias = "decrypt_passkeys")]
    DecryptPasskeys(cmds::decrypt_passkeys::Opts),

    #[command(alias = "encrypt_passkeys")]
    EncryptPasskeys(cmds::encrypt_passkeys::Opts),
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match &cli.command {
        Commands::CreateId(opts) => cmds::create_id::run(opts).await?,
        Commands::DecryptPasskeys(opts) => cmds::decrypt_passkeys::run(opts).await?,
        Commands::EncryptPasskeys(opts) => cmds::encrypt_passkeys::run(opts).await?,
    }

    Ok(())
}
