use anyhow::{Context, Result};
use clap::Parser;
use rpassword::read_password;
use std::env;
use std::fs;
use std::path::PathBuf;

use modality_utils::keypair::Keypair;

#[derive(Debug, Parser)]
pub struct Opts {
    #[clap(long)]
    name: Option<String>,

    /// Path to search for passkey files. Defaults to current directory if not specified.
    #[clap(long, value_parser)]
    path: Option<PathBuf>,
}

pub async fn run(opts: &Opts) -> Result<()> {
    // Get password first
    let password = get_password().context("Failed to get password")?;

    // Determine root directory
    let root_dir = if let Some(path) = &opts.path {
        path.clone()
    } else {
        env::current_dir().context("Failed to get current directory")?
    };

    // Validate directory
    if !root_dir.exists() {
        return Err(anyhow::anyhow!(
            "Directory does not exist: {}",
            root_dir.display()
        ));
    }
    if !root_dir.is_dir() {
        return Err(anyhow::anyhow!(
            "Path is not a directory: {}",
            root_dir.display()
        ));
    }

    println!("\nSearching for passkey files in: {}", root_dir.display());

    // Find all .mod_passkey files in specified directory
    let entries = fs::read_dir(&root_dir)?;
    let mut encrypted_count = 0;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        if let Some(ext) = path.extension() {
            if ext == "mod_passkey" {
                // Try to read as json to check if already encrypted
                if let Ok(content) = fs::read_to_string(&path) {
                    if content.contains("private_key") {
                        // Read keypair from unencrypted file
                        let keypair = Keypair::from_json_file(path.to_str().ok_or_else(|| {
                            anyhow::anyhow!("Invalid file path: contains non-Unicode characters")
                        })?)
                        .map_err(|e| {
                            eprintln!("Failed to read keypair from file {}: {}", path.display(), e);
                            e
                        })?;

                        // Encrypt and save back to same file
                        keypair
                            .as_encrypted_json_file(
                                path.to_str().ok_or_else(|| {
                                    anyhow::anyhow!(
                                        "Invalid file path: contains non-Unicode characters"
                                    )
                                })?,
                                &password,
                            )
                            .map_err(|e| {
                                eprintln!("Failed to save encrypted keypair to file: {}", e);
                                e
                            })?;

                        println!("🔒 Encrypted {}", path.display());
                        encrypted_count += 1;
                    }
                }
            }
        }
    }

    if encrypted_count > 0 {
        println!(
            "\n✨ Successfully encrypted {} passkey files!",
            encrypted_count
        );
    } else {
        println!("\nℹ️ No unencrypted passkey files found.");
    }

    Ok(())
}

fn get_password() -> Result<String> {
    eprint!("Enter password to encrypt the passkeys: ");

    let password = read_password()?;
    if password.is_empty() {
        return Err(anyhow::anyhow!("Password cannot be empty"));
    }

    eprint!("Confirm password: ");

    let confirm = read_password()?;
    if password != confirm {
        return Err(anyhow::anyhow!("Passwords do not match"));
    }

    Ok(password)
}
