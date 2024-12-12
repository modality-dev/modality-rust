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
    let mut decrypted_count = 0;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        if let Some(ext) = path.extension() {
            if ext == "mod_passkey" {
                // Try to read as json to check if encrypted
                if let Ok(content) = fs::read_to_string(&path) {
                    if content.contains("encrypted_private_key") {
                        // Decrypt keypair from file
                        let keypair = Keypair::from_encrypted_json_file(
                            path.to_str().ok_or_else(|| {
                                anyhow::anyhow!(
                                    "Invalid file path: contains non-Unicode characters"
                                )
                            })?,
                            &password,
                        )
                        .map_err(|e| {
                            eprintln!(
                                "Failed to decrypt keypair from file {}: {}",
                                path.display(),
                                e
                            );
                            e
                        })?;

                        keypair
                            .as_json_file(path.to_str().ok_or_else(|| {
                                anyhow::anyhow!(
                                    "Invalid file path: contains non-Unicode characters"
                                )
                            })?)
                            .map_err(|e| {
                                eprintln!(
                                    "Failed to save decrypted keypair to file {}: {}",
                                    path.display(),
                                    e
                                );
                                e
                            })?;

                        println!("🔓 Decrypted {}", path.display());
                        decrypted_count += 1;
                    }
                }
            }
        }
    }

    if decrypted_count > 0 {
        println!(
            "\n✨ Successfully decrypted {} passkey files!",
            decrypted_count
        );
    } else {
        println!("\nℹ️ No encrypted passkey files found.");
    }

    Ok(())
}

fn get_password() -> Result<String> {
    eprint!("Enter password to decrypt the passkeys: ");

    let password = read_password()?;
    if password.is_empty() {
        return Err(anyhow::anyhow!("Password cannot be empty"));
    }

    // Verify password against encrypted passkeys
    let entries = fs::read_dir(".")?;
    for entry in entries {
        let path = entry?.path();
        if let Some(ext) = path.extension() {
            if ext == "mod_passkey" {
                if let Ok(content) = fs::read_to_string(&path) {
                    if content.contains("encrypted_private_key") {
                        let keypair_json: modality_utils::keypair::KeypairJSON =
                            serde_json::from_str(&content)?;

                        if let Some(encrypted_key) = keypair_json.encrypted_private_key() {
                            if modality_utils::encrypted_text::EncryptedText::decrypt(
                                encrypted_key,
                                &password,
                            )
                            .is_ok()
                            {
                                return Ok(password);
                            }
                        }
                    }
                }
            }
        }
    }

    Err(anyhow::anyhow!(
        "Invalid password - could not decrypt any passkeys"
    ))
}
