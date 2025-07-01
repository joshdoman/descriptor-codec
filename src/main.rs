// Written in 2025 by Joshua Doman <joshsdoman@gmail.com>
// SPDX-License-Identifier: CC0-1.0

#[cfg(feature = "cli")]
use anyhow::{Context, Result};
#[cfg(feature = "cli")]
use clap::{Args, Parser, Subcommand};

#[cfg(feature = "cli")]
#[derive(Parser)]
#[clap(name = "descriptor-codec")]
#[clap(author = "Joshua Doman <joshsdoman@gmail.com>")]
#[clap(version = "0.1.0")]
#[clap(about = "CLI tool to encode and decode Bitcoin descriptors.", long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[cfg(feature = "cli")]
#[derive(Subcommand)]
enum Commands {
    /// Encodes a Bitcoin descriptor, outputs hex
    Encode(EncodeArgs),
    /// Decodes a hex-encoded descriptor
    Decode(DecodeArgs),
}

#[cfg(feature = "cli")]
#[derive(Args)]
struct EncodeArgs {
    /// The Bitcoin descriptor string to encode
    descriptor: String,
}

#[cfg(feature = "cli")]
#[derive(Args)]
struct DecodeArgs {
    /// Hex-encoded descriptor data
    data: String,
}

#[cfg(feature = "cli")]
fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encode(args) => handle_encode(args),
        Commands::Decode(args) => handle_decode(args),
    }
}

#[cfg(not(feature = "cli"))]
fn main() {
    println!("Feature --cli is not enabled");
}

#[cfg(feature = "cli")]
fn handle_encode(args: EncodeArgs) -> Result<()> {
    let encoded_data =
        descriptor_codec::encode(&args.descriptor).context("Failed to parse descriptor string")?;

    println!("{}", hex::encode(encoded_data));

    Ok(())
}

#[cfg(feature = "cli")]
fn handle_decode(args: DecodeArgs) -> Result<()> {
    let data = hex::decode(&args.data).context("Failed to decode hex data")?;

    let desc = descriptor_codec::decode(&data).context("Unable to decode")?;

    println!("{}", desc);

    Ok(())
}
