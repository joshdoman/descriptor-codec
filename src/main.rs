// // Written in 2025 by Joshua Doman <joshsdoman@gmail.com>
// // SPDX-License-Identifier: CC0-1.0

// use anyhow::{Context, Result};
// use clap::{Args, Parser, Subcommand};
// use descriptor_encrypt::{
//     bitcoin::{bip32::DerivationPath, secp256k1::Secp256k1},
//     miniscript::descriptor::{Descriptor, DescriptorPublicKey, DescriptorSecretKey},
// };
// use std::str::FromStr;

// #[derive(Parser)]
// #[clap(name = "descriptor-codec")]
// #[clap(author = "Joshua Doman <joshsdoman@gmail.com>")]
// #[clap(version = "0.1.0")]
// #[clap(about = "CLI tool to encode and decode Bitcoin descriptors.", long_about = None)]
// struct Cli {
//     #[clap(subcommand)]
//     command: Commands,
// }

// #[derive(Subcommand)]
// enum Commands {
//     /// Encodes a Bitcoin descriptor, outputs hex
//     Encode(EncodeArgs),
//     /// Decodes a hex-encoded descriptor
//     Decode(DecodeArgs),
// }

// #[derive(Args)]
// struct EncodeArgs {
//     /// The Bitcoin descriptor string to encode
//     descriptor: String,
// }

// #[derive(Args)]
// struct DecodeArgs {
//     /// Hex-encoded descriptor data
//     data: String,
// }

// fn main() -> Result<()> {
//     let cli = Cli::parse();

//     match cli.command {
//         Commands::Encode(args) => handle_encode(args),
//         Commands::Decode(args) => handle_decode(args),
//     }
// }

fn main() {}

// fn handle_encrypt(args: EncryptArgs) -> Result<()> {
//     let secp = Secp256k1::new();
//     let (desc, _) = Descriptor::<DescriptorPublicKey>::parse_descriptor(&secp, &args.descriptor)
//         .context("Failed to parse descriptor string")?;

//     let encrypted_data = if args.with_full_secrecy {
//         descriptor_encrypt::encrypt_with_full_secrecy(desc)
//             .context("Encryption with full secrecy failed")?
//     } else {
//         descriptor_encrypt::encrypt(desc).context("Encryption failed")?
//     };

//     println!("{}", hex::encode(encrypted_data));

//     Ok(())
// }

// fn handle_decrypt(args: DecryptArgs) -> Result<()> {
//     let data_bytes =
//         hex::decode(&args.data).context("Failed to decode hex data for encrypted payload")?;

//     let mut pks = Vec::new();
//     for pk_str in args.pks {
//         let pk = if let Ok(key) = DescriptorSecretKey::from_str(&pk_str) {
//             let secp = Secp256k1::new();
//             key.to_public(&secp)
//                 .with_context(|| format!("Failed to convert string to public key: {}", pk_str))?
//         } else {
//             DescriptorPublicKey::from_str(&pk_str)
//                 .with_context(|| format!("Failed to parse public key string: {}", pk_str))?
//         };
//         pks.push(pk);
//     }

//     let decrypted_desc =
//         descriptor_encrypt::decrypt(&data_bytes, pks).context("Decryption failed")?;

//     println!("{}", decrypted_desc);

//     Ok(())
// }

// fn handle_get_template(args: GetTemplateArgs) -> Result<()> {
//     let data_bytes = hex::decode(&args.data).context("Failed to decode hex data")?;

//     let template_desc = descriptor_encrypt::get_template(&data_bytes)
//         .context("Failed to get template descriptor")?;

//     println!("{}", template_desc);

//     Ok(())
// }

// fn handle_get_derivation_paths(args: GetPathsArgs) -> Result<()> {
//     let data_bytes = hex::decode(&args.data).context("Failed to decode hex data")?;

//     let paths: Vec<DerivationPath> = descriptor_encrypt::get_origin_derivation_paths(&data_bytes)
//         .context("Failed to get origin derivation paths")?;

//     if paths.is_empty() {
//         println!("No origin derivation paths found in the descriptor.");
//     } else {
//         for path in paths {
//             println!("{}", path);
//         }
//     }

//     Ok(())
// }
