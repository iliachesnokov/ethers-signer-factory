//! # Key Derivation and Signing Functions
//!
//! This crate provides a set of functions for key derivation and signing of Ethereum transactions
//! and messages. It uses the HKDF (HMAC-based Key Derivation Function) with SHA-512 as the base
//! key derivation algorithm and SHA-256 for expanding keys.
//!
//! ## Functions
//!
//! - `get_derived_key`: Computes a derived key of length SHA256_OUTPUT_LEN bytes using HKDF-SHA512.
//! - `get_wallet_address`: Computes the Ethereum address associated with a derived key.
//! - `sign_transaction`: Signs an Ethereum transaction using a derived key and returns the
//!   RLP-encoded transaction with the attached signature.
//! - `sign_message`: Signs an Ethereum message using a derived key and returns the generated
//!   signature.
//!
//! ## Example
//!
//! ```rust
//! use ethers_signer_factory::{get_derived_key, get_wallet_address, sign_transaction, sign_message};
//! use ethers_core::types::transaction::eip2718::TypedTransaction;
//! use ethers_core::types::{TransactionRequest, Address};
//!
//! let key: [u8; 64] = [0u8; 64];
//! let salt: [u8; 64] = [0u8; 64];
//! let info = "some_key_id";
//!
//! // Example 1: Derive a key.
//! let derived_key = get_derived_key(&key, &salt, info).expect("Key derivation failed");
//! assert_eq!(
//!     hex::encode(derived_key).as_str(),
//!     "de61002dc1676e6b59b2dd27da3f32280defe3bc384f77de6eee372f70ceaae7"
//! );
//!
//! // Example 2: Get an Ethereum address from the derived key.
//! let wallet_address: Address = get_wallet_address(&key, &salt, info).expect("Wallet creation failed");
//! assert_eq!(
//!     hex::encode(wallet_address.as_bytes()).as_str(),
//!     "ea4d3e00f3d283cdb0e4d4fb783f208a5095fcb7"
//! );
//!
//! // Example 3: Sign a transaction.
//! let tx = TypedTransaction::Legacy(TransactionRequest::default().from(wallet_address));
//! let signed_tx =
//!     sign_transaction(&key, &salt, info, &tx).expect("Transaction signing failed");
//!
//! assert_eq!(
//!     hex::encode(signed_tx.to_vec().as_slice()).as_str(),
//!     "f84980808080808026a0815dd9b736c52fed571b2d5d985c52d78593a6d4a602f8455e88437127076013a02c8cd1f163af8303dc83aaaf48d2a03bff3697f6c922951809c19c0593841b34"
//! );
//!
//! // Example 4: Sign a message.
//! let message = "Some message to sign";
//! let signature = sign_message(&key, &salt, info, message).expect("Message signing failed");
//!
//! assert_eq!(
//!     hex::encode(signature.to_vec().as_slice()).as_str(),
//!     "35867e62e5a2c4dd52947c0cbb4af6afc95564d5abb0584bec2f9669046f81aa0d22dba8e6844fb125b93fec9a3e3684916dc4541e45bdc824cf18b5ab2409c81c"
//! );
//! ```
//!
//! ## Dependencies
//!
//! This crate depends on the following external libraries:
//!
//! - `ethers_core`: Ethereum core library for types and utilities.
//! - `ethers_signers`: Ethereum wallet and signing functionality.
//! - `ring`: Cryptographic library for key derivation.
//! - `hex`: Hex strings encoding and decoding library.
//!
//! ## Error Handling
//!
//! Functions in this crate return a `Result` type that can contain errors specific to key
//! derivation and signing. Refer to the individual function documentation for details on error
//! types and how to handle them.

use ethers_core::k256::ecdsa::SigningKey;
use ethers_core::types::{transaction::eip2718::TypedTransaction, Address, Bytes, Signature};
use ethers_core::utils::secret_key_to_address;
use ethers_signers::Wallet;
use ring::digest::{SHA256_OUTPUT_LEN, SHA512_OUTPUT_LEN};
use ring::hkdf;

pub mod error;

type Result<T> = std::result::Result<T, error::Error>;

/// Derives a cryptographic key of length 32 bytes using the HKDF-SHA512
/// key derivation function. The input key and salt must both be 64 bytes each.
///
/// # Arguments
///
/// * `key` - The input key material.
/// * `salt` - The salt value used for salt extraction.
/// * `info` - A string that serves as additional context for key derivation.
///
/// # Returns
///
/// A Result containing the derived key as a fixed-size array of 32 bytes or an error if
/// key derivation fails.
pub fn get_derived_key(
    key: &[u8; SHA512_OUTPUT_LEN],
    salt: &[u8; SHA512_OUTPUT_LEN],
    info: &str,
) -> Result<[u8; SHA256_OUTPUT_LEN]> {
    // Create a Salt instance for HKDF-SHA512 using the exposed salt value.
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA512, salt);

    // Extract the PRK using the salt and exposed key value.
    let prk = salt.extract(key);

    // Convert the info string to bytes.
    let info = &[info.as_bytes()];

    // Expand the PRK using HKDF-SHA256 to obtain the output key material (OKM).
    let okm = prk.expand(info, hkdf::HKDF_SHA256)?;

    // Initialize a buffer to store the derived key.
    let mut buffer = [0u8; SHA256_OUTPUT_LEN];

    // Fill the buffer with the derived key material.
    okm.fill(&mut buffer)?;

    // Return the derived key buffer.
    Ok(buffer)
}

/// Derives a wallet address from the given input key material, salt, and info string.
///
/// # Arguments
///
/// * `key` - The input key material.
/// * `salt` - The salt value used for salt extraction.
/// * `info` - A string that serves as additional context for key derivation.
///
/// # Returns
///
/// A Result containing the Ethereum address associated with the derived key or an error
/// if key derivation or address generation fails.
pub fn get_wallet_address(
    key: &[u8; SHA512_OUTPUT_LEN],
    salt: &[u8; SHA512_OUTPUT_LEN],
    info: &str,
) -> Result<Address> {
    // Get the derived key buffer.
    let buffer = get_derived_key(key, salt, info)?;

    // Create a signing key from the derived key buffer.
    let signing_key = SigningKey::from_bytes(buffer.as_slice().into())
        .map_err(ethers_signers::WalletError::from)?;

    // Calculate the Ethereum address associated with the signing key.
    Ok(secret_key_to_address(&signing_key))
}

/// Signs a TypedTransaction using a derived key, salt, and info string.
///
/// # Arguments
///
/// * `key` - The input key material.
/// * `salt` - The salt value used for salt extraction.
/// * `info` - A string that serves as additional context for key derivation.
/// * `tx` - A TypedTransaction to be signed.
///
/// # Returns
///
/// A Result containing the RLP-encoded transaction with the attached signature or an error
/// if key derivation or transaction signing fails.
pub fn sign_transaction(
    key: &[u8; SHA512_OUTPUT_LEN],
    salt: &[u8; SHA512_OUTPUT_LEN],
    info: &str,
    tx: &TypedTransaction,
) -> Result<Bytes> {
    // Get the derived key buffer.
    let buffer = get_derived_key(key, salt, info)?;

    // Create a wallet from the derived key buffer.
    let wallet = Wallet::from_bytes(&buffer)?;

    // Sign the transaction using the wallet and obtain the signature.
    let signature = wallet.sign_transaction_sync(tx)?;

    // Return the RLP-encoded transaction with the attached signature.
    Ok(tx.rlp_signed(&signature))
}

/// Signs a message using a derived key, salt, and info string.
///
/// # Arguments
///
/// * `key` - The input key material.
/// * `salt` - The salt value used for salt extraction.
/// * `info` - A string that serves as additional context for key derivation.
/// * `message` - The message to be signed.
///
/// # Returns
///
/// A Result containing the cryptographic signature of the message or an error if key
/// derivation or message signing fails.
pub fn sign_message<M>(
    key: &[u8; SHA512_OUTPUT_LEN],
    salt: &[u8; SHA512_OUTPUT_LEN],
    info: &str,
    message: M,
) -> Result<Signature>
where
    M: AsRef<[u8]>,
{
    // Get the derived key buffer.
    let buffer = get_derived_key(key, salt, info)?;

    // Create a wallet from the derived key buffer.
    let wallet = Wallet::from_bytes(&buffer)?;

    // Hash the provided message to obtain the message hash.
    let message_hash = ethers_core::utils::hash_message(message);

    // Sign the message hash using the wallet and obtain the signature.
    let signature = wallet.sign_hash(message_hash)?;

    // Return the generated signature.
    Ok(signature)
}

#[cfg(test)]
mod tests {
    use ethers_core::types::transaction::eip2718::TypedTransaction;
    use ethers_core::types::TransactionRequest;

    use crate::{get_derived_key, get_wallet_address, sign_message, sign_transaction};

    #[test]
    fn main() {
        let key: [u8; 64] = [0u8; 64];
        let salt: [u8; 64] = [0u8; 64];

        let info = "some_key_id";

        // Example 1: Derive a key.
        let derived_key = get_derived_key(&key, &salt, info).expect("Key derivation failed");
        assert_eq!(
            hex::encode(derived_key).as_str(),
            "de61002dc1676e6b59b2dd27da3f32280defe3bc384f77de6eee372f70ceaae7"
        );

        // Example 2: Get an Ethereum address from the derived key.
        let wallet_address = get_wallet_address(&key, &salt, info).expect("Wallet creation failed");
        assert_eq!(
            hex::encode(wallet_address.as_bytes()).as_str(),
            "ea4d3e00f3d283cdb0e4d4fb783f208a5095fcb7"
        );

        // Example 3: Sign a transaction.
        let tx = TypedTransaction::Legacy(TransactionRequest::default().from(wallet_address));
        let signed_tx =
            sign_transaction(&key, &salt, info, &tx).expect("Transaction signing failed");

        assert_eq!(
            hex::encode(signed_tx.to_vec().as_slice()).as_str(),
            "f84980808080808026a0815dd9b736c52fed571b2d5d985c52d78593a6d4a602f8455e88437127076013a02c8cd1f163af8303dc83aaaf48d2a03bff3697f6c922951809c19c0593841b34"
        );

        // Example 4: Sign a message.
        let message = "Some message to sign";
        let signature = sign_message(&key, &salt, info, message).expect("Message signing failed");

        assert_eq!(
            hex::encode(signature.to_vec().as_slice()).as_str(),
            "35867e62e5a2c4dd52947c0cbb4af6afc95564d5abb0584bec2f9669046f81aa0d22dba8e6844fb125b93fec9a3e3684916dc4541e45bdc824cf18b5ab2409c81c"
        );
    }
}
