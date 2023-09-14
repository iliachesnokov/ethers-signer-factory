# ethers-signer-factory

**ethers-signer-factory** is a Rust crate that provides functions for key derivation and signing of Ethereum
transactions and messages.

## Features

- **Key Derivation:** Compute derived keys from a master key using HKDF-SHA512.
- **Address Generation:** Calculate the Ethereum address associated with a derived key.
- **Transaction Signing:** Sign Ethereum transactions using a derived key and obtain the RLP-encoded transaction with
  the attached signature.
- **Message Signing:** Sign Ethereum messages using a derived key and obtain the generated signature.

## Getting Started

To use **ethers-signer-factory** in your Rust project, add it as a dependency in your `Cargo.toml` file:

```toml
[dependencies]
ethers-signer-factory = "1.0.0"
```

## Usage

```rust
use ethers_signer_factory::{get_derived_key, get_wallet_address, sign_transaction, sign_message};
use ethers_core::types::transaction::eip2718::TypedTransaction;
use ethers_core::types::{TransactionRequest, Address};

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
    let wallet_address: Address = get_wallet_address(&key, &salt, info).expect("Wallet creation failed");
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
```

## License

This code is licensed under the MIT License.