# ethers-signer-factory

**ethers-signer-factory** is a Rust crate that provides functions for key derivation and signing of Ethereum
transactions and messages.

## Features

- **Key Derivation:** Compute derived keys from a master key using HKDF-SHA512.
- **Address Generation:** Calculate the Ethereum address associated with a derived key.
- **Transaction Signing:** Sign Ethereum transactions using a derived key and obtain the generated signature.
- **Message Signing:** Sign Ethereum messages using a derived key and obtain the generated signature.
- **Typed Data Signing (EIP-712)**: Sign EIP-712 typed data using a derived key and obtain the generated signature.

## Getting Started

To use **ethers-signer-factory** in your Rust project, add it as a dependency in your `Cargo.toml` file:

```toml
[dependencies]
ethers-signer-factory = "2.0.0"
```

## Usage

```rust
use ethers_signer_factory::{get_derived_key, get_wallet_address, sign_transaction, sign_message};
use ethers_contract_derive::{Eip712, EthAbiType};
use ethers_core::types::transaction::eip2718::TypedTransaction;
use ethers_core::types::{TransactionRequest, Address};

#[tokio::main]
async fn main() {
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

    // Example 3. Get a Signer Wallet from the derived key.
    let chain_id = 1;
    let _wallet = get_signer(&key, &salt, info, chain_id).expect("Signer creation failed");

    // Example 4: Sign a transaction.
    let tx = TypedTransaction::Legacy(TransactionRequest::default().from(wallet_address));
    let signed_tx =
        sign_transaction(&key, &salt, info, &tx).expect("Transaction signing failed");

    assert_eq!(
        hex::encode(signed_tx.to_vec().as_slice()).as_str(),
        "815dd9b736c52fed571b2d5d985c52d78593a6d4a602f8455e884371270760132c8cd1f163af8303dc83aaaf48d2a03bff3697f6c922951809c19c0593841b3426"
    );

    // Example 5: Sign a message.
    let message = "Some message to sign";
    let signature = sign_message(&key, &salt, info, message).expect("Message signing failed");

    assert_eq!(
        hex::encode(signature.to_vec().as_slice()).as_str(),
        "35867e62e5a2c4dd52947c0cbb4af6afc95564d5abb0584bec2f9669046f81aa0d22dba8e6844fb125b93fec9a3e3684916dc4541e45bdc824cf18b5ab2409c81c"
    );

    // Example 6: Sign Typed data.
    #[derive(Clone, Default, EthAbiType, Eip712)]
    struct TestTypedData {
        value: u32,
    }

    let test_payload = TestTypedData { value: 1 };
    let signature = sign_typed_data(&key, &salt, info, &test_payload)
        .await
        .expect("Sign typed data failed");

    assert_eq!(
        hex::encode(signature.to_vec().as_slice()).as_str(),
        "cdd86e133a50b7d2c4f5bff092dbfe4086ed559bb0718e9c1c9bce31171f0ff44df3cc0dcd20388ad99be26b6eca0c104bff48eb6ad8135bec9d76aee2c6930f1b"
    );
}
```

## License

This code is licensed under the MIT License.