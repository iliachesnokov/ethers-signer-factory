#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    UnspecifiedRingError(#[from] ring::error::Unspecified),
    #[error(transparent)]
    WalletError(#[from] ethers_signers::WalletError),
}
