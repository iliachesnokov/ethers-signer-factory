#[derive(Debug)]
pub enum Error {
    UnspecifiedRingError(ring::error::Unspecified),
    WalletError(ethers_signers::WalletError),
}

impl From<ring::error::Unspecified> for Error {
    fn from(value: ring::error::Unspecified) -> Self {
        Error::UnspecifiedRingError(value)
    }
}

impl From<ethers_signers::WalletError> for Error {
    fn from(value: ethers_signers::WalletError) -> Self {
        Error::WalletError(value)
    }
}
