use thiserror::Error;

pub mod blob;
pub mod suite;
pub mod transcript;

#[cfg(test)]
mod vectors_tests;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum E2eError {
    #[error("hpke error: {0}")]
    Hpke(&'static str),
    #[error("signature error: {0}")]
    Signature(&'static str),
    #[error("invalid transcript or record CBOR: {0}")]
    Cbor(&'static str),
    #[error("non-canonical CBOR")]
    NonCanonicalCbor,
    #[error("invalid blob stream: {0}")]
    Blob(&'static str),
    #[error("range out of bounds")]
    RangeOutOfBounds,
    #[error("rng error")]
    Rng,
}
