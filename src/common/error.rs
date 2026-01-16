//! Unified error types for the dazhbog codebase.

use std::fmt;

/// Error type for codec/protocol operations.
#[derive(Debug)]
pub enum CodecError {
    /// Not enough data available
    Short,
    /// Data format is invalid
    Malformed(&'static str),
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CodecError::Short => write!(f, "unexpected end of data"),
            CodecError::Malformed(msg) => write!(f, "malformed data: {}", msg),
        }
    }
}

impl std::error::Error for CodecError {}

/// Error type for Lumina protocol operations.
#[derive(Debug)]
pub enum LuminaError {
    /// Unexpected end of stream
    UnexpectedEof,
    /// Invalid data format
    InvalidData,
}

impl fmt::Display for LuminaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LuminaError::UnexpectedEof => write!(f, "unexpected EOF"),
            LuminaError::InvalidData => write!(f, "invalid data"),
        }
    }
}

impl std::error::Error for LuminaError {}

/// Error type for index operations.
pub enum IndexError {
    /// Index is full (capacity exceeded)
    #[allow(dead_code)]
    Full,
    /// I/O error
    Io(std::io::Error),
}

impl From<std::io::Error> for IndexError {
    fn from(e: std::io::Error) -> Self {
        IndexError::Io(e)
    }
}

impl fmt::Display for IndexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IndexError::Full => write!(f, "index is full"),
            IndexError::Io(e) => write!(f, "I/O error: {}", e),
        }
    }
}

impl fmt::Debug for IndexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IndexError::Full => write!(f, "IndexError::Full"),
            IndexError::Io(e) => write!(f, "IndexError::Io({:?})", e),
        }
    }
}

impl std::error::Error for IndexError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            IndexError::Io(e) => Some(e),
            _ => None,
        }
    }
}
