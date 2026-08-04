// SPDX-License-Identifier: MPL-2.0

//! Error types for the TPM subsystem.

use alloc::string::String;
use core::fmt;

/// Errors that can occur during TPM operations.
#[derive(Debug)]
pub enum TpmError {
    /// Transport layer communication failure.
    Transport(TransportError),
    /// TPM protocol error (non-zero response code).
    Protocol(u32),
    /// Buffer validation failure (malformed command or response).
    Buffer(BufferError),
    /// Chip not ready for commands.
    ChipNotReady(String),
}

/// Transport-specific errors.
#[derive(Debug)]
pub enum TransportError {
    /// MMIO access failed.
    MmioAccess,
    /// Locality request timed out.
    LocalityTimeout,
    /// Device not responding.
    DeviceNotResponding,
    /// Command too large for buffer.
    CommandTooLarge { size: usize, max: usize },
    /// Generic transport failure.
    Generic(&'static str),
}

/// Buffer validation errors.
#[derive(Debug)]
pub enum BufferError {
    /// Buffer too short for expected data.
    TooShort,
    /// Invalid TPM tag in header.
    InvalidTag(u16),
    /// Response size exceeds buffer capacity.
    ResponseTooLarge,
    /// Size mismatch between header and actual data.
    SizeMismatch { expected: usize, actual: usize },
    /// Arithmetic overflow in buffer calculation.
    Overflow,
    /// Generic buffer error.
    Generic(&'static str),
}

impl fmt::Display for TpmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TpmError::Transport(e) => write!(f, "TPM transport error: {:?}", e),
            TpmError::Protocol(code) => write!(f, "TPM protocol error: 0x{:08x}", code),
            TpmError::Buffer(e) => write!(f, "TPM buffer error: {:?}", e),
            TpmError::ChipNotReady(msg) => write!(f, "TPM chip not ready: {}", msg),
        }
    }
}

impl From<TransportError> for TpmError {
    fn from(err: TransportError) -> Self {
        TpmError::Transport(err)
    }
}

impl From<BufferError> for TpmError {
    fn from(err: BufferError) -> Self {
        TpmError::Buffer(err)
    }
}
