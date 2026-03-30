// SPDX-License-Identifier: MPL-2.0

//! TPM transport layer.

pub mod crb;
pub mod tis;

use alloc::vec::Vec;

use crate::error::TpmError;

/// Trait for TPM hardware transport backends.
///
/// Implementations of this trait handle the low-level communication
/// with a TPM device (e.g., via CRB, TIS/FIFO).
pub trait TpmTransport: Send + Sync {
    /// Sends a command to the TPM.
    ///
    /// # Arguments
    /// * `cmd` - Command buffer to send
    ///
    /// # Errors
    /// Returns an error if the command cannot be sent.
    fn send(&self, cmd: &[u8]) -> Result<(), TpmError>;

    /// Receives a response from the TPM.
    ///
    /// # Returns
    /// Response buffer from the TPM.
    ///
    /// # Errors
    /// Returns an error if the response cannot be received.
    fn recv(&self) -> Result<Vec<u8>, TpmError>;
}
