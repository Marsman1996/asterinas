// SPDX-License-Identifier: MPL-2.0

//! Transport bridge between the generic TPM chip layer and the Formal TPM HAL.

use alloc::vec::Vec;

use spin::Mutex;

use crate::{
    device,
    error::{TpmError, TransportError},
};

/// A command/response TPM transport.
pub trait TpmTransport: Send + Sync {
    fn send(&self, cmd: &[u8]) -> Result<(), TpmError>;
    fn recv(&self) -> Result<Vec<u8>, TpmError>;
}

/// Adapts the existing verified Formal TPM device to [`TpmTransport`].
pub struct FormalTransport {
    pending_command: Mutex<Option<Vec<u8>>>,
}

impl FormalTransport {
    pub const fn new() -> Self {
        Self {
            pending_command: Mutex::new(None),
        }
    }
}

impl TpmTransport for FormalTransport {
    fn send(&self, cmd: &[u8]) -> Result<(), TpmError> {
        let mut pending = self.pending_command.lock();
        if pending.is_some() {
            return Err(TransportError::Generic("a TPM command is already pending").into());
        }
        *pending = Some(cmd.to_vec());
        Ok(())
    }

    fn recv(&self) -> Result<Vec<u8>, TpmError> {
        let command = self
            .pending_command
            .lock()
            .take()
            .ok_or(TransportError::Generic("no TPM command is pending"))?;
        let device = device().ok_or(TransportError::DeviceNotResponding)?;
        let response_capacity = usize::try_from(device.limits().max_response)
            .unwrap_or(64 * 1024)
            .clamp(10, 64 * 1024);
        let mut response = alloc::vec![0; response_capacity];
        let response_len = device
            .exec(&command, &mut response)
            .map_err(|_| TransportError::DeviceNotResponding)?;
        response.truncate(response_len);
        Ok(response)
    }
}
