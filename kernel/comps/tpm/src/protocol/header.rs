// SPDX-License-Identifier: MPL-2.0

//! TPM 2.0 command and response header handling.

use alloc::vec::Vec;

use crate::{
    error::{BufferError, TpmError},
    protocol::constants::{rc, tag},
};

/// Size of the TPM 2.0 command/response header.
pub const TPM_HEADER_SIZE: usize = 10;

/// TPM 2.0 command header.
#[derive(Debug, Clone, Copy)]
pub struct TpmCommandHeader {
    /// Command tag (e.g., TPM_ST_NO_SESSIONS).
    pub tag: u16,
    /// Total command size including header.
    pub size: u32,
    /// Command code.
    pub command_code: u32,
}

/// TPM 2.0 response header.
#[derive(Debug, Clone, Copy)]
pub struct TpmResponseHeader {
    /// Response tag.
    pub tag: u16,
    /// Total response size including header.
    pub size: u32,
    /// Response code.
    pub response_code: u32,
}

impl TpmCommandHeader {
    /// Creates a new command header.
    pub fn new(tag: u16, size: u32, command_code: u32) -> Self {
        Self {
            tag,
            size,
            command_code,
        }
    }

    /// Serializes the header to a byte vector in big-endian format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(TPM_HEADER_SIZE);
        buf.extend_from_slice(&self.tag.to_be_bytes());
        buf.extend_from_slice(&self.size.to_be_bytes());
        buf.extend_from_slice(&self.command_code.to_be_bytes());
        buf
    }
}

impl TpmResponseHeader {
    /// Parses a response header from a byte slice.
    ///
    /// Returns an error if the buffer is too short or contains invalid data.
    pub fn from_bytes(data: &[u8]) -> Result<Self, TpmError> {
        if data.len() < TPM_HEADER_SIZE {
            return Err(TpmError::Buffer(BufferError::TooShort));
        }

        let tag = u16::from_be_bytes([data[0], data[1]]);
        let size = u32::from_be_bytes([data[2], data[3], data[4], data[5]]);
        let response_code = u32::from_be_bytes([data[6], data[7], data[8], data[9]]);

        // Validate tag
        if tag != tag::TPM_ST_RSP_NO_SESSIONS && tag != tag::TPM_ST_RSP_SESSIONS {
            return Err(TpmError::Buffer(BufferError::InvalidTag(tag)));
        }

        // Validate size with checked comparison
        let size_usize = size as usize;
        if size_usize > data.len() {
            return Err(TpmError::Buffer(BufferError::SizeMismatch {
                expected: size_usize,
                actual: data.len(),
            }));
        }

        if size_usize < TPM_HEADER_SIZE {
            return Err(TpmError::Buffer(BufferError::TooShort));
        }

        Ok(Self {
            tag,
            size,
            response_code,
        })
    }

    /// Returns true if the response indicates success.
    pub fn is_success(&self) -> bool {
        self.response_code == rc::TPM_RC_SUCCESS
    }
}

/// Extracts the response body (parameters after the header).
pub fn response_body(data: &[u8]) -> Result<&[u8], TpmError> {
    if data.len() < TPM_HEADER_SIZE {
        return Err(TpmError::Buffer(BufferError::TooShort));
    }
    let header = TpmResponseHeader::from_bytes(data)?;
    let body_start = TPM_HEADER_SIZE;
    let body_end = header.size as usize;
    if body_end > data.len() {
        return Err(TpmError::Buffer(BufferError::ResponseTooLarge));
    }
    Ok(&data[body_start..body_end])
}

/// Reads a u32 from a byte slice at the given offset (big-endian).
pub fn read_u32_be(data: &[u8], offset: usize) -> Result<u32, TpmError> {
    let end = offset
        .checked_add(4)
        .ok_or(TpmError::Buffer(BufferError::Overflow))?;
    if end > data.len() {
        return Err(TpmError::Buffer(BufferError::TooShort));
    }
    Ok(u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]))
}

/// Reads a u16 from a byte slice at the given offset (big-endian).
pub fn read_u16_be(data: &[u8], offset: usize) -> Result<u16, TpmError> {
    let end = offset
        .checked_add(2)
        .ok_or(TpmError::Buffer(BufferError::Overflow))?;
    if end > data.len() {
        return Err(TpmError::Buffer(BufferError::TooShort));
    }
    Ok(u16::from_be_bytes([data[offset], data[offset + 1]]))
}

/// Writes a u32 to a byte vector in big-endian format.
pub fn write_u32_be(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_be_bytes());
}

/// Writes a u16 to a byte vector in big-endian format.
pub fn write_u16_be(buf: &mut Vec<u8>, value: u16) {
    buf.extend_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_header_to_bytes() {
        let header = TpmCommandHeader::new(0x8001, 22, 0x0000017A);
        let bytes = header.to_bytes();

        assert_eq!(bytes.len(), TPM_HEADER_SIZE);
        assert_eq!(u16::from_be_bytes([bytes[0], bytes[1]]), 0x8001);
        assert_eq!(
            u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]),
            22
        );
        assert_eq!(
            u32::from_be_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]),
            0x0000017A
        );
    }

    #[test]
    fn test_response_header_from_bytes_valid() {
        let mut data = vec![0u8; 20];
        // Valid tag
        data[0] = 0x80;
        data[1] = 0x01;
        // Size
        data[2] = 0x00;
        data[3] = 0x00;
        data[4] = 0x00;
        data[5] = 0x14;
        // Response code (success)
        data[6] = 0x00;
        data[7] = 0x00;
        data[8] = 0x00;
        data[9] = 0x00;

        let header = TpmResponseHeader::from_bytes(&data).unwrap();
        assert_eq!(header.tag, 0x8001);
        assert_eq!(header.size, 20);
        assert_eq!(header.response_code, 0);
        assert!(header.is_success());
    }

    #[test]
    fn test_response_header_too_short() {
        let data = [0u8; 5];
        assert!(TpmResponseHeader::from_bytes(&data).is_err());
    }

    #[test]
    fn test_response_header_invalid_tag() {
        let mut data = vec![0u8; 20];
        data[0] = 0x00; // Invalid tag
        data[1] = 0x00;
        data[2] = 0x00;
        data[3] = 0x00;
        data[4] = 0x00;
        data[5] = 0x14;

        assert!(TpmResponseHeader::from_bytes(&data).is_err());
    }

    #[test]
    fn test_response_header_size_too_large() {
        let mut data = vec![0u8; 20];
        data[0] = 0x80;
        data[1] = 0x01;
        // Size larger than buffer
        data[2] = 0x00;
        data[3] = 0x00;
        data[4] = 0x00;
        data[5] = 0xFF; // 255 > 20

        assert!(TpmResponseHeader::from_bytes(&data).is_err());
    }

    #[test]
    fn test_response_header_size_too_small() {
        let mut data = vec![0u8; 20];
        data[0] = 0x80;
        data[1] = 0x01;
        // Size smaller than header
        data[2] = 0x00;
        data[3] = 0x00;
        data[4] = 0x00;
        data[5] = 0x05; // 5 < 10

        assert!(TpmResponseHeader::from_bytes(&data).is_err());
    }

    #[test]
    fn test_response_body_valid() {
        let mut data = vec![0u8; 20];
        data[0] = 0x80;
        data[1] = 0x01;
        data[2] = 0x00;
        data[3] = 0x00;
        data[4] = 0x00;
        data[5] = 0x14;
        data[6] = 0x00;
        data[7] = 0x00;
        data[8] = 0x00;
        data[9] = 0x00;
        // Body
        data[10] = 0xAA;
        data[11] = 0xBB;

        let body = response_body(&data).unwrap();
        assert_eq!(body.len(), 10);
        assert_eq!(body[0], 0xAA);
        assert_eq!(body[1], 0xBB);
    }

    #[test]
    fn test_response_body_too_short() {
        let data = [0u8; 5];
        assert!(response_body(&data).is_err());
    }

    #[test]
    fn test_read_u32_be_valid() {
        let data = [0x01, 0x02, 0x03, 0x04, 0x05];
        assert_eq!(read_u32_be(&data, 0).unwrap(), 0x01020304);
        assert_eq!(read_u32_be(&data, 1).unwrap(), 0x02030405);
    }

    #[test]
    fn test_read_u32_be_overflow() {
        let data = [0u8; 10];
        assert!(read_u32_be(&data, usize::MAX).is_err());
    }

    #[test]
    fn test_read_u32_be_too_short() {
        let data = [0u8; 3];
        assert!(read_u32_be(&data, 0).is_err());
    }

    #[test]
    fn test_read_u16_be_valid() {
        let data = [0x01, 0x02, 0x03];
        assert_eq!(read_u16_be(&data, 0).unwrap(), 0x0102);
        assert_eq!(read_u16_be(&data, 1).unwrap(), 0x0203);
    }

    #[test]
    fn test_read_u16_be_overflow() {
        let data = [0u8; 10];
        assert!(read_u16_be(&data, usize::MAX).is_err());
    }

    #[test]
    fn test_read_u16_be_too_short() {
        let data = [0u8; 1];
        assert!(read_u16_be(&data, 0).is_err());
    }
}
