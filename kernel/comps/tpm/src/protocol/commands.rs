// SPDX-License-Identifier: MPL-2.0

//! TPM 2.0 command encoding and response parsing.

use alloc::{vec, vec::Vec};

use crate::{
    error::{BufferError, TpmError},
    protocol::{
        constants::{alg, capability, command, pcr, random, session, tag},
        header::{
            TPM_HEADER_SIZE, TpmCommandHeader, TpmResponseHeader, read_u16_be, read_u32_be,
            response_body, write_u16_be, write_u32_be,
        },
    },
};

/// Builds a TPM2_GetCapability command buffer.
///
/// # Arguments
/// * `cap` - Capability to query (e.g., TPM_CAP_TPM_PROPERTIES)
/// * `property` - Property to retrieve (e.g., TPM_PT_MANUFACTURER)
/// * `property_count` - Number of properties to retrieve
pub fn build_get_capability_command(cap: u32, property: u32, property_count: u32) -> Vec<u8> {
    let mut buf = Vec::new();

    // Parameters
    write_u32_be(&mut buf, cap);
    write_u32_be(&mut buf, property);
    write_u32_be(&mut buf, property_count);

    // Now fill in the header
    let total_size = TPM_HEADER_SIZE + buf.len();
    let header = TpmCommandHeader::new(
        tag::TPM_ST_NO_SESSIONS,
        total_size as u32,
        command::TPM2_GET_CAPABILITY,
    );

    let mut result = header.to_bytes();
    result.extend_from_slice(&buf);

    result
}

/// Builds a TPM2_Startup command buffer.
///
/// # Arguments
/// * `startup_type` - Startup type (e.g., TPM_SU_CLEAR)
pub fn build_startup_command(startup_type: u16) -> Vec<u8> {
    let mut params = Vec::new();

    // Parameters: startup type (u16)
    params.extend_from_slice(&startup_type.to_be_bytes());

    let total_size = TPM_HEADER_SIZE + params.len();
    let header = TpmCommandHeader::new(
        tag::TPM_ST_NO_SESSIONS,
        total_size as u32,
        command::TPM2_STARTUP,
    );

    let mut result = header.to_bytes();
    result.extend_from_slice(&params);

    result
}

/// Builds a TPM2_GetRandom command buffer.
///
/// # Arguments
/// * `num_bytes` - Number of random bytes to request (max 64)
///
/// # Errors
/// Returns error if num_bytes is 0 or exceeds TPM_MAX_RANDOM_BYTES
pub fn build_get_random_command(num_bytes: u16) -> Result<Vec<u8>, TpmError> {
    if num_bytes == 0 {
        return Err(TpmError::Buffer(BufferError::Generic(
            "num_bytes must be > 0",
        )));
    }

    if num_bytes as usize > random::TPM_MAX_RANDOM_BYTES {
        return Err(TpmError::Buffer(BufferError::Generic(
            "num_bytes exceeds maximum",
        )));
    }

    let mut params = Vec::new();

    // Parameters: num_bytes (u16)
    params.extend_from_slice(&num_bytes.to_be_bytes());

    let total_size = TPM_HEADER_SIZE + params.len();
    let header = TpmCommandHeader::new(
        tag::TPM_ST_NO_SESSIONS,
        total_size as u32,
        command::TPM2_GET_RANDOM,
    );

    let mut result = header.to_bytes();
    result.extend_from_slice(&params);

    Ok(result)
}

/// Parsed GetCapability response.
#[derive(Debug)]
pub struct GetCapabilityResponse {
    /// Whether more data is available.
    pub more_data: bool,
    /// Capability data.
    pub capability_data: CapabilityData,
}

/// Capability data from GetCapability response.
#[derive(Debug)]
pub enum CapabilityData {
    /// TPM properties.
    TpmProperties(Vec<TpmProperty>),
    /// Unknown capability.
    Unknown(u32),
}

/// A single TPM property.
#[derive(Debug)]
pub struct TpmProperty {
    /// Property tag.
    pub property: u32,
    /// Property value.
    pub value: u32,
}

/// Parsed GetRandom response.
#[derive(Debug)]
pub struct GetRandomResponse {
    /// Random bytes from the TPM.
    pub random_bytes: Vec<u8>,
}

/// Parses a GetCapability response.
pub fn parse_get_capability_response(data: &[u8]) -> Result<GetCapabilityResponse, TpmError> {
    let header = TpmResponseHeader::from_bytes(data)?;
    if !header.is_success() {
        return Err(TpmError::Protocol(header.response_code));
    }

    let body = response_body(data)?;

    if body.len() < 5 {
        return Err(TpmError::Buffer(BufferError::TooShort));
    }

    // Parse more_data flag (1 byte)
    let more_data = body[0] != 0;

    // Parse capability (u32)
    let cap = read_u32_be(body, 1)?;

    // Parse capability-specific data
    let cap_data = match cap {
        capability::TPM_CAP_TPM_PROPERTIES => {
            // Parse property list
            // Format: u32 count, then (u32 property, u32 value) pairs
            if body.len() < 9 {
                return Err(TpmError::Buffer(BufferError::TooShort));
            }
            let count = read_u32_be(body, 5)? as usize;
            let mut properties = Vec::with_capacity(count);
            let mut offset = 9;
            for _ in 0..count {
                if offset + 8 > body.len() {
                    return Err(TpmError::Buffer(BufferError::TooShort));
                }
                let property = read_u32_be(body, offset)?;
                let value = read_u32_be(body, offset + 4)?;
                properties.push(TpmProperty { property, value });
                offset = offset
                    .checked_add(8)
                    .ok_or(TpmError::Buffer(BufferError::Overflow))?;
            }
            CapabilityData::TpmProperties(properties)
        }
        other => CapabilityData::Unknown(other),
    };

    Ok(GetCapabilityResponse {
        more_data,
        capability_data: cap_data,
    })
}

/// Parses a GetRandom response.
pub fn parse_get_random_response(data: &[u8]) -> Result<GetRandomResponse, TpmError> {
    let header = TpmResponseHeader::from_bytes(data)?;
    if !header.is_success() {
        return Err(TpmError::Protocol(header.response_code));
    }

    let body = response_body(data)?;

    if body.len() < 2 {
        return Err(TpmError::Buffer(BufferError::TooShort));
    }

    // Parse size (u16)
    let size = u16::from_be_bytes([body[0], body[1]]) as usize;

    // Validate we have enough data
    let data_start = 2;
    if data_start + size > body.len() {
        return Err(TpmError::Buffer(BufferError::TooShort));
    }

    let random_bytes = body[data_start..data_start + size].to_vec();

    Ok(GetRandomResponse { random_bytes })
}

/// Builds a TPM2_PCR_Read command buffer.
///
/// # Arguments
/// * `pcr_index` - PCR index to read (0-23)
/// * `algorithm` - Hash algorithm (e.g., TPM_ALG_SHA256)
///
/// # Errors
/// Returns error if pcr_index is invalid (> 23)
pub fn build_pcr_read_command(pcr_index: u32, algorithm: u16) -> Result<Vec<u8>, TpmError> {
    if pcr_index >= pcr::TPM_MAX_PCRS {
        return Err(TpmError::Buffer(BufferError::Generic(
            "PCR index out of range",
        )));
    }

    let mut params = Vec::new();

    // PCR selection list:
    // - hash algorithm (u16)
    // - size of select (u8) - number of bytes in the bitmap
    // - select bitmap - which PCRs to read
    let select_size: u8 = 3; // 3 bytes covers PCRs 0-23
    let mut select = vec![0u8; select_size as usize];
    let byte_index = (pcr_index / 8) as usize;
    let bit_index = (pcr_index % 8) as u8;
    select[byte_index] = 1u8 << bit_index;

    write_u16_be(&mut params, algorithm);
    params.push(select_size);
    params.extend_from_slice(&select);

    let total_size = TPM_HEADER_SIZE + params.len();
    let header = TpmCommandHeader::new(
        tag::TPM_ST_NO_SESSIONS,
        total_size as u32,
        command::TPM2_PCR_READ,
    );

    let mut result = header.to_bytes();
    result.extend_from_slice(&params);

    Ok(result)
}

/// Parsed PCR_Read response.
#[derive(Debug)]
pub struct PcrReadResponse {
    /// Update counter for the PCR selection.
    pub update_counter: u32,
    /// PCR selection that was read.
    pub pcr_selection: PcrSelection,
    /// PCR digest values.
    pub digests: Vec<alloc::vec::Vec<u8>>,
}

/// PCR selection information.
#[derive(Debug)]
pub struct PcrSelection {
    /// Hash algorithm used.
    pub algorithm: u16,
    /// Number of bytes in select bitmap.
    pub size_of_select: u8,
    /// Bitmap of selected PCRs.
    pub select: alloc::vec::Vec<u8>,
}

/// Builds a TPM2_StartAuthSession command buffer.
///
/// # Arguments
/// * `tpm_key` - Handle of the tpmKey (TPM_RH_NULL for unbound sessions)
/// * `bind` - Handle of the bind entity (TPM_RH_NULL for unsalted sessions)
/// * `nonce_caller` - Initial nonce from caller
/// * `session_type` - Session type (HMAC, Policy, Trial)
/// * `symmetric` - Symmetric algorithm (TPM_ALG_NULL for no encryption)
/// * `auth_hash` - Hash algorithm for the session
pub fn build_start_auth_session_command(
    tpm_key: u32,
    bind: u32,
    nonce_caller: &[u8],
    session_type: u8,
    symmetric_algorithm: u16,
    symmetric_key_bits: u16,
    auth_hash: u16,
) -> Result<Vec<u8>, TpmError> {
    if nonce_caller.is_empty() {
        return Err(TpmError::Buffer(BufferError::Generic(
            "nonce_caller must not be empty",
        )));
    }

    let mut params = Vec::new();

    // tpmKey handle (u32)
    write_u32_be(&mut params, tpm_key);

    // bind handle (u32)
    write_u32_be(&mut params, bind);

    // nonceCaller (TPM2B_NONCE - size prefix + data)
    write_u16_be(&mut params, nonce_caller.len() as u16);
    params.extend_from_slice(nonce_caller);

    // encryptedSalt (TPM2B_ENCRYPTED_SECRET - empty for unsalted)
    write_u16_be(&mut params, 0);

    // sessionType (u8)
    params.push(session_type);

    // symmetric (TPMT_SYM_DEF)
    // algorithm (u16)
    write_u16_be(&mut params, symmetric_algorithm);
    if symmetric_algorithm != alg::TPM_ALG_NULL {
        // keyBits (u16)
        write_u16_be(&mut params, symmetric_key_bits);
        // mode (u16) - TPM_ALG_NULL for no mode
        write_u16_be(&mut params, alg::TPM_ALG_NULL);
    }

    // authHash (u16)
    write_u16_be(&mut params, auth_hash);

    let total_size = TPM_HEADER_SIZE + params.len();
    let header = TpmCommandHeader::new(
        tag::TPM_ST_NO_SESSIONS,
        total_size as u32,
        command::TPM2_START_AUTH_SESSION,
    );

    let mut result = header.to_bytes();
    result.extend_from_slice(&params);

    Ok(result)
}

/// Builds a TPM2_FlushContext command buffer.
///
/// # Arguments
/// * `flush_handle` - Handle of the resource to flush
pub fn build_flush_context_command(flush_handle: u32) -> Vec<u8> {
    let mut params = Vec::new();

    // flushHandle (u32)
    write_u32_be(&mut params, flush_handle);

    let total_size = TPM_HEADER_SIZE + params.len();
    let header = TpmCommandHeader::new(
        tag::TPM_ST_NO_SESSIONS,
        total_size as u32,
        command::TPM2_FLUSH_CONTEXT,
    );

    let mut result = header.to_bytes();
    result.extend_from_slice(&params);

    result
}

/// Builds a TPM2_ContextSave command buffer.
///
/// # Arguments
/// * `save_handle` - Handle of the resource to save
pub fn build_context_save_command(save_handle: u32) -> Vec<u8> {
    let mut params = Vec::new();

    // saveHandle (u32)
    write_u32_be(&mut params, save_handle);

    let total_size = TPM_HEADER_SIZE + params.len();
    let header = TpmCommandHeader::new(
        tag::TPM_ST_NO_SESSIONS,
        total_size as u32,
        command::TPM2_CONTEXT_SAVE,
    );

    let mut result = header.to_bytes();
    result.extend_from_slice(&params);

    result
}

/// Builds a TPM2_ContextLoad command buffer.
///
/// # Arguments
/// * `context_blob` - The context blob to load
pub fn build_context_load_command(context_blob: &[u8]) -> Vec<u8> {
    let mut params = Vec::new();

    // ContextLoad takes a raw `TPMS_CONTEXT` body with no outer size prefix.
    params.extend_from_slice(context_blob);

    let total_size = TPM_HEADER_SIZE + params.len();
    let header = TpmCommandHeader::new(
        tag::TPM_ST_NO_SESSIONS,
        total_size as u32,
        command::TPM2_CONTEXT_LOAD,
    );

    let mut result = header.to_bytes();
    result.extend_from_slice(&params);

    result
}

/// Parsed StartAuthSession response.
#[derive(Debug)]
pub struct StartAuthSessionResponse {
    /// Session handle.
    pub handle: u32,
    /// Initial nonce from TPM.
    pub nonce_tpm: Vec<u8>,
}

/// Parses a StartAuthSession response.
pub fn parse_start_auth_session_response(
    data: &[u8],
) -> Result<StartAuthSessionResponse, TpmError> {
    let header = TpmResponseHeader::from_bytes(data)?;
    if !header.is_success() {
        return Err(TpmError::Protocol(header.response_code));
    }

    let body = response_body(data)?;

    // Session handle (u32) - this is returned as the first 4 bytes
    if body.len() < 4 {
        return Err(TpmError::Buffer(BufferError::TooShort));
    }
    let handle = read_u32_be(body, 0)?;

    // nonceTPM (TPM2B_NONCE - size prefix + data)
    if body.len() < 6 {
        return Err(TpmError::Buffer(BufferError::TooShort));
    }
    let nonce_size = read_u16_be(body, 4)? as usize;
    let nonce_start = 6;
    let nonce_end = nonce_start + nonce_size;
    if nonce_end > body.len() {
        return Err(TpmError::Buffer(BufferError::TooShort));
    }
    let nonce_tpm = body[nonce_start..nonce_end].to_vec();

    Ok(StartAuthSessionResponse { handle, nonce_tpm })
}

/// Parses a FlushContext response (success only, no data).
pub fn parse_flush_context_response(data: &[u8]) -> Result<(), TpmError> {
    let header = TpmResponseHeader::from_bytes(data)?;
    if !header.is_success() {
        return Err(TpmError::Protocol(header.response_code));
    }
    Ok(())
}

/// Parses a TPM2_ContextSave response.
///
/// # Arguments
/// * `data` - Response buffer
///
/// # Returns
/// * `context_blob` - The context blob saved by the TPM
pub fn parse_context_save_response(data: &[u8]) -> Result<Vec<u8>, TpmError> {
    let header = TpmResponseHeader::from_bytes(data)?;
    if !header.is_success() {
        return Err(TpmError::Protocol(header.response_code));
    }

    let body = response_body(data)?;

    // `TPM2_ContextSave` returns a raw `TPMS_CONTEXT` body:
    // sequence (u64), savedHandle (u32), hierarchy (u32),
    // contextBlob.size (u16), contextBlob.buffer (variable).
    if body.len() < 18 {
        return Err(TpmError::Buffer(BufferError::TooShort));
    }

    let context_data_size = read_u16_be(body, 16)? as usize;
    let total_context_size = 18usize
        .checked_add(context_data_size)
        .ok_or(TpmError::Buffer(BufferError::Overflow))?;
    if total_context_size > body.len() {
        return Err(TpmError::Buffer(BufferError::TooShort));
    }

    Ok(body[..total_context_size].to_vec())
}

/// Parsed ContextLoad response.
#[derive(Debug)]
pub struct ContextLoadResponse {
    /// Loaded object or session handle.
    pub handle: u32,
}

/// Parses a TPM2_ContextLoad response.
///
/// # Arguments
/// * `data` - Response buffer
///
/// # Returns
/// * Loaded handle assigned by the TPM
pub fn parse_context_load_response(data: &[u8]) -> Result<ContextLoadResponse, TpmError> {
    let header = TpmResponseHeader::from_bytes(data)?;
    if !header.is_success() {
        return Err(TpmError::Protocol(header.response_code));
    }

    let body = response_body(data)?;
    if body.len() < 4 {
        return Err(TpmError::Buffer(BufferError::TooShort));
    }

    let handle = read_u32_be(body, 0)?;
    Ok(ContextLoadResponse { handle })
}

/// Parses a PCR_Read response.
pub fn parse_pcr_read_response(data: &[u8]) -> Result<PcrReadResponse, TpmError> {
    let header = TpmResponseHeader::from_bytes(data)?;
    if !header.is_success() {
        return Err(TpmError::Protocol(header.response_code));
    }

    let body = response_body(data)?;

    // Parse update counter (u32)
    if body.len() < 4 {
        return Err(TpmError::Buffer(BufferError::TooShort));
    }
    let update_counter = read_u32_be(body, 0)?;

    // Parse PCR selection
    let mut offset = 4;

    // Hash algorithm (u16)
    if offset + 2 > body.len() {
        return Err(TpmError::Buffer(BufferError::TooShort));
    }
    let algorithm = read_u16_be(body, offset)?;
    offset += 2;

    // Size of select (u8)
    if offset >= body.len() {
        return Err(TpmError::Buffer(BufferError::TooShort));
    }
    let size_of_select = body[offset];
    offset += 1;

    // Select bitmap
    let select_end = offset + size_of_select as usize;
    if select_end > body.len() {
        return Err(TpmError::Buffer(BufferError::TooShort));
    }
    let select = body[offset..select_end].to_vec();
    offset = select_end;

    // Parse digest list
    if offset + 4 > body.len() {
        return Err(TpmError::Buffer(BufferError::TooShort));
    }
    let digest_count = read_u32_be(body, offset)?;
    offset += 4;

    let mut digests = Vec::new();
    for _ in 0..digest_count {
        // Hash algorithm (u16)
        if offset + 2 > body.len() {
            return Err(TpmError::Buffer(BufferError::TooShort));
        }
        let _alg = read_u16_be(body, offset)?;
        offset += 2;

        // Digest size (u16)
        if offset + 2 > body.len() {
            return Err(TpmError::Buffer(BufferError::TooShort));
        }
        let digest_size = read_u16_be(body, offset)? as usize;
        offset += 2;

        // Digest value
        let digest_end = offset + digest_size;
        if digest_end > body.len() {
            return Err(TpmError::Buffer(BufferError::TooShort));
        }
        digests.push(body[offset..digest_end].to_vec());
        offset = digest_end;
    }

    Ok(PcrReadResponse {
        update_counter,
        pcr_selection: PcrSelection {
            algorithm,
            size_of_select,
            select,
        },
        digests,
    })
}

/// Builds a TPM2_PolicyPCR command buffer.
///
/// # Arguments
/// * `policy_session` - Session handle for the policy session
/// * `pcr_index` - PCR index to include in policy
/// * `algorithm` - Hash algorithm (e.g., TPM_ALG_SHA256)
pub fn build_policy_pcr_command(
    policy_session: u32,
    pcr_index: u32,
    algorithm: u16,
) -> Result<Vec<u8>, TpmError> {
    if pcr_index >= pcr::TPM_MAX_PCRS {
        return Err(TpmError::Buffer(BufferError::Generic(
            "PCR index out of range",
        )));
    }

    let mut params = Vec::new();

    // sessionHandle (u32)
    write_u32_be(&mut params, policy_session);

    // PCR selection list
    let select_size: u8 = 3; // 3 bytes covers PCRs 0-23
    let mut select = vec![0u8; select_size as usize];
    let byte_index = (pcr_index / 8) as usize;
    let bit_index = (pcr_index % 8) as u8;
    select[byte_index] = 1u8 << bit_index;

    // digest (empty for PolicyPCR)
    write_u16_be(&mut params, 0); // digest size = 0

    // pcrSelect
    write_u16_be(&mut params, algorithm);
    params.push(select_size);
    params.extend_from_slice(&select);

    let total_size = TPM_HEADER_SIZE + params.len();
    let header = TpmCommandHeader::new(
        tag::TPM_ST_NO_SESSIONS,
        total_size as u32,
        command::TPM2_POLICY_PCR,
    );

    let mut result = header.to_bytes();
    result.extend_from_slice(&params);

    Ok(result)
}

/// Builds a TPM2_PolicyGetDigest command buffer.
///
/// # Arguments
/// * `policy_session` - Session handle for the policy session
pub fn build_policy_get_digest_command(policy_session: u32) -> Vec<u8> {
    let mut params = Vec::new();

    // sessionHandle (u32)
    write_u32_be(&mut params, policy_session);

    let total_size = TPM_HEADER_SIZE + params.len();
    let header = TpmCommandHeader::new(
        tag::TPM_ST_NO_SESSIONS,
        total_size as u32,
        command::TPM2_POLICY_GET_DIGEST,
    );

    let mut result = header.to_bytes();
    result.extend_from_slice(&params);

    result
}

/// Builds a TPM2_NV_ReadPublic command buffer.
///
/// # Arguments
/// * `nv_index` - NV index to query
pub fn build_nv_read_public_command(nv_index: u32) -> Vec<u8> {
    let mut params = Vec::new();

    // nvIndex (u32)
    write_u32_be(&mut params, nv_index);

    let total_size = TPM_HEADER_SIZE + params.len();
    let header = TpmCommandHeader::new(
        tag::TPM_ST_NO_SESSIONS,
        total_size as u32,
        command::TPM2_NV_READ_PUBLIC,
    );

    let mut result = header.to_bytes();
    result.extend_from_slice(&params);

    result
}

/// Parses a PolicyGetDigest response.
pub fn parse_policy_get_digest_response(data: &[u8]) -> Result<Vec<u8>, TpmError> {
    let header = TpmResponseHeader::from_bytes(data)?;
    if !header.is_success() {
        return Err(TpmError::Protocol(header.response_code));
    }

    let body = response_body(data)?;

    if body.len() < 2 {
        return Err(TpmError::Buffer(BufferError::TooShort));
    }

    // Parse digest size (u16)
    let size = u16::from_be_bytes([body[0], body[1]]) as usize;
    let data_start = 2;

    if data_start + size > body.len() {
        return Err(TpmError::Buffer(BufferError::TooShort));
    }

    Ok(body[data_start..data_start + size].to_vec())
}

/// Builds a TPM2_NV_DefineSpace command buffer.
///
/// # Arguments
/// * `nv_index` - NV index to define
/// * `size` - Size of the NV space in bytes
/// * `attributes` - NV space attributes
pub fn build_nv_define_space_command(
    nv_index: u32,
    size: u16,
    attributes: u32,
) -> Result<Vec<u8>, TpmError> {
    if nv_index < 0x01000000 || nv_index >= 0x02000000 {
        return Err(TpmError::Buffer(BufferError::Generic(
            "NV index must be in range 0x01000000-0x01FFFFFF",
        )));
    }

    let mut params = Vec::new();

    // authHandle (TPM_RH_OWNER = 0x40000001)
    write_u32_be(&mut params, 0x40000001);

    // nvPublic (TPM2B_NV_PUBLIC)
    // size (u16) - filled at end
    let nv_public_start = params.len();
    write_u16_be(&mut params, 0); // placeholder

    // nvIndex (u32)
    write_u32_be(&mut params, nv_index);

    // nameAlg (u16) - TPM_ALG_SHA256
    write_u16_be(&mut params, 0x000B);

    // attributes (u32)
    write_u32_be(&mut params, attributes);

    // authPolicy (TPM2B_DIGEST) - empty
    write_u16_be(&mut params, 0);

    // dataSize (u16)
    write_u16_be(&mut params, size);

    // Calculate and fill nvPublic size
    let nv_public_size = (params.len() - nv_public_start - 2) as u16;
    params[nv_public_start..nv_public_start + 2].copy_from_slice(&nv_public_size.to_be_bytes());

    // auth (TPMS_AUTH_COMMAND) - password session with empty authValue
    write_u32_be(&mut params, session::TPM_RS_PW); // sessionHandle (TPM_RS_PW)
    write_u16_be(&mut params, 0); // nonce size
    write_u8(&mut params, 0); // sessionAttributes
    write_u16_be(&mut params, 0); // hmac size

    let total_size = TPM_HEADER_SIZE + params.len();
    let header = TpmCommandHeader::new(
        tag::TPM_ST_SESSIONS,
        total_size as u32,
        command::TPM2_NV_DEFINE_SPACE,
    );

    let mut result = header.to_bytes();
    result.extend_from_slice(&params);

    Ok(result)
}

/// Builds a TPM2_NV_Read command buffer.
///
/// # Arguments
/// * `nv_index` - NV index to read
/// * `size` - Number of bytes to read
/// * `offset` - Offset within the NV space
pub fn build_nv_read_command(nv_index: u32, size: u16, offset: u16) -> Vec<u8> {
    let mut params = Vec::new();

    // authHandle (nvIndex)
    write_u32_be(&mut params, nv_index);

    // nvIndex
    write_u32_be(&mut params, nv_index);

    // size (u16)
    write_u16_be(&mut params, size);

    // offset (u16)
    write_u16_be(&mut params, offset);

    let total_size = TPM_HEADER_SIZE + params.len();
    let header = TpmCommandHeader::new(
        tag::TPM_ST_NO_SESSIONS,
        total_size as u32,
        command::TPM2_NV_READ,
    );

    let mut result = header.to_bytes();
    result.extend_from_slice(&params);

    result
}

/// Builds a TPM2_NV_Write command buffer.
///
/// # Arguments
/// * `nv_index` - NV index to write
/// * `data` - Data to write
/// * `offset` - Offset within the NV space
pub fn build_nv_write_command(nv_index: u32, data: &[u8], offset: u16) -> Vec<u8> {
    let mut params = Vec::new();

    // authHandle (nvIndex)
    write_u32_be(&mut params, nv_index);

    // nvIndex
    write_u32_be(&mut params, nv_index);

    // data (TPM2B_MAX_NV_BUFFER)
    write_u16_be(&mut params, data.len() as u16);
    params.extend_from_slice(data);

    // offset (u16)
    write_u16_be(&mut params, offset);

    let total_size = TPM_HEADER_SIZE + params.len();
    let header = TpmCommandHeader::new(
        tag::TPM_ST_NO_SESSIONS,
        total_size as u32,
        command::TPM2_NV_WRITE,
    );

    let mut result = header.to_bytes();
    result.extend_from_slice(&params);

    result
}

/// Parses an NV_Read response.
pub fn parse_nv_read_response(data: &[u8]) -> Result<Vec<u8>, TpmError> {
    let header = TpmResponseHeader::from_bytes(data)?;
    if !header.is_success() {
        return Err(TpmError::Protocol(header.response_code));
    }

    let body = response_body(data)?;

    if body.len() < 2 {
        return Err(TpmError::Buffer(BufferError::TooShort));
    }

    // Parse data size (u16)
    let size = u16::from_be_bytes([body[0], body[1]]) as usize;
    let data_start = 2;

    if data_start + size > body.len() {
        return Err(TpmError::Buffer(BufferError::TooShort));
    }

    Ok(body[data_start..data_start + size].to_vec())
}

/// Helper to write u8 to buffer.
fn write_u8(buf: &mut Vec<u8>, value: u8) {
    buf.push(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_capability_command_round_trip() {
        let cmd = build_get_capability_command(
            capability::TPM_CAP_TPM_PROPERTIES,
            crate::protocol::constants::property::TPM_PT_MANUFACTURER,
            1,
        );

        // Verify header
        assert_eq!(cmd.len(), TPM_HEADER_SIZE + 12); // header + 3 * u32
        let header = TpmCommandHeader::new(
            tag::TPM_ST_NO_SESSIONS,
            cmd.len() as u32,
            command::TPM2_GET_CAPABILITY,
        );
        let expected_header = header.to_bytes();
        assert_eq!(&cmd[..TPM_HEADER_SIZE], &expected_header[..]);
    }

    #[test]
    fn test_startup_command() {
        let cmd = build_startup_command(crate::protocol::constants::startup::TPM_SU_CLEAR);
        assert_eq!(cmd.len(), TPM_HEADER_SIZE + 2); // header + u16
    }

    #[test]
    fn test_get_random_command() {
        let cmd = build_get_random_command(32).unwrap();
        assert_eq!(cmd.len(), TPM_HEADER_SIZE + 2); // header + u16

        // Verify command code
        let code = u32::from_be_bytes([cmd[6], cmd[7], cmd[8], cmd[9]]);
        assert_eq!(code, command::TPM2_GET_RANDOM);
    }

    #[test]
    fn test_get_random_command_zero_bytes() {
        assert!(build_get_random_command(0).is_err());
    }

    #[test]
    fn test_get_random_command_too_large() {
        assert!(build_get_random_command(100).is_err());
    }

    #[test]
    fn test_pcr_read_command() {
        let cmd = build_pcr_read_command(0, pcr::TPM_ALG_SHA256).unwrap();

        // Verify command code
        let code = u32::from_be_bytes([cmd[6], cmd[7], cmd[8], cmd[9]]);
        assert_eq!(code, command::TPM2_PCR_READ);

        // Header + algorithm (2) + size_of_select (1) + select (3) = 16 bytes
        assert_eq!(cmd.len(), TPM_HEADER_SIZE + 6);
    }

    #[test]
    fn test_pcr_read_command_invalid_index() {
        assert!(build_pcr_read_command(24, pcr::TPM_ALG_SHA256).is_err());
        assert!(build_pcr_read_command(100, pcr::TPM_ALG_SHA256).is_err());
    }

    #[test]
    fn test_pcr_read_command_pcr_selection() {
        // PCR 0 should set bit 0 of byte 0
        let cmd = build_pcr_read_command(0, pcr::TPM_ALG_SHA256).unwrap();
        let select_byte = cmd[TPM_HEADER_SIZE + 3]; // After algorithm (2) + size (1)
        assert_eq!(select_byte, 0x01);

        // PCR 7 should set bit 7 of byte 0
        let cmd = build_pcr_read_command(7, pcr::TPM_ALG_SHA256).unwrap();
        let select_byte = cmd[TPM_HEADER_SIZE + 3];
        assert_eq!(select_byte, 0x80);

        // PCR 8 should set bit 0 of byte 1
        let cmd = build_pcr_read_command(8, pcr::TPM_ALG_SHA256).unwrap();
        let select_byte = cmd[TPM_HEADER_SIZE + 4];
        assert_eq!(select_byte, 0x01);
    }

    #[test]
    fn test_parse_response_too_short() {
        let data = [0u8; 5];
        assert!(TpmResponseHeader::from_bytes(&data).is_err());
    }

    #[test]
    fn test_parse_response_invalid_tag() {
        let mut data = [0u8; 12];
        data[0] = 0x00; // Invalid tag
        data[1] = 0x01;
        assert!(TpmResponseHeader::from_bytes(&data).is_err());
    }

    #[test]
    fn test_start_auth_session_command() {
        let nonce = [0x01, 0x02, 0x03, 0x04];
        let cmd = build_start_auth_session_command(
            0x40000007, // TPM_RH_NULL
            0x40000007, // TPM_RH_NULL
            &nonce,
            session::TPM_SE_HMAC,
            alg::TPM_ALG_NULL,
            0,
            pcr::TPM_ALG_SHA256,
        )
        .unwrap();

        // Verify command code
        let code = u32::from_be_bytes([cmd[6], cmd[7], cmd[8], cmd[9]]);
        assert_eq!(code, command::TPM2_START_AUTH_SESSION);
    }

    #[test]
    fn test_start_auth_session_empty_nonce() {
        let result = build_start_auth_session_command(
            0x40000007,
            0x40000007,
            &[],
            session::TPM_SE_HMAC,
            alg::TPM_ALG_NULL,
            0,
            pcr::TPM_ALG_SHA256,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_flush_context_command() {
        let cmd = build_flush_context_command(0x02000000);

        // Verify command code
        let code = u32::from_be_bytes([cmd[6], cmd[7], cmd[8], cmd[9]]);
        assert_eq!(code, command::TPM2_FLUSH_CONTEXT);

        // Header + handle (4 bytes) = 14 bytes
        assert_eq!(cmd.len(), TPM_HEADER_SIZE + 4);
    }
}
