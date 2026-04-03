// SPDX-License-Identifier: MPL-2.0

//! TPM chip abstraction.

use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};
use core::sync::atomic::{AtomicU8, Ordering};

use log::{debug, error, info, warn};
use ostd::sync::Mutex;

use crate::{
    error::{BufferError, TpmError, TransportError},
    protocol::{
        commands::{
            build_context_load_command, build_context_save_command, build_flush_context_command,
            build_get_capability_command, build_get_random_command, build_nv_read_public_command,
            build_pcr_read_command, build_policy_get_digest_command, build_policy_pcr_command,
            build_start_auth_session_command, build_startup_command, parse_context_load_response,
            parse_context_save_response, parse_flush_context_response,
            parse_get_capability_response, parse_get_random_response, parse_pcr_read_response,
            parse_policy_get_digest_response, parse_start_auth_session_response,
            ContextLoadResponse, GetCapabilityResponse, PcrReadResponse,
        },
        constants::{alg, capability, handle, pcr, property, rc, session, startup, tag},
        header::{read_u16_be, read_u32_be, TpmCommandHeader, TpmResponseHeader, TPM_HEADER_SIZE},
    },
    resource::{TpmResource, TpmResourceManager, TpmResourceType},
    session::{TpmSession, TpmSessionManager, TpmSessionType},
    space::TpmSpace,
    transport::TpmTransport,
};

/// TPM chip initialization state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ChipState {
    /// Chip has not been initialized yet.
    Uninitialized = 0,
    /// Chip is initialized and ready for commands.
    Initialized = 1,
    /// Chip is in error state and needs reset.
    Error = 2,
}

impl From<u8> for ChipState {
    fn from(value: u8) -> Self {
        match value {
            0 => ChipState::Uninitialized,
            1 => ChipState::Initialized,
            _ => ChipState::Error,
        }
    }
}

/// Represents a single TPM 2.0 device.
///
/// The chip manages command execution lifecycle and provides
/// a high-level interface for TPM operations.
pub struct TpmChip {
    /// Transport backend for hardware communication.
    transport: Mutex<Box<dyn TpmTransport>>,
    /// Chip initialization state.
    state: AtomicU8,
    /// Resource manager for tracking TPM resources.
    resource_manager: TpmResourceManager,
    /// Session manager for tracking active sessions.
    session_manager: TpmSessionManager,
}

const TPM2_CC_CREATE_PRIMARY: u32 = 0x0000_0131;
const TPM2_CC_EVICT_CONTROL: u32 = 0x0000_0120;
const TPM2_CC_SEQUENCE_COMPLETE: u32 = 0x0000_013E;
const TPM2_CC_ACTIVATE_CREDENTIAL: u32 = 0x0000_0147;
const TPM2_CC_CERTIFY: u32 = 0x0000_0148;
const TPM2_CC_POLICY_NV: u32 = 0x0000_0149;
const TPM2_CC_CREATE: u32 = 0x0000_0153;
const TPM2_CC_CERTIFY_CREATION: u32 = 0x0000_014A;
const TPM2_CC_DUPLICATE: u32 = 0x0000_014B;
const TPM2_CC_GET_COMMAND_AUDIT_DIGEST: u32 = 0x0000_0133;
const TPM2_CC_GET_TIME: u32 = 0x0000_014C;
const TPM2_CC_GET_SESSION_AUDIT_DIGEST: u32 = 0x0000_014D;
const TPM2_CC_NV_CERTIFY: u32 = 0x0000_0184;
const TPM2_CC_GET_CAPABILITY: u32 = 0x0000_017A;
const TPM2_CC_ECDH_ZGEN: u32 = 0x0000_0154;
const TPM2_CC_HMAC: u32 = 0x0000_0155;
const TPM2_CC_HMAC_START: u32 = 0x0000_015B;
const TPM2_CC_SEQUENCE_UPDATE: u32 = 0x0000_015C;
const TPM2_CC_IMPORT: u32 = 0x0000_0156;
const TPM2_CC_LOAD: u32 = 0x0000_0157;
const TPM2_CC_LOAD_EXTERNAL: u32 = 0x0000_0167;
const TPM2_CC_REWRAP: u32 = 0x0000_0152;
const TPM2_CC_RSA_DECRYPT: u32 = 0x0000_0159;
const TPM2_CC_RSA_ENCRYPT: u32 = 0x0000_0174;
const TPM2_CC_SIGN: u32 = 0x0000_015D;
const TPM2_CC_QUOTE: u32 = 0x0000_0158;
const TPM2_CC_UNSEAL: u32 = 0x0000_015E;
const TPM2_CC_ECDH_KEY_GEN: u32 = 0x0000_0163;
const TPM2_CC_ENCRYPT_DECRYPT: u32 = 0x0000_0164;
const TPM2_CC_NV_READ: u32 = 0x0000_014E;
const TPM2_CC_NV_WRITE: u32 = 0x0000_0137;
const TPM2_CC_CONTEXT_SAVE: u32 = 0x0000_0162;
const TPM2_CC_FLUSH_CONTEXT: u32 = 0x0000_0165;
const TPM2_CC_MAKE_CREDENTIAL: u32 = 0x0000_0168;
const TPM2_CC_POLICY_COMMAND_CODE: u32 = 0x0000_016C;
const TPM2_CC_POLICY_AUTH_VALUE: u32 = 0x0000_016B;
const TPM2_CC_POLICY_AUTHORIZE: u32 = 0x0000_016A;
const TPM2_CC_POLICY_COUNTER_TIMER: u32 = 0x0000_016D;
const TPM2_CC_POLICY_CP_HASH: u32 = 0x0000_016E;
const TPM2_CC_POLICY_LOCALITY: u32 = 0x0000_016F;
const TPM2_CC_POLICY_NAME_HASH: u32 = 0x0000_0170;
const TPM2_CC_POLICY_OR: u32 = 0x0000_0171;
const TPM2_CC_POLICY_TICKET: u32 = 0x0000_0172;
const TPM2_CC_POLICY_PCR: u32 = 0x0000_017F;
const TPM2_CC_POLICY_RESTART: u32 = 0x0000_0180;
const TPM2_CC_OBJECT_CHANGE_AUTH: u32 = 0x0000_0150;
const TPM2_CC_POLICY_SECRET: u32 = 0x0000_0151;
const TPM2_CC_READ_PUBLIC: u32 = 0x0000_0173;
const TPM2_CC_VERIFY_SIGNATURE: u32 = 0x0000_0177;
const TPM2_CC_EVENT_SEQUENCE_COMPLETE: u32 = 0x0000_0185;
const TPM2_CC_HASH_SEQUENCE_START: u32 = 0x0000_0186;
const TPM2_CC_POLICY_DUPLICATION_SELECT: u32 = 0x0000_0188;
const TPM2_CC_POLICY_GET_DIGEST: u32 = 0x0000_0189;
const TPM2_CC_POLICY_PASSWORD: u32 = 0x0000_018C;
const TPM2_CC_COMMIT: u32 = 0x0000_018B;
const TPM2_CC_POLICY_NV_WRITTEN: u32 = 0x0000_018F;
const TPM2_CC_POLICY_TEMPLATE: u32 = 0x0000_0190;
const TPM2_CC_CREATE_LOADED: u32 = 0x0000_0191;
const TPM2_CC_POLICY_AUTHORIZE_NV: u32 = 0x0000_0192;
const TPM2_CC_POLICY_SIGNED: u32 = 0x0000_0160;
const TPM2_CC_ZGEN_2PHASE: u32 = 0x0000_018D;
const TPM2_CC_CONTEXT_LOAD: u32 = 0x0000_0161;
const TPM2_CC_ENCRYPT_DECRYPT2: u32 = 0x0000_0193;
const TPM2_CC_START_AUTH_SESSION: u32 = 0x0000_0176;

impl core::fmt::Debug for TpmChip {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TpmChip")
            .field("state", &self.get_state())
            .finish()
    }
}

impl TpmChip {
    /// Creates a new TPM chip with the given transport.
    ///
    /// # Arguments
    /// * `transport` - Transport backend for hardware communication
    pub fn new(transport: impl TpmTransport + 'static) -> Self {
        Self {
            transport: Mutex::new(Box::new(transport)),
            state: AtomicU8::new(ChipState::Uninitialized as u8),
            resource_manager: TpmResourceManager::new(),
            session_manager: TpmSessionManager::new(),
        }
    }

    /// Returns a reference to the resource manager.
    pub fn resource_manager(&self) -> &TpmResourceManager {
        &self.resource_manager
    }

    /// Returns a reference to the session manager.
    pub fn session_manager(&self) -> &TpmSessionManager {
        &self.session_manager
    }

    /// Returns the current chip state.
    pub fn get_state(&self) -> ChipState {
        ChipState::from(self.state.load(Ordering::Acquire))
    }

    /// Sets the chip state.
    fn set_state(&self, new_state: ChipState) {
        let old_state = self.get_state();
        self.state.store(new_state as u8, Ordering::Release);
        if old_state != new_state {
            info!("TPM: chip state {:?} -> {:?}", old_state, new_state);
        }
    }

    /// Resets the chip state to Uninitialized.
    ///
    /// This can be used to recover from error state.
    pub fn reset(&self) {
        debug!("TPM: resetting chip state");
        self.set_state(ChipState::Uninitialized);
    }

    /// Forces the chip to Initialized state.
    ///
    /// Use this when you know the TPM is already initialized
    /// (e.g., by firmware or previous boot).
    pub fn force_initialized(&self) {
        debug!("TPM: forcing chip to Initialized state");
        self.set_state(ChipState::Initialized);
    }

    /// Sends a TPM2_Startup command to initialize the TPM.
    ///
    /// This should be called after device discovery to bring the TPM
    /// out of the idle state and into a ready state for command processing.
    pub fn startup(&self) -> Result<(), TpmError> {
        if self.get_state() == ChipState::Initialized {
            debug!("TPM: chip already initialized");
            return Ok(());
        }

        info!("TPM: sending Startup(CLEAR) command");
        let cmd = build_startup_command(startup::TPM_SU_CLEAR);
        match self.execute_command(&cmd) {
            Ok(_) => {
                self.set_state(ChipState::Initialized);
                info!("TPM: startup complete");
                Ok(())
            }
            Err(e) => {
                // Don't set error state - TPM might already be initialized
                // by firmware or previous boot. Just mark as initialized.
                warn!(
                    "TPM: startup command returned error (may already be initialized): {:?}",
                    e
                );
                self.set_state(ChipState::Initialized);
                Ok(())
            }
        }
    }

    /// Validates a command buffer before sending.
    ///
    /// Returns the parsed command header if valid.
    fn validate_command(cmd: &[u8]) -> Result<TpmCommandHeader, TpmError> {
        if cmd.is_empty() {
            return Err(TpmError::Buffer(BufferError::TooShort));
        }

        if cmd.len() < TPM_HEADER_SIZE {
            return Err(TpmError::Buffer(BufferError::TooShort));
        }

        // Use checked indexing for safety
        let tag = u16::from_be_bytes([cmd[0], cmd[1]]);
        let size = u32::from_be_bytes([cmd[2], cmd[3], cmd[4], cmd[5]]);
        let command_code = u32::from_be_bytes([cmd[6], cmd[7], cmd[8], cmd[9]]);

        // Validate tag
        if tag != tag::TPM_ST_NO_SESSIONS && tag != tag::TPM_ST_SESSIONS {
            warn!("TPM: invalid command tag 0x{:04x}", tag);
            return Err(TpmError::Buffer(BufferError::InvalidTag(tag)));
        }

        // Validate size matches buffer length
        if size as usize != cmd.len() {
            warn!(
                "TPM: command size mismatch: header={}, actual={}",
                size,
                cmd.len()
            );
            return Err(TpmError::Buffer(BufferError::SizeMismatch {
                expected: size as usize,
                actual: cmd.len(),
            }));
        }

        Ok(TpmCommandHeader {
            tag,
            size,
            command_code,
        })
    }

    /// Validates a response buffer after receiving.
    ///
    /// Returns the parsed response header if valid.
    /// Note: This only validates the response structure, not the response code.
    /// A valid response with a nonzero TPM RC is still returned successfully.
    fn validate_response(response: &[u8]) -> Result<TpmResponseHeader, TpmError> {
        if response.is_empty() {
            warn!("TPM: response is empty");
            return Err(TpmError::Buffer(BufferError::TooShort));
        }

        if response.len() < TPM_HEADER_SIZE {
            warn!(
                "TPM: response too short: {} bytes (minimum {})",
                response.len(),
                TPM_HEADER_SIZE
            );
            return Err(TpmError::Buffer(BufferError::TooShort));
        }

        let header = TpmResponseHeader::from_bytes(response)?;

        // Validate size matches actual data length
        if header.size as usize != response.len() {
            warn!(
                "TPM: response size mismatch: header={}, actual={}",
                header.size,
                response.len()
            );
            return Err(TpmError::Buffer(BufferError::SizeMismatch {
                expected: header.size as usize,
                actual: response.len(),
            }));
        }

        // Note: We do NOT return an error here for nonzero response codes.
        // Valid TPM error responses should be preserved and returned to userspace.
        if !header.is_success() {
            debug!(
                "TPM: command returned nonzero response code 0x{:08x} (preserved for userspace)",
                header.response_code
            );
        }

        Ok(header)
    }

    /// Executes a raw TPM command and returns the response.
    ///
    /// This method serializes command execution per chip, ensuring
    /// only one command is processed at a time.
    ///
    /// # Arguments
    /// * `cmd` - Raw command buffer
    ///
    /// # Returns
    /// Response buffer from the TPM (may be a success or error response)
    ///
    /// # Errors
    /// Returns an error only for transport failures or malformed responses.
    /// Valid TPM responses with nonzero RC are returned successfully.
    pub fn execute_command(&self, cmd: &[u8]) -> Result<Vec<u8>, TpmError> {
        // Check chip state
        let state = self.get_state();
        if state == ChipState::Error {
            return Err(TpmError::ChipNotReady("chip is in error state".into()));
        }

        // Allow startup command even when uninitialized
        let is_startup = cmd.len() >= TPM_HEADER_SIZE
            && u32::from_be_bytes([cmd[6], cmd[7], cmd[8], cmd[9]]) == 0x00000144;

        if state == ChipState::Uninitialized && !is_startup {
            return Err(TpmError::ChipNotReady("chip not initialized".into()));
        }

        debug!("TPM: executing command ({} bytes)", cmd.len());

        // Validate command header
        let cmd_header = Self::validate_command(cmd)?;
        debug!(
            "TPM: command tag=0x{:04x} size={} code=0x{:08x}",
            cmd_header.tag, cmd_header.size, cmd_header.command_code
        );

        // Acquire lock for command serialization
        let transport = self.transport.lock();

        // Send command
        transport.send(cmd).map_err(|e| {
            warn!("TPM: send failed: {:?}", e);
            e
        })?;

        // Receive response
        let response = transport.recv().map_err(|e| {
            warn!("TPM: recv failed: {:?}", e);
            e
        })?;

        // Validate response structure (but not response code)
        let header = Self::validate_response(&response)?;

        // Log response info
        if header.is_success() {
            debug!("TPM: response received ({} bytes, success)", response.len());
        } else {
            debug!(
                "TPM: response received ({} bytes, rc=0x{:08x})",
                response.len(),
                header.response_code
            );
        }

        // Return the response regardless of TPM RC
        Ok(response)
    }

    /// Executes a raw TPM command and checks for success.
    ///
    /// This is a convenience method that returns an error if the TPM
    /// returns a nonzero response code.
    ///
    /// # Arguments
    /// * `cmd` - Raw command buffer
    ///
    /// # Returns
    /// Response buffer from the TPM
    ///
    /// # Errors
    /// Returns an error for transport failures, malformed responses, or nonzero TPM RC.
    pub fn execute_command_expect_success(&self, cmd: &[u8]) -> Result<Vec<u8>, TpmError> {
        let response = self.execute_command(cmd)?;

        // Check if response indicates success
        let header = TpmResponseHeader::from_bytes(&response)?;
        if !header.is_success() {
            return Err(TpmError::Protocol(header.response_code));
        }

        Ok(response)
    }

    /// Executes a GetCapability command.
    ///
    /// # Arguments
    /// * `cap` - Capability to query
    /// * `property` - Property to retrieve
    /// * `property_count` - Number of properties to retrieve
    ///
    /// # Returns
    /// Parsed GetCapability response
    pub fn get_capability(
        &self,
        cap: u32,
        property: u32,
        property_count: u32,
    ) -> Result<GetCapabilityResponse, TpmError> {
        let cmd = build_get_capability_command(cap, property, property_count);
        let response = self.execute_command_expect_success(&cmd)?;
        parse_get_capability_response(&response)
    }

    /// Gets the TPM manufacturer.
    pub fn get_manufacturer(&self) -> Result<u32, TpmError> {
        let response = self.get_capability(
            capability::TPM_CAP_TPM_PROPERTIES,
            property::TPM_PT_MANUFACTURER,
            1,
        )?;

        match response.capability_data {
            crate::protocol::commands::CapabilityData::TpmProperties(props) => {
                if let Some(prop) = props.first() {
                    Ok(prop.value)
                } else {
                    Err(TpmError::Protocol(rc::TPM_RC_BAD_TAG))
                }
            }
            _ => Err(TpmError::Protocol(rc::TPM_RC_BAD_TAG)),
        }
    }

    /// Gets random bytes from the TPM.
    ///
    /// # Arguments
    /// * `num_bytes` - Number of random bytes to request (max 64 per call)
    ///
    /// # Returns
    /// Random bytes from the TPM
    pub fn get_random(&self, num_bytes: usize) -> Result<Vec<u8>, TpmError> {
        if num_bytes == 0 {
            return Ok(Vec::new());
        }

        let cmd = build_get_random_command(num_bytes as u16)?;
        let response = self.execute_command_expect_success(&cmd)?;
        let random_response = parse_get_random_response(&response)?;
        Ok(random_response.random_bytes)
    }

    /// Reads a PCR value from the TPM.
    ///
    /// # Arguments
    /// * `pcr_index` - PCR index to read (0-23)
    /// * `algorithm` - Hash algorithm (e.g., TPM_ALG_SHA256)
    ///
    /// # Returns
    /// PCR read response with digest values
    pub fn pcr_read(&self, pcr_index: u32, algorithm: u16) -> Result<PcrReadResponse, TpmError> {
        let cmd = build_pcr_read_command(pcr_index, algorithm)?;
        let response = self.execute_command_expect_success(&cmd)?;
        parse_pcr_read_response(&response)
    }

    /// Reads a PCR value using SHA-256 algorithm.
    ///
    /// # Arguments
    /// * `pcr_index` - PCR index to read (0-23)
    ///
    /// # Returns
    /// PCR digest value (32 bytes for SHA-256)
    pub fn pcr_read_sha256(&self, pcr_index: u32) -> Result<Vec<u8>, TpmError> {
        let response = self.pcr_read(pcr_index, pcr::TPM_ALG_SHA256)?;
        if let Some(digest) = response.digests.first() {
            Ok(digest.clone())
        } else {
            Err(TpmError::Protocol(rc::TPM_RC_BAD_TAG))
        }
    }

    /// Starts a new authorization session.
    ///
    /// # Arguments
    /// * `session_type` - Session type (HMAC, Policy, Trial)
    /// * `auth_hash` - Hash algorithm for the session
    /// * `symmetric_algorithm` - Symmetric algorithm (TPM_ALG_NULL for no encryption)
    ///
    /// # Returns
    /// Response buffer from TPM (may be success or error response)
    ///
    /// # Errors
    /// Returns an error only for transport failures or malformed responses.
    /// Valid TPM error responses are returned as the response buffer.
    pub fn start_auth_session(
        &self,
        session_type: u8,
        auth_hash: u16,
        symmetric_algorithm: u16,
    ) -> Result<Vec<u8>, TpmError> {
        // Generate a nonce (use random bytes from TPM)
        let nonce = self.get_random(32)?;

        let cmd = build_start_auth_session_command(
            handle::TPM_HT_PERMANENT + 7, // TPM_RH_NULL for tpm_key
            handle::TPM_HT_PERMANENT + 7, // TPM_RH_NULL for bind
            &nonce,
            session_type,
            symmetric_algorithm,
            0, // key_bits (0 for TPM_ALG_NULL)
            auth_hash,
        )?;

        // Execute command - returns response even if TPM returns error RC
        let response = self.execute_command(&cmd)?;

        // Try to parse the response - if successful, track the session
        if let Ok(session_response) = parse_start_auth_session_response(&response) {
            // Determine session type enum from byte
            let session_type_enum = match session_type {
                0 => TpmSessionType::Hmac,
                1 => TpmSessionType::Policy,
                3 => TpmSessionType::Trial,
                _ => TpmSessionType::Hmac, // Default
            };

            // Create and track the session
            let mut session =
                TpmSession::new(session_response.handle, session_type_enum, auth_hash);
            session.auth_mut().nonce_tpm = session_response.nonce_tpm.clone();
            self.session_manager.add_session(session);

            // Track the real TPM session handle so `flush_context` can release
            // the same resource entry it later looks up by handle.
            self.resource_manager.insert_resource(TpmResource {
                handle: session_response.handle,
                resource_type: session_type_enum.resource_type(),
                data: alloc::vec![],
                public_area: None,
                private_area: None,
                name: None,
                last_used: 0,
            });

            info!(
                "TPM: started auth session with handle 0x{:08x}",
                session_response.handle
            );
        }

        // Return the response regardless of success/failure
        Ok(response)
    }

    /// Starts an HMAC session.
    ///
    /// # Arguments
    /// * `auth_hash` - Hash algorithm for the session (e.g., TPM_ALG_SHA256)
    ///
    /// # Returns
    /// Response buffer from TPM (may be success or error response)
    pub fn start_hmac_session(&self, auth_hash: u16) -> Result<Vec<u8>, TpmError> {
        self.start_auth_session(session::TPM_SE_HMAC, auth_hash, alg::TPM_ALG_NULL)
    }

    /// Starts a policy session.
    ///
    /// # Arguments
    /// * `auth_hash` - Hash algorithm for the session (e.g., TPM_ALG_SHA256)
    ///
    /// # Returns
    /// Response buffer from TPM (may be success or error response)
    pub fn start_policy_session(&self, auth_hash: u16) -> Result<Vec<u8>, TpmError> {
        self.start_auth_session(session::TPM_SE_POLICY, auth_hash, alg::TPM_ALG_NULL)
    }

    /// Flushes a context (session or object) from the TPM.
    ///
    /// # Arguments
    /// * `flush_handle` - Handle of the resource to flush
    pub fn flush_context(&self, flush_handle: u32) -> Result<(), TpmError> {
        debug!("TPM: flushing context 0x{:08x}", flush_handle);

        let cmd = build_flush_context_command(flush_handle);
        let response = self.execute_command_expect_success(&cmd)?;
        parse_flush_context_response(&response)?;

        // Remove session from tracking
        self.session_manager.remove_session(flush_handle);

        // Also release from resource manager
        self.resource_manager.release_resource(flush_handle);

        info!("TPM: flushed context 0x{:08x}", flush_handle);
        Ok(())
    }

    /// Saves a context (session or object) from the TPM.
    ///
    /// # Arguments
    /// * `save_handle` - Handle of the resource to save
    /// # Returns
    /// * `context_blob` - The context blob saved by the TPM
    pub fn context_save(&self, save_handle: u32) -> Result<Vec<u8>, TpmError> {
        debug!("TPM: saving context 0x{:08x}", save_handle);

        let cmd = build_context_save_command(save_handle);
        let response = self.execute_command(&cmd)?;

        // Parse the response to get the context blob
        let context_blob = parse_context_save_response(&response)?;

        debug!(
            "TPM: saved context 0x{:08x}, blob size {} bytes",
            save_handle,
            context_blob.len()
        );
        Ok(context_blob)
    }

    /// Loads a context (session or object) into the TPM.
    ///
    /// # Arguments
    /// * `context_blob` - The context blob to load
    pub fn context_load(&self, context_blob: &[u8]) -> Result<u32, TpmError> {
        debug!("TPM: loading context of {} bytes", context_blob.len());

        let cmd = build_context_load_command(context_blob);
        let response = self.execute_command(&cmd)?;

        let load_response = parse_context_load_response(&response)?;

        debug!(
            "TPM: context load successful, handle 0x{:08x}",
            load_response.handle
        );
        Ok(load_response.handle)
    }

    /// Cleans up all resources managed by this chip.
    ///
    /// This should be called during chip disposal or system shutdown.
    pub fn cleanup_resources(&self) {
        info!("TPM: cleaning up chip resources");
        self.session_manager.clear_all();
        self.resource_manager.clear_all();
    }

    /// Executes a PolicyPCR command on a policy session.
    ///
    /// # Arguments
    /// * `policy_session` - Session handle for the policy session
    /// * `pcr_index` - PCR index to include in policy
    /// * `algorithm` - Hash algorithm (e.g., TPM_ALG_SHA256)
    pub fn policy_pcr(
        &self,
        policy_session: u32,
        pcr_index: u32,
        algorithm: u16,
    ) -> Result<Vec<u8>, TpmError> {
        let cmd = build_policy_pcr_command(policy_session, pcr_index, algorithm)?;
        self.execute_command_expect_success(&cmd)
    }

    /// Executes a PolicyGetDigest command on a policy session.
    ///
    /// # Arguments
    /// * `policy_session` - Session handle for the policy session
    ///
    /// # Returns
    /// Policy digest value
    pub fn policy_get_digest(&self, policy_session: u32) -> Result<Vec<u8>, TpmError> {
        let cmd = build_policy_get_digest_command(policy_session);
        let response = self.execute_command_expect_success(&cmd)?;
        parse_policy_get_digest_response(&response)
    }

    /// Executes an NV_ReadPublic command.
    ///
    /// # Arguments
    /// * `nv_index` - NV index to query
    pub fn nv_read_public(&self, nv_index: u32) -> Result<Vec<u8>, TpmError> {
        let cmd = build_nv_read_public_command(nv_index);
        self.execute_command_expect_success(&cmd)
    }

    fn command_code(cmd: &[u8]) -> Option<u32> {
        (cmd.len() >= TPM_HEADER_SIZE).then(|| u32::from_be_bytes([cmd[6], cmd[7], cmd[8], cmd[9]]))
    }

    fn command_tag(cmd: &[u8]) -> Option<u16> {
        (cmd.len() >= TPM_HEADER_SIZE).then(|| u16::from_be_bytes([cmd[0], cmd[1]]))
    }

    fn command_handle_count(command_code: u32) -> Option<usize> {
        match command_code {
            TPM2_CC_CREATE_PRIMARY => Some(1),
            TPM2_CC_EVICT_CONTROL => Some(2),
            TPM2_CC_SEQUENCE_COMPLETE => Some(1),
            TPM2_CC_ACTIVATE_CREDENTIAL => Some(2),
            TPM2_CC_CERTIFY => Some(2),
            TPM2_CC_POLICY_NV => Some(3),
            TPM2_CC_CREATE => Some(1),
            TPM2_CC_CERTIFY_CREATION => Some(2),
            TPM2_CC_DUPLICATE => Some(2),
            TPM2_CC_GET_COMMAND_AUDIT_DIGEST => Some(2),
            TPM2_CC_GET_TIME => Some(2),
            TPM2_CC_GET_SESSION_AUDIT_DIGEST => Some(3),
            TPM2_CC_NV_CERTIFY => Some(3),
            TPM2_CC_ECDH_ZGEN => Some(1),
            TPM2_CC_HMAC => Some(1),
            TPM2_CC_HMAC_START => Some(1),
            TPM2_CC_SEQUENCE_UPDATE => Some(1),
            TPM2_CC_IMPORT => Some(1),
            TPM2_CC_LOAD => Some(1),
            TPM2_CC_LOAD_EXTERNAL => Some(1),
            TPM2_CC_OBJECT_CHANGE_AUTH => Some(2),
            TPM2_CC_POLICY_SECRET => Some(2),
            TPM2_CC_REWRAP => Some(2),
            TPM2_CC_RSA_DECRYPT => Some(1),
            TPM2_CC_RSA_ENCRYPT => Some(1),
            TPM2_CC_SIGN => Some(1),
            TPM2_CC_QUOTE => Some(1),
            TPM2_CC_UNSEAL => Some(1),
            TPM2_CC_POLICY_SIGNED => Some(2),
            TPM2_CC_ECDH_KEY_GEN => Some(1),
            TPM2_CC_ENCRYPT_DECRYPT => Some(1),
            TPM2_CC_NV_READ => Some(2),
            TPM2_CC_NV_WRITE => Some(2),
            TPM2_CC_CONTEXT_SAVE => Some(1),
            TPM2_CC_FLUSH_CONTEXT => Some(1),
            TPM2_CC_MAKE_CREDENTIAL => Some(1),
            TPM2_CC_POLICY_COMMAND_CODE => Some(1),
            TPM2_CC_POLICY_AUTH_VALUE => Some(1),
            TPM2_CC_POLICY_AUTHORIZE => Some(1),
            TPM2_CC_POLICY_COUNTER_TIMER => Some(1),
            TPM2_CC_POLICY_CP_HASH => Some(1),
            TPM2_CC_POLICY_LOCALITY => Some(1),
            TPM2_CC_POLICY_NAME_HASH => Some(1),
            TPM2_CC_POLICY_OR => Some(1),
            TPM2_CC_POLICY_PCR => Some(1),
            TPM2_CC_POLICY_TICKET => Some(1),
            TPM2_CC_POLICY_RESTART => Some(1),
            TPM2_CC_READ_PUBLIC => Some(1),
            TPM2_CC_EVENT_SEQUENCE_COMPLETE => Some(1),
            TPM2_CC_HASH_SEQUENCE_START => Some(0),
            TPM2_CC_POLICY_DUPLICATION_SELECT => Some(1),
            TPM2_CC_POLICY_GET_DIGEST => Some(1),
            TPM2_CC_POLICY_PASSWORD => Some(1),
            TPM2_CC_COMMIT => Some(1),
            TPM2_CC_POLICY_NV_WRITTEN => Some(1),
            TPM2_CC_ZGEN_2PHASE => Some(1),
            TPM2_CC_POLICY_TEMPLATE => Some(1),
            TPM2_CC_CREATE_LOADED => Some(1),
            TPM2_CC_POLICY_AUTHORIZE_NV => Some(3),
            TPM2_CC_CONTEXT_LOAD => Some(0),
            TPM2_CC_VERIFY_SIGNATURE => Some(1),
            TPM2_CC_ENCRYPT_DECRYPT2 => Some(1),
            _ => None,
        }
    }

    fn command_handle(cmd: &[u8], handle_index: usize) -> Option<u32> {
        let offset = TPM_HEADER_SIZE.checked_add(handle_index.checked_mul(4)?)?;
        (cmd.len() >= offset + 4).then(|| {
            u32::from_be_bytes([
                cmd[offset],
                cmd[offset + 1],
                cmd[offset + 2],
                cmd[offset + 3],
            ])
        })
    }

    fn rewrite_handle(cmd: &mut [u8], handle_index: usize, remapped_handle: u32) {
        let offset = TPM_HEADER_SIZE + handle_index * 4;
        cmd[offset..offset + 4].copy_from_slice(&remapped_handle.to_be_bytes());
    }

    fn rewrite_auth_area_session_handles(cmd: &mut [u8], space: &TpmSpace) -> Result<(), TpmError> {
        if Self::command_tag(cmd) != Some(tag::TPM_ST_SESSIONS) {
            return Ok(());
        }

        let Some(command_code) = Self::command_code(cmd) else {
            return Ok(());
        };
        let Some(handle_count) = Self::command_handle_count(command_code) else {
            return Ok(());
        };

        let handles_len = handle_count
            .checked_mul(4)
            .ok_or(TpmError::Buffer(BufferError::Overflow))?;
        let auth_size_offset = TPM_HEADER_SIZE
            .checked_add(handles_len)
            .ok_or(TpmError::Buffer(BufferError::Overflow))?;
        let auth_size = read_u32_be(cmd, auth_size_offset)? as usize;
        let auth_start = auth_size_offset
            .checked_add(4)
            .ok_or(TpmError::Buffer(BufferError::Overflow))?;
        let auth_end = auth_start
            .checked_add(auth_size)
            .ok_or(TpmError::Buffer(BufferError::Overflow))?;
        if auth_end > cmd.len() {
            return Err(TpmError::Buffer(BufferError::TooShort));
        }

        let mut offset = auth_start;
        while offset < auth_end {
            let session_handle = read_u32_be(cmd, offset)?;
            if Self::is_tracked_session(space, session_handle) {
                if let Some(real_handle) = space.session_real_handle(session_handle) {
                    if real_handle != session_handle {
                        cmd[offset..offset + 4].copy_from_slice(&real_handle.to_be_bytes());
                    }
                }
            }
            offset = offset
                .checked_add(4)
                .ok_or(TpmError::Buffer(BufferError::Overflow))?;

            let nonce_size = read_u16_be(cmd, offset)? as usize;
            offset = offset
                .checked_add(2 + nonce_size)
                .ok_or(TpmError::Buffer(BufferError::Overflow))?;

            let _session_attributes = *cmd
                .get(offset)
                .ok_or(TpmError::Buffer(BufferError::TooShort))?;
            offset = offset
                .checked_add(1)
                .ok_or(TpmError::Buffer(BufferError::Overflow))?;

            let hmac_size = read_u16_be(cmd, offset)? as usize;
            offset = offset
                .checked_add(2 + hmac_size)
                .ok_or(TpmError::Buffer(BufferError::Overflow))?;
        }

        if offset != auth_end {
            return Err(TpmError::Buffer(BufferError::SizeMismatch {
                expected: auth_end,
                actual: offset,
            }));
        }

        Ok(())
    }

    fn context_load_saved_handle(cmd: &[u8]) -> Option<u32> {
        (cmd.len() >= TPM_HEADER_SIZE + 12)
            .then(|| u32::from_be_bytes([cmd[18], cmd[19], cmd[20], cmd[21]]))
    }

    fn is_tracked_object(space: &TpmSpace, logical_handle: u32) -> bool {
        space.object_entry(logical_handle).is_some()
    }

    fn is_tracked_session(space: &TpmSpace, logical_handle: u32) -> bool {
        space.session_entry(logical_handle).is_some()
    }

    fn tracked_resource_type(space: &TpmSpace, logical_handle: u32) -> Option<TpmResourceType> {
        if space.object_entry(logical_handle).is_some() {
            Some(TpmResourceType::Key)
        } else if space.session_entry(logical_handle).is_some() {
            TpmResourceType::from_handle(logical_handle).and_then(|resource_type| {
                matches!(
                    resource_type,
                    TpmResourceType::HmacSession | TpmResourceType::PolicySession
                )
                .then_some(resource_type)
            })
        } else {
            None
        }
    }

    fn tracked_context_blob(space: &TpmSpace, logical_handle: u32) -> Option<Vec<u8>> {
        if space.object_entry(logical_handle).is_some() {
            space.object_context_blob(logical_handle)
        } else if space.session_entry(logical_handle).is_some() {
            space.session_context_blob(logical_handle)
        } else {
            None
        }
    }

    fn tracked_handle_needs_context_load(space: &TpmSpace, logical_handle: u32) -> bool {
        if space.object_entry(logical_handle).is_some() {
            space.object_needs_context_load(logical_handle)
        } else {
            space.session_needs_context_load(logical_handle)
        }
    }

    fn prepare_sessions(&self, space: &TpmSpace) -> Result<BTreeMap<u32, u32>, TpmError> {
        let mut loaded_sessions = BTreeMap::new();

        for logical_handle in space.session_handles() {
            if !space.session_needs_context_load(logical_handle) {
                continue;
            }

            let Some(context_blob) = space.session_context_blob(logical_handle) else {
                continue;
            };

            let real_handle = self.context_load(&context_blob)?;
            Self::validate_restored_session_handle(logical_handle, real_handle).inspect_err(
                |_| {
                    if let Err(err) = self.flush_context(real_handle) {
                        warn!(
                            "TPM: failed to flush mismatched restored session 0x{:08x} for logical handle 0x{:08x} in space {}: {:?}",
                            real_handle,
                            logical_handle,
                            space.id(),
                            err
                        );
                    }
                },
            )?;
            space.mark_session_loaded_with_real(logical_handle, real_handle);
            loaded_sessions.insert(logical_handle, real_handle);
        }

        Ok(loaded_sessions)
    }

    fn validate_restored_session_handle(
        logical_handle: u32,
        restored_handle: u32,
    ) -> Result<(), TpmError> {
        if restored_handle == logical_handle {
            Ok(())
        } else {
            Err(TpmError::Transport(TransportError::Generic(
                "session restored to a different handle",
            )))
        }
    }

    fn store_tracked_context_blob(space: &TpmSpace, logical_handle: u32, context_blob: Vec<u8>) {
        if space.object_entry(logical_handle).is_some() {
            space.store_object_context_blob(logical_handle, context_blob);
        } else if space.session_entry(logical_handle).is_some() {
            space.store_session_context_blob(logical_handle, context_blob);
        } else {
            space
                .resource_manager()
                .store_context_blob(logical_handle, context_blob);
        }
    }

    fn remove_tracked_context_blob(space: &TpmSpace, logical_handle: u32) -> Option<Vec<u8>> {
        if Self::is_tracked_object(space, logical_handle) {
            space.remove_object_context_blob(logical_handle)
        } else if Self::is_tracked_session(space, logical_handle) {
            space.remove_session_context_blob(logical_handle)
        } else {
            space.resource_manager().remove_context_blob(logical_handle)
        }
    }

    fn store_and_maybe_flush_context(
        &self,
        space: &TpmSpace,
        logical_handle: u32,
        real_handle: u32,
        resource_type: TpmResourceType,
        context_blob: Vec<u8>,
    ) -> Result<(), TpmError> {
        Self::store_tracked_context_blob(space, logical_handle, context_blob);

        if matches!(resource_type, TpmResourceType::Key) {
            space.mark_object_saved(logical_handle);
            self.flush_context(real_handle)?;
        } else if matches!(
            resource_type,
            TpmResourceType::HmacSession | TpmResourceType::PolicySession
        ) {
            space.mark_session_saved(logical_handle);
        }

        Ok(())
    }

    fn prepare_space(
        &self,
        cmd: &mut [u8],
        space: &TpmSpace,
    ) -> Result<BTreeMap<u32, u32>, TpmError> {
        let Some(command_code) = Self::command_code(cmd) else {
            return Ok(BTreeMap::new());
        };
        let mut loaded_handles = self.prepare_sessions(space)?;
        let Some(handle_count) = Self::command_handle_count(command_code) else {
            Self::rewrite_auth_area_session_handles(cmd, space)?;
            return Ok(loaded_handles);
        };

        for handle_index in 0..handle_count {
            let Some(logical_handle) = Self::command_handle(cmd, handle_index) else {
                continue;
            };

            let tracked_resource_type = Self::tracked_resource_type(space, logical_handle);
            if tracked_resource_type.is_none() {
                continue;
            }

            if !Self::tracked_handle_needs_context_load(space, logical_handle) {
                if Self::is_tracked_object(space, logical_handle) {
                    if let Some(real_handle) = space.object_real_handle(logical_handle) {
                        if real_handle != logical_handle {
                            Self::rewrite_handle(cmd, handle_index, real_handle);
                        }
                    }
                } else if Self::is_tracked_session(space, logical_handle) {
                    if let Some(real_handle) = space.session_real_handle(logical_handle) {
                        if real_handle != logical_handle {
                            Self::rewrite_handle(cmd, handle_index, real_handle);
                        }
                    }
                }
                continue;
            }

            let Some(context_blob) = Self::tracked_context_blob(space, logical_handle) else {
                continue;
            };

            let real_handle = self.context_load(&context_blob)?;
            if matches!(tracked_resource_type, Some(TpmResourceType::Key)) {
                space.mark_object_loaded_with_real(logical_handle, real_handle);
            } else {
                Self::validate_restored_session_handle(logical_handle, real_handle).inspect_err(
                    |_| {
                        if let Err(err) = self.flush_context(real_handle) {
                            warn!(
                                "TPM: failed to flush mismatched restored session 0x{:08x} for logical handle 0x{:08x} in space {}: {:?}",
                                real_handle,
                                logical_handle,
                                space.id(),
                                err
                            );
                        }
                    },
                )?;
                space.mark_session_loaded_with_real(logical_handle, real_handle);
            }
            Self::rewrite_handle(cmd, handle_index, real_handle);
            loaded_handles.insert(logical_handle, real_handle);
        }

        Self::rewrite_auth_area_session_handles(cmd, space)?;

        Ok(loaded_handles)
    }

    fn commit_prepared_handles(
        &self,
        space: &TpmSpace,
        loaded_handles: &BTreeMap<u32, u32>,
    ) -> Result<(), TpmError> {
        for (&logical_handle, &real_handle) in loaded_handles {
            let was_loaded = if Self::is_tracked_object(space, logical_handle) {
                space.object_is_loaded(logical_handle)
            } else if Self::is_tracked_session(space, logical_handle) {
                space.session_is_loaded(logical_handle)
            } else {
                false
            };
            let context_blob = self.context_save(real_handle)?;
            let Some(resource_type) = Self::tracked_resource_type(space, logical_handle) else {
                continue;
            };
            self.store_and_maybe_flush_context(
                space,
                logical_handle,
                real_handle,
                resource_type,
                context_blob,
            )?;

            debug!(
                "TPM: committed prepared {:?} handle 0x{:08x} in space {} (was_loaded={})",
                resource_type,
                logical_handle,
                space.id(),
                was_loaded
            );
        }

        Ok(())
    }

    fn commit_context_save(
        &self,
        space: &TpmSpace,
        original_cmd: &[u8],
        translated_handles: &BTreeMap<u32, u32>,
        response: &[u8],
    ) -> Result<(), TpmError> {
        let Some(logical_handle) = Self::command_handle(original_cmd, 0) else {
            return Ok(());
        };
        let was_object_loaded = Self::is_tracked_object(space, logical_handle)
            && space.object_is_loaded(logical_handle);

        let context_blob = parse_context_save_response(response)?;
        Self::store_tracked_context_blob(space, logical_handle, context_blob);
        debug!(
            "TPM: stored explicit context-save blob for handle 0x{:08x} in space {}",
            logical_handle,
            space.id()
        );

        if Self::is_tracked_object(space, logical_handle) {
            let real_handle = translated_handles
                .get(&logical_handle)
                .copied()
                .or_else(|| space.object_real_handle(logical_handle))
                .unwrap_or(logical_handle);
            if was_object_loaded || real_handle != logical_handle {
                self.flush_context(real_handle)?;
            }
        } else if matches!(
            TpmResourceType::from_handle(logical_handle),
            Some(TpmResourceType::HmacSession | TpmResourceType::PolicySession)
        ) {
            if Self::is_tracked_session(space, logical_handle) {
                space.finish_explicit_session_context_save(logical_handle);
            }
        }

        Ok(())
    }

    fn commit_flush_context(&self, space: &TpmSpace, original_cmd: &[u8], response: &[u8]) {
        let Ok(header) = TpmResponseHeader::from_bytes(response) else {
            return;
        };
        if !header.is_success() {
            return;
        }

        if let Some(logical_handle) = Self::command_handle(original_cmd, 0) {
            Self::remove_tracked_context_blob(space, logical_handle);
            if Self::is_tracked_object(space, logical_handle) {
                space.untrack_object(logical_handle);
            } else if Self::is_tracked_session(space, logical_handle) {
                space.untrack_session(logical_handle);
            }
        }
    }

    fn save_loaded_space_resources(&self, space: &TpmSpace) -> Result<(), TpmError> {
        for logical_handle in space.loaded_object_handles() {
            let Some(real_handle) = space.object_real_handle(logical_handle) else {
                continue;
            };
            let context_blob = self.context_save(real_handle)?;
            self.store_and_maybe_flush_context(
                space,
                logical_handle,
                real_handle,
                TpmResourceType::Key,
                context_blob,
            )?;
        }

        for logical_handle in space.loaded_session_handles() {
            let Some(real_handle) = space.session_real_handle(logical_handle) else {
                continue;
            };
            let Some(resource_type) = Self::tracked_resource_type(space, logical_handle) else {
                continue;
            };
            let context_blob = self.context_save(real_handle)?;
            self.store_and_maybe_flush_context(
                space,
                logical_handle,
                real_handle,
                resource_type,
                context_blob,
            )?;
        }

        Ok(())
    }

    fn commit_context_load(
        &self,
        space: &TpmSpace,
        original_cmd: &[u8],
        response: &mut [u8],
    ) -> Result<(), TpmError> {
        let Some(saved_handle) = Self::context_load_saved_handle(original_cmd) else {
            return Ok(());
        };
        let ContextLoadResponse {
            handle: loaded_handle,
        } = parse_context_load_response(response)?;

        let Some(resource_type) = TpmResourceType::from_handle(loaded_handle) else {
            return Ok(());
        };

        match resource_type {
            TpmResourceType::Key => {
                let incoming_context_blob = original_cmd
                    .get(TPM_HEADER_SIZE..)
                    .ok_or(TpmError::Buffer(BufferError::TooShort))?;
                let reuse_saved_handle = space
                    .object_context_blob(saved_handle)
                    .as_deref()
                    .is_some_and(|stored_blob| stored_blob == incoming_context_blob);
                let Some(logical_handle) = space.finish_explicit_object_context_load(
                    saved_handle,
                    loaded_handle,
                    true,
                    reuse_saved_handle,
                ) else {
                    if let Err(err) = self.flush_context(loaded_handle) {
                        warn!(
                            "TPM: failed to flush explicitly loaded object 0x{:08x} after vhandle exhaustion in space {}: {:?}",
                            loaded_handle,
                            space.id(),
                            err
                        );
                    }
                    return Err(TpmError::Transport(TransportError::Generic(
                        "out of transient object vhandle slots",
                    )));
                };
                response[10..14].copy_from_slice(&logical_handle.to_be_bytes());
            }
            TpmResourceType::HmacSession | TpmResourceType::PolicySession => {
                if let Err(err) =
                    Self::validate_restored_session_handle(saved_handle, loaded_handle)
                {
                    if let Err(err) = self.flush_context(loaded_handle) {
                        warn!(
                            "TPM: failed to flush mismatched explicit session restore 0x{:08x} for logical handle 0x{:08x} in space {}: {:?}",
                            loaded_handle,
                            saved_handle,
                            space.id(),
                            err
                        );
                    }
                    return Err(err);
                }
                // Sessions must stay loaded after an explicit `ContextLoad`;
                // otherwise auth commands immediately fail with
                // "session not loaded". Consume any old saved blob to avoid a
                // second implicit `ContextLoad` on the same file descriptor.
                space.finish_explicit_session_context_load(saved_handle, loaded_handle);
                response[10..14].copy_from_slice(&saved_handle.to_be_bytes());
            }
            _ => {}
        }

        Ok(())
    }

    fn commit_returned_handle(
        &self,
        space: &TpmSpace,
        command_code: u32,
        response: &mut [u8],
    ) -> Result<(), TpmError> {
        let should_track = matches!(
            command_code,
            TPM2_CC_START_AUTH_SESSION
                | TPM2_CC_CREATE_PRIMARY
                | TPM2_CC_CREATE_LOADED
                | TPM2_CC_HMAC_START
                | TPM2_CC_HASH_SEQUENCE_START
                | TPM2_CC_LOAD
                | TPM2_CC_LOAD_EXTERNAL
        );
        if !should_track || response.len() < 14 {
            return Ok(());
        }

        let Ok(header) = TpmResponseHeader::from_bytes(response) else {
            return Ok(());
        };
        if !header.is_success() {
            return Ok(());
        }

        let handle = u32::from_be_bytes([response[10], response[11], response[12], response[13]]);
        if handle == 0 {
            return Ok(());
        }

        match TpmResourceType::from_handle(handle) {
            Some(TpmResourceType::Key) => {
                if let Some(logical_handle) = space.insert_loaded_object_with_real(handle) {
                    response[10..14].copy_from_slice(&logical_handle.to_be_bytes());
                } else if let Err(err) = self.flush_context(handle) {
                    warn!(
                        "TPM: no free transient vhandle slots for object 0x{:08x} in space {}; flush failed: {:?}",
                        handle,
                        space.id(),
                        err
                    );
                    return Err(TpmError::Transport(TransportError::Generic(
                        "out of transient object vhandle slots",
                    )));
                } else {
                    return Err(TpmError::Transport(TransportError::Generic(
                        "out of transient object vhandle slots",
                    )));
                }
            }
            Some(TpmResourceType::HmacSession | TpmResourceType::PolicySession) => {
                space.insert_loaded_session(handle)
            }
            _ => {}
        }

        Ok(())
    }

    fn commit_get_capability(
        &self,
        space: &TpmSpace,
        original_cmd: &[u8],
        response: &mut Vec<u8>,
    ) -> Result<(), TpmError> {
        let requested_capability = read_u32_be(original_cmd, TPM_HEADER_SIZE)?;
        if requested_capability != capability::TPM_CAP_HANDLES {
            return Ok(());
        }

        let header = TpmResponseHeader::from_bytes(response)?;
        if !header.is_success() {
            return Ok(());
        }

        let returned_capability = read_u32_be(response, TPM_HEADER_SIZE + 1)?;
        if returned_capability != capability::TPM_CAP_HANDLES {
            return Ok(());
        }

        let count = read_u32_be(response, TPM_HEADER_SIZE + 5)? as usize;
        let mut read_offset = TPM_HEADER_SIZE + 9;
        let mut write_offset = TPM_HEADER_SIZE + 9;
        let mut mapped_count = 0usize;
        for _ in 0..count {
            let real_handle = read_u32_be(response, read_offset)?;
            let mapped_handle = if matches!(
                TpmResourceType::from_handle(real_handle),
                Some(TpmResourceType::Key)
            ) {
                space.logical_object_handle_for_real(real_handle)
            } else if matches!(
                TpmResourceType::from_handle(real_handle),
                Some(TpmResourceType::HmacSession | TpmResourceType::PolicySession)
            ) {
                space.logical_session_handle_for_real(real_handle)
            } else {
                Some(real_handle)
            };

            if let Some(logical_handle) = mapped_handle {
                response[write_offset..write_offset + 4]
                    .copy_from_slice(&logical_handle.to_be_bytes());
                write_offset = write_offset
                    .checked_add(4)
                    .ok_or(TpmError::Buffer(BufferError::Overflow))?;
                mapped_count = mapped_count
                    .checked_add(1)
                    .ok_or(TpmError::Buffer(BufferError::Overflow))?;
            }
            read_offset = read_offset
                .checked_add(4)
                .ok_or(TpmError::Buffer(BufferError::Overflow))?;
        }

        response[TPM_HEADER_SIZE + 5..TPM_HEADER_SIZE + 9]
            .copy_from_slice(&(mapped_count as u32).to_be_bytes());
        response[2..6].copy_from_slice(&(write_offset as u32).to_be_bytes());
        response.truncate(write_offset);

        Ok(())
    }

    pub fn close_space(&self, space: &TpmSpace) {
        for logical_handle in space.loaded_object_handles() {
            let real_handle = space
                .object_real_handle(logical_handle)
                .unwrap_or(logical_handle);
            if space
                .object_entry(logical_handle)
                .is_some_and(|entry| entry.externally_loaded)
            {
                if let Err(err) = self.flush_context(real_handle) {
                    warn!(
                        "TPM: failed to flush externally loaded object 0x{:08x} while closing space {}: {:?}",
                        logical_handle,
                        space.id(),
                        err
                    );
                }
                continue;
            }

            match self.context_save(real_handle) {
                Ok(context_blob) => {
                    space.store_object_context_blob(logical_handle, context_blob);
                    if let Err(err) = self.flush_context(real_handle) {
                        warn!(
                            "TPM: failed to flush object 0x{:08x} while closing space {}: {:?}",
                            logical_handle,
                            space.id(),
                            err
                        );
                    }
                }
                Err(err) => {
                    warn!(
                        "TPM: failed to save object 0x{:08x} while closing space {}: {:?}",
                        logical_handle,
                        space.id(),
                        err
                    );
                }
            }
        }

        for logical_handle in space.loaded_session_handles() {
            let real_handle = space
                .session_real_handle(logical_handle)
                .unwrap_or(logical_handle);
            if let Err(err) = self.flush_context(real_handle) {
                warn!(
                    "TPM: failed to flush session 0x{:08x} while closing space {}: {:?}",
                    logical_handle,
                    space.id(),
                    err
                );
            }
        }
    }

    /// Executes a command within a specific TPM space.
    ///
    /// This allows resource-isolated command execution where
    /// resources created during the command are tracked in the space.
    ///
    /// # Arguments
    /// * `cmd` - Raw command buffer
    /// * `space` - The TPM space context
    ///
    /// # Returns
    /// Response buffer from the TPM
    pub fn execute_command_in_space(
        &self,
        cmd: &[u8],
        space: &TpmSpace,
    ) -> Result<Vec<u8>, TpmError> {
        debug!("TPM: executing command in space context");

        let mut translated_cmd = cmd.to_vec();
        let command_code = Self::command_code(cmd).unwrap_or(0);
        let translated_handles = self
            .prepare_space(&mut translated_cmd, space)
            .map_err(|err| {
                error!(
                    "TPM: failed to prepare space {} for command 0x{:08x}: {:?}",
                    space.id(),
                    command_code,
                    err
                );
                err
            })?;
        let mut response = match self.execute_command(&translated_cmd) {
            Ok(response) => response,
            Err(err) => {
                error!(
                    "TPM: command 0x{:08x} failed in space {} with translated handles {:?}: {:?}",
                    command_code,
                    space.id(),
                    translated_handles,
                    err
                );
                if let Err(commit_err) = self.commit_prepared_handles(space, &translated_handles) {
                    warn!(
                        "TPM: failed to restore prepared handles after command error in space {}: {:?}",
                        space.id(),
                        commit_err
                    );
                }
                return Err(err);
            }
        };
        let commit_result = match command_code {
            TPM2_CC_GET_CAPABILITY => self.commit_get_capability(space, cmd, &mut response),
            TPM2_CC_CONTEXT_SAVE => {
                self.commit_context_save(space, cmd, &translated_handles, &response)
            }
            TPM2_CC_CONTEXT_LOAD => self.commit_context_load(space, cmd, &mut response),
            TPM2_CC_FLUSH_CONTEXT => {
                self.commit_flush_context(space, cmd, &response);
                Ok(())
            }
            _ => self.commit_prepared_handles(space, &translated_handles),
        };

        if let Err(err) = commit_result {
            error!(
                "TPM: failed to commit space {} after command 0x{:08x}: {:?}",
                space.id(),
                command_code,
                err
            );
            return Err(err);
        }

        self.commit_returned_handle(space, command_code, &mut response)
            .map_err(|err| {
                error!(
                    "TPM: failed to map returned handles for command 0x{:08x} in space {}: {:?}",
                    command_code,
                    space.id(),
                    err
                );
                err
            })?;

        if let Err(err) = self.save_loaded_space_resources(space) {
            error!(
                "TPM: failed to save loaded resources in space {} after command 0x{:08x}: {:?}",
                space.id(),
                command_code,
                err
            );
            return Err(err);
        }

        Ok(response)
    }
}

impl Drop for TpmChip {
    fn drop(&mut self) {
        self.cleanup_resources();
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::protocol::header::{write_u16_be, write_u32_be};

    struct DummyTransport;

    impl TpmTransport for DummyTransport {
        fn send(&self, _cmd: &[u8]) -> Result<(), TpmError> {
            unreachable!("dummy transport is not used by these unit tests")
        }

        fn recv(&self) -> Result<Vec<u8>, TpmError> {
            unreachable!("dummy transport is not used by these unit tests")
        }
    }

    fn build_sessions_command_with_one_auth(
        command_code: u32,
        command_handles: &[u32],
        auth_session_handle: u32,
    ) -> Vec<u8> {
        let mut params = Vec::new();
        for handle in command_handles {
            write_u32_be(&mut params, *handle);
        }

        let mut auth_area = Vec::new();
        write_u32_be(&mut auth_area, auth_session_handle);
        write_u16_be(&mut auth_area, 0);
        auth_area.push(0);
        write_u16_be(&mut auth_area, 0);

        write_u32_be(&mut params, auth_area.len() as u32);
        params.extend_from_slice(&auth_area);

        let header = TpmCommandHeader::new(
            tag::TPM_ST_SESSIONS,
            (TPM_HEADER_SIZE + params.len()) as u32,
            command_code,
        );
        let mut cmd = header.to_bytes();
        cmd.extend_from_slice(&params);
        cmd
    }

    #[test]
    fn rewrite_auth_area_session_handles_rewrites_tracked_session() {
        let space = TpmSpace::new(1);
        let logical_handle = 0x0300_0001;
        let real_handle = 0x0300_0011;
        space.track_session(logical_handle);
        space.finish_explicit_session_context_load(logical_handle, real_handle);

        let mut cmd = build_sessions_command_with_one_auth(
            TPM2_CC_CREATE_PRIMARY,
            &[0x4000_0001],
            logical_handle,
        );

        TpmChip::rewrite_auth_area_session_handles(&mut cmd, &space).unwrap();

        let session_offset = TPM_HEADER_SIZE + 4 + 4;
        let rewritten = u32::from_be_bytes([
            cmd[session_offset],
            cmd[session_offset + 1],
            cmd[session_offset + 2],
            cmd[session_offset + 3],
        ]);
        assert_eq!(rewritten, real_handle);
    }

    #[test]
    fn rewrite_auth_area_session_handles_leaves_pw_session_unchanged() {
        let space = TpmSpace::new(1);
        let mut cmd = build_sessions_command_with_one_auth(
            TPM2_CC_CREATE_PRIMARY,
            &[0x4000_0001],
            session::TPM_RS_PW,
        );

        TpmChip::rewrite_auth_area_session_handles(&mut cmd, &space).unwrap();

        let session_offset = TPM_HEADER_SIZE + 4 + 4;
        let rewritten = u32::from_be_bytes([
            cmd[session_offset],
            cmd[session_offset + 1],
            cmd[session_offset + 2],
            cmd[session_offset + 3],
        ]);
        assert_eq!(rewritten, session::TPM_RS_PW);
    }

    #[test]
    fn validate_restored_session_handle_rejects_different_handle() {
        let err = TpmChip::validate_restored_session_handle(0x0300_0001, 0x0300_0011)
            .expect_err("different restored session handle must be rejected");
        assert!(matches!(
            err,
            TpmError::Transport(TransportError::Generic(
                "session restored to a different handle"
            ))
        ));
    }

    #[test]
    fn get_capability_remaps_visible_object_and_session_handles() {
        let chip = TpmChip::new(DummyTransport);
        let space = TpmSpace::new(1);

        let real_object_handle = 0x8000_0001;
        let logical_object_handle = space
            .insert_loaded_object_with_real(real_object_handle)
            .expect("transient vhandle slot should be available");
        let logical_session_handle = 0x0200_0001;
        space.track_session(logical_session_handle);
        space.mark_session_loaded_with_real(logical_session_handle, logical_session_handle);

        let original_cmd =
            build_get_capability_command(capability::TPM_CAP_HANDLES, handle::TRANSIENT_FIRST, 8);

        let mut response = Vec::new();
        response.extend_from_slice(&tag::TPM_ST_NO_SESSIONS.to_be_bytes());
        response.extend_from_slice(&0u32.to_be_bytes());
        response.extend_from_slice(&rc::TPM_RC_SUCCESS.to_be_bytes());
        response.push(0);
        response.extend_from_slice(&capability::TPM_CAP_HANDLES.to_be_bytes());
        response.extend_from_slice(&3u32.to_be_bytes());
        response.extend_from_slice(&real_object_handle.to_be_bytes());
        response.extend_from_slice(&logical_session_handle.to_be_bytes());
        response.extend_from_slice(&0x0200_0002u32.to_be_bytes());
        let response_size = response.len() as u32;
        response[2..6].copy_from_slice(&response_size.to_be_bytes());

        chip.commit_get_capability(&space, &original_cmd, &mut response)
            .expect("capability remap should succeed");

        assert_eq!(read_u32_be(&response, TPM_HEADER_SIZE + 5).unwrap(), 2);
        assert_eq!(
            read_u32_be(&response, TPM_HEADER_SIZE + 9).unwrap(),
            logical_object_handle
        );
        assert_eq!(
            read_u32_be(&response, TPM_HEADER_SIZE + 13).unwrap(),
            logical_session_handle
        );
    }
}
