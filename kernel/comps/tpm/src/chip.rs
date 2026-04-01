// SPDX-License-Identifier: MPL-2.0

//! TPM chip abstraction.

use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};
use core::sync::atomic::{AtomicU8, Ordering};

use log::{debug, info, warn};
use ostd::sync::Mutex;

use crate::{
    error::{BufferError, TpmError},
    protocol::{
        commands::{
            build_context_load_command, build_context_save_command, build_flush_context_command,
            build_get_capability_command, build_get_random_command, build_nv_read_public_command,
            build_pcr_read_command, build_policy_get_digest_command, build_policy_pcr_command,
            build_start_auth_session_command, build_startup_command, parse_context_load_response,
            parse_context_save_response, parse_flush_context_response,
            parse_get_capability_response, parse_get_random_response, parse_pcr_read_response,
            parse_policy_get_digest_response, parse_start_auth_session_response,
            ContextLoadResponse, GetCapabilityResponse, PcrReadResponse, StartAuthSessionResponse,
        },
        constants::{alg, capability, handle, pcr, property, rc, session, startup, tag},
        header::{TpmCommandHeader, TpmResponseHeader, TPM_HEADER_SIZE},
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
const TPM2_CC_CREATE: u32 = 0x0000_0153;
const TPM2_CC_HMAC: u32 = 0x0000_0155;
const TPM2_CC_LOAD: u32 = 0x0000_0157;
const TPM2_CC_NV_READ: u32 = 0x0000_014E;
const TPM2_CC_NV_WRITE: u32 = 0x0000_0137;
const TPM2_CC_CONTEXT_SAVE: u32 = 0x0000_0162;
const TPM2_CC_FLUSH_CONTEXT: u32 = 0x0000_0165;
const TPM2_CC_POLICY_COMMAND_CODE: u32 = 0x0000_016C;
const TPM2_CC_READ_PUBLIC: u32 = 0x0000_0173;
const TPM2_CC_POLICY_GET_DIGEST: u32 = 0x0000_0189;
const TPM2_CC_CONTEXT_LOAD: u32 = 0x0000_0161;

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

    fn context_load_saved_handle(cmd: &[u8]) -> Option<u32> {
        (cmd.len() >= TPM_HEADER_SIZE + 12)
            .then(|| u32::from_be_bytes([cmd[18], cmd[19], cmd[20], cmd[21]]))
    }

    fn command_handle_indexes(command_code: u32) -> &'static [usize] {
        match command_code {
            TPM2_CC_CREATE
            | TPM2_CC_HMAC
            | TPM2_CC_LOAD
            | TPM2_CC_CONTEXT_SAVE
            | TPM2_CC_FLUSH_CONTEXT
            | TPM2_CC_POLICY_COMMAND_CODE
            | TPM2_CC_READ_PUBLIC
            | TPM2_CC_POLICY_GET_DIGEST => &[0],
            TPM2_CC_EVICT_CONTROL | TPM2_CC_NV_READ | TPM2_CC_NV_WRITE => &[1],
            _ => &[],
        }
    }

    fn is_tracked_object(space: &TpmSpace, logical_handle: u32) -> bool {
        space.object_handles().contains(&logical_handle)
    }

    fn store_and_maybe_flush_context(
        &self,
        space: &TpmSpace,
        logical_handle: u32,
        real_handle: u32,
        resource_type: TpmResourceType,
        context_blob: Vec<u8>,
    ) -> Result<(), TpmError> {
        space
            .resource_manager()
            .store_context_blob(logical_handle, context_blob);

        if matches!(resource_type, TpmResourceType::Key) {
            self.flush_context(real_handle)?;
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

        let handle_indexes = Self::command_handle_indexes(command_code);
        if handle_indexes.is_empty() {
            return Ok(BTreeMap::new());
        }

        let mut loaded_handles = BTreeMap::new();
        for &handle_index in handle_indexes {
            let Some(logical_handle) = Self::command_handle(cmd, handle_index) else {
                continue;
            };

            if !Self::is_tracked_object(space, logical_handle) {
                continue;
            }

            if let Some(context_blob) = space.resource_manager().get_context_blob(logical_handle) {
                let real_handle = self.context_load(&context_blob)?;
                Self::rewrite_handle(cmd, handle_index, real_handle);
                loaded_handles.insert(logical_handle, real_handle);
            }
        }

        Ok(loaded_handles)
    }

    fn commit_prepared_handles(
        &self,
        space: &TpmSpace,
        loaded_handles: &BTreeMap<u32, u32>,
    ) -> Result<(), TpmError> {
        for (&logical_handle, &real_handle) in loaded_handles {
            let context_blob = self.context_save(real_handle)?;
            let resource_type = TpmResourceType::Key;
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

        let context_blob = parse_context_save_response(response)?;
        space
            .resource_manager()
            .store_context_blob(logical_handle, context_blob);
        debug!(
            "TPM: stored explicit context-save blob for handle 0x{:08x} in space {}",
            logical_handle,
            space.id()
        );

        if Self::is_tracked_object(space, logical_handle) {
            let real_handle = translated_handles
                .get(&logical_handle)
                .copied()
                .unwrap_or(logical_handle);
            self.flush_context(real_handle)?;
        }

        Ok(())
    }

    fn commit_flush_context(&self, space: &TpmSpace, original_cmd: &[u8]) {
        if let Some(logical_handle) = Self::command_handle(original_cmd, 0) {
            space.resource_manager().remove_context_blob(logical_handle);
        }
    }

    fn commit_context_load(
        &self,
        space: &TpmSpace,
        original_cmd: &[u8],
        response: &[u8],
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
                // Keep explicitly loaded objects alive for the lifetime of the
                // current file descriptor so follow-up commands on the same
                // ESYS context can use the returned transient handle directly.
                // Consume the old saved blob to avoid a second implicit
                // `ContextLoad` on the same fd.
                space.resource_manager().remove_context_blob(saved_handle);
                space.untrack_object(saved_handle);
                space.track_object(loaded_handle);
            }
            TpmResourceType::HmacSession | TpmResourceType::PolicySession => {
                // Sessions must stay loaded after an explicit `ContextLoad`;
                // otherwise auth commands immediately fail with
                // "session not loaded". Consume any old saved blob to avoid a
                // second implicit `ContextLoad` on the same file descriptor.
                space.resource_manager().remove_context_blob(saved_handle);
                space.untrack_session(saved_handle);
                space.track_session(loaded_handle);
            }
            _ => {}
        }

        Ok(())
    }

    pub fn close_space(&self, space: &TpmSpace) {
        for logical_handle in space.object_handles() {
            if space
                .resource_manager()
                .get_context_blob(logical_handle)
                .is_some()
            {
                continue;
            }

            match self.context_save(logical_handle) {
                Ok(context_blob) => {
                    space
                        .resource_manager()
                        .store_context_blob(logical_handle, context_blob);
                    if let Err(err) = self.flush_context(logical_handle) {
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

        for logical_handle in space.session_handles() {
            if space
                .resource_manager()
                .get_context_blob(logical_handle)
                .is_some()
            {
                continue;
            }

            if let Err(err) = self.flush_context(logical_handle) {
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
        let translated_handles = self.prepare_space(&mut translated_cmd, space)?;
        let response = match self.execute_command(&translated_cmd) {
            Ok(response) => response,
            Err(err) => {
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
            TPM2_CC_CONTEXT_SAVE => {
                self.commit_context_save(space, cmd, &translated_handles, &response)
            }
            TPM2_CC_CONTEXT_LOAD => self.commit_context_load(space, cmd, &response),
            TPM2_CC_FLUSH_CONTEXT => {
                self.commit_flush_context(space, cmd);
                Ok(())
            }
            _ => self.commit_prepared_handles(space, &translated_handles),
        };

        if let Err(err) = commit_result {
            warn!(
                "TPM: failed to commit space {} after command 0x{:08x}: {:?}",
                space.id(),
                command_code,
                err
            );
        }

        Ok(response)
    }
}

impl Drop for TpmChip {
    fn drop(&mut self) {
        self.cleanup_resources();
    }
}
