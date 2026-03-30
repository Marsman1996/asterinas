// SPDX-License-Identifier: MPL-2.0

//! TPM 2.0 session foundations module.
//!
//! Provides internal structures for TPM session management.
//! This module implements HMAC authorization based on Linux tpm2-sessions.c.

use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::sync::atomic::{AtomicU32, Ordering};

use log::{debug, info, warn};

use crate::{
    TpmChip,
    resource::{TpmResourceHandle, TpmResourceType},
};

/// Types of TPM sessions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpmSessionType {
    /// HMAC session for command authentication.
    Hmac,
    /// Policy session for policy-based authorization.
    Policy,
    /// Trial policy session for testing policy computations.
    Trial,
}

impl TpmSessionType {
    /// Converts to TPM session type byte.
    pub fn to_tpm_byte(&self) -> u8 {
        match self {
            TpmSessionType::Hmac => crate::protocol::constants::session::TPM_SE_HMAC,
            TpmSessionType::Policy => crate::protocol::constants::session::TPM_SE_POLICY,
            TpmSessionType::Trial => crate::protocol::constants::session::TPM_SE_TRIAL,
        }
    }

    /// Returns the resource type for this session type.
    pub fn resource_type(&self) -> TpmResourceType {
        match self {
            TpmSessionType::Hmac | TpmSessionType::Trial => TpmResourceType::HmacSession,
            TpmSessionType::Policy => TpmResourceType::PolicySession,
        }
    }
}

/// Session state during command execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpmSessionState {
    /// Session is initialized and ready.
    Ready,
    /// Session is processing a command.
    Processing,
    /// Session has been closed.
    Closed,
    /// Session has an error.
    Error,
}

/// Authentication data for a session.
#[derive(Debug, Clone)]
pub struct TpmSessionAuth {
    /// Nonce from caller (updated after each command).
    pub nonce_caller: Vec<u8>,
    /// Nonce from TPM (updated after each command).
    pub nonce_tpm: Vec<u8>,
    /// Session password/auth value.
    pub password: Vec<u8>,
    /// Session key for HMAC calculation.
    pub session_key: Vec<u8>,
}

impl TpmSessionAuth {
    /// Creates new auth data.
    pub fn new() -> Self {
        Self {
            nonce_caller: Vec::new(),
            nonce_tpm: Vec::new(),
            password: Vec::new(),
            session_key: Vec::new(),
        }
    }

    /// Creates auth data with a password.
    pub fn with_password(password: Vec<u8>) -> Self {
        Self {
            nonce_caller: Vec::new(),
            nonce_tpm: Vec::new(),
            password,
            session_key: Vec::new(),
        }
    }

    /// Updates the caller nonce after a command.
    pub fn update_caller_nonce(&mut self, nonce: Vec<u8>) {
        self.nonce_caller = nonce;
    }

    /// Updates the TPM nonce after a response.
    pub fn update_tpm_nonce(&mut self, nonce: Vec<u8>) {
        self.nonce_tpm = nonce;
    }
}

impl Default for TpmSessionAuth {
    fn default() -> Self {
        Self::new()
    }
}

/// HMAC calculation helper for session authorization.
///
/// This implements basic HMAC-SHA256 for TPM session auth.
/// Note: Full HMAC calculation requires SHA-256 implementation.
/// This is a placeholder structure that tracks the inputs.
#[derive(Debug)]
pub struct SessionHmac {
    /// Session handle.
    pub session_handle: u32,
    /// Nonce caller.
    pub nonce_caller: Vec<u8>,
    /// Nonce TPM.
    pub nonce_tpm: Vec<u8>,
    /// Session attributes.
    pub session_attributes: u8,
    /// Auth value.
    pub auth_value: Vec<u8>,
}

impl SessionHmac {
    /// Creates a new session HMAC context.
    pub fn new(session: &TpmSession) -> Self {
        Self {
            session_handle: session.handle(),
            nonce_caller: session.auth().nonce_caller.clone(),
            nonce_tpm: session.auth().nonce_tpm.clone(),
            session_attributes: 0,
            auth_value: session.auth().password.clone(),
        }
    }

    /// Calculates the HMAC for a command.
    ///
    /// Returns the HMAC value. In a full implementation, this would
    /// use SHA-256 to compute the actual HMAC.
    pub fn calculate(&self, _command_code: u32, _command_params: &[u8]) -> Vec<u8> {
        // Placeholder: return zeros for now
        // Real implementation would compute HMAC-SHA256
        vec![0u8; 32]
    }
}

/// Represents a TPM 2.0 session.
///
/// This struct tracks session state and provides foundations
/// for future HMAC/parameter encryption support.
#[derive(Debug, Clone)]
pub struct TpmSession {
    /// Session handle.
    handle: TpmResourceHandle,
    /// Type of session.
    session_type: TpmSessionType,
    /// Hash algorithm used (TPM_ALG_* constant).
    algorithm: u16,
    /// Current session state.
    state: TpmSessionState,
    /// Authentication data.
    auth: TpmSessionAuth,
    /// Whether this session is bound to an entity.
    bound: bool,
    /// Whether this session uses salt.
    salted: bool,
}

impl TpmSession {
    /// Creates a new session.
    ///
    /// # Arguments
    /// * `handle` - Session handle
    /// * `session_type` - Type of session
    /// * `algorithm` - Hash algorithm constant
    pub fn new(handle: TpmResourceHandle, session_type: TpmSessionType, algorithm: u16) -> Self {
        debug!(
            "TPM: creating {:?} session with handle 0x{:08x}",
            session_type, handle
        );
        Self {
            handle,
            session_type,
            algorithm,
            state: TpmSessionState::Ready,
            auth: TpmSessionAuth::new(),
            bound: false,
            salted: false,
        }
    }

    /// Returns the session handle.
    pub fn handle(&self) -> TpmResourceHandle {
        self.handle
    }

    /// Returns the session type.
    pub fn session_type(&self) -> TpmSessionType {
        self.session_type
    }

    /// Returns the algorithm.
    pub fn algorithm(&self) -> u16 {
        self.algorithm
    }

    /// Returns the current state.
    pub fn state(&self) -> TpmSessionState {
        self.state
    }

    /// Sets the session state.
    pub fn set_state(&mut self, state: TpmSessionState) {
        self.state = state;
    }

    /// Returns the auth data.
    pub fn auth(&self) -> &TpmSessionAuth {
        &self.auth
    }

    /// Returns mutable auth data.
    pub fn auth_mut(&mut self) -> &mut TpmSessionAuth {
        &mut self.auth
    }

    /// Sets the auth data.
    pub fn set_auth(&mut self, auth: TpmSessionAuth) {
        self.auth = auth;
    }

    /// Returns whether the session is bound.
    pub fn is_bound(&self) -> bool {
        self.bound
    }

    /// Sets whether the session is bound.
    pub fn set_bound(&mut self, bound: bool) {
        self.bound = bound;
    }

    /// Returns whether the session uses salt.
    pub fn is_salted(&self) -> bool {
        self.salted
    }

    /// Sets whether the session uses salt.
    pub fn set_salted(&mut self, salted: bool) {
        self.salted = salted;
    }

    /// Returns the resource type for this session.
    pub fn resource_type(&self) -> TpmResourceType {
        self.session_type.resource_type()
    }
}

/// Manages TPM sessions.
pub struct TpmSessionManager {
    /// Active sessions.
    sessions: spin::Mutex<BTreeMap<TpmResourceHandle, TpmSession>>,
}

impl core::fmt::Debug for TpmSessionManager {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TpmSessionManager").finish()
    }
}

impl TpmSessionManager {
    /// Creates a new session manager.
    pub fn new() -> Self {
        Self {
            sessions: spin::Mutex::new(BTreeMap::new()),
        }
    }

    /// Creates a new session via StartAuthSession.
    ///
    /// # Arguments
    /// * `chip` - TPM chip to use for the command
    /// * `session_type` - Type of session to create
    /// * `auth_hash` - Hash algorithm for the session
    pub fn create_session(
        &self,
        chip: &TpmChip,
        session_type: TpmSessionType,
        auth_hash: u16,
    ) -> Result<TpmSession, crate::TpmError> {
        let response = chip.start_auth_session(
            session_type.to_tpm_byte(),
            auth_hash,
            crate::protocol::constants::alg::TPM_ALG_NULL,
        )?;

        // Parse the response
        let session_response =
            crate::protocol::commands::parse_start_auth_session_response(&response)?;

        let mut session = TpmSession::new(session_response.handle, session_type, auth_hash);
        session.auth.nonce_tpm = session_response.nonce_tpm;

        info!(
            "TPM: created {:?} session with handle 0x{:08x}",
            session_type, session_response.handle
        );

        self.add_session(session.clone());
        Ok(session)
    }

    /// Flushes a session via FlushContext.
    ///
    /// # Arguments
    /// * `chip` - TPM chip to use for the command
    /// * `handle` - Session handle to flush
    pub fn flush_session(
        &self,
        chip: &TpmChip,
        handle: TpmResourceHandle,
    ) -> Result<(), crate::TpmError> {
        chip.flush_context(handle)?;

        // Remove from our tracking
        if let Some(mut session) = self.remove_session(handle) {
            session.set_state(TpmSessionState::Closed);
            info!("TPM: flushed session with handle 0x{:08x}", handle);
        }

        Ok(())
    }

    /// Adds a session.
    pub fn add_session(&self, session: TpmSession) {
        let handle = session.handle();
        self.sessions.lock().insert(handle, session);
        debug!("TPM: added session with handle 0x{:08x}", handle);
    }

    /// Gets a session by handle.
    pub fn get_session(&self, handle: TpmResourceHandle) -> Option<TpmSession> {
        self.sessions.lock().get(&handle).cloned()
    }

    /// Removes a session by handle.
    pub fn remove_session(&self, handle: TpmResourceHandle) -> Option<TpmSession> {
        let session = self.sessions.lock().remove(&handle);
        if session.is_some() {
            debug!("TPM: removed session with handle 0x{:08x}", handle);
        }
        session
    }

    /// Returns the number of active sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.lock().len()
    }

    /// Lists all session handles.
    pub fn list_handles(&self) -> Vec<TpmResourceHandle> {
        self.sessions.lock().keys().copied().collect()
    }

    /// Clears all sessions.
    pub fn clear_all(&self) {
        let mut sessions = self.sessions.lock();
        let count = sessions.len();
        sessions.clear();
        if count > 0 {
            info!("TPM: cleared {} sessions", count);
        }
    }
}

impl Default for TpmSessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let session = TpmSession::new(0x02000000, TpmSessionType::Hmac, 0x000B);
        assert_eq!(session.handle(), 0x02000000);
        assert_eq!(session.session_type(), TpmSessionType::Hmac);
        assert_eq!(session.algorithm(), 0x000B);
        assert_eq!(session.state(), TpmSessionState::Ready);
        assert!(!session.is_bound());
        assert!(!session.is_salted());
    }

    #[test]
    fn test_session_state_transitions() {
        let mut session = TpmSession::new(0x02000000, TpmSessionType::Hmac, 0x000B);
        assert_eq!(session.state(), TpmSessionState::Ready);

        session.set_state(TpmSessionState::Processing);
        assert_eq!(session.state(), TpmSessionState::Processing);

        session.set_state(TpmSessionState::Ready);
        assert_eq!(session.state(), TpmSessionState::Ready);

        session.set_state(TpmSessionState::Closed);
        assert_eq!(session.state(), TpmSessionState::Closed);
    }

    #[test]
    fn test_session_auth() {
        let mut session = TpmSession::new(0x02000000, TpmSessionType::Hmac, 0x000B);

        let mut auth = TpmSessionAuth::with_password(vec![1, 2, 3]);
        auth.nonce_tpm = vec![4, 5, 6];
        session.set_auth(auth);

        assert_eq!(session.auth().password, vec![1, 2, 3]);
        assert_eq!(session.auth().nonce_tpm, vec![4, 5, 6]);
    }

    #[test]
    fn test_session_bound_and_salted() {
        let mut session = TpmSession::new(0x02000000, TpmSessionType::Hmac, 0x000B);

        session.set_bound(true);
        assert!(session.is_bound());

        session.set_salted(true);
        assert!(session.is_salted());
    }

    #[test]
    fn test_session_type_to_byte() {
        assert_eq!(TpmSessionType::Hmac.to_tpm_byte(), 0x00);
        assert_eq!(TpmSessionType::Policy.to_tpm_byte(), 0x01);
        assert_eq!(TpmSessionType::Trial.to_tpm_byte(), 0x03);
    }

    #[test]
    fn test_session_type_resource_type() {
        assert_eq!(
            TpmSessionType::Hmac.resource_type(),
            TpmResourceType::HmacSession
        );
        assert_eq!(
            TpmSessionType::Policy.resource_type(),
            TpmResourceType::PolicySession
        );
        assert_eq!(
            TpmSessionType::Trial.resource_type(),
            TpmResourceType::HmacSession
        );
    }

    #[test]
    fn test_session_manager() {
        let manager = TpmSessionManager::new();

        let session1 = TpmSession::new(0x02000001, TpmSessionType::Hmac, 0x000B);
        let session2 = TpmSession::new(0x02000002, TpmSessionType::Policy, 0x000B);

        manager.add_session(session1);
        manager.add_session(session2);

        assert_eq!(manager.session_count(), 2);

        let retrieved = manager.get_session(0x02000001);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().session_type(), TpmSessionType::Hmac);

        manager.remove_session(0x02000001);
        assert_eq!(manager.session_count(), 1);
    }

    #[test]
    fn test_session_manager_list_handles() {
        let manager = TpmSessionManager::new();

        manager.add_session(TpmSession::new(0x02000001, TpmSessionType::Hmac, 0x000B));
        manager.add_session(TpmSession::new(0x02000002, TpmSessionType::Policy, 0x000B));

        let handles = manager.list_handles();
        assert_eq!(handles.len(), 2);
        assert!(handles.contains(&0x02000001));
        assert!(handles.contains(&0x02000002));
    }
}
