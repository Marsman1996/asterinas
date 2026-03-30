// SPDX-License-Identifier: MPL-2.0

//! TPM 2.0 space module.
//!
//! Provides TPM space abstractions for session isolation and resource management.
//! Each space maintains its own resource context, enabling multi-process TPM access.

use alloc::{collections::BTreeSet, sync::Arc, vec::Vec};

use log::{debug, info, warn};
use spin::Mutex;

use crate::resource::TpmResourceManager;

/// Unique identifier for a TPM space.
pub type TpmSpaceId = u32;

/// First valid space ID.
const FIRST_SPACE_ID: TpmSpaceId = 1;

/// Represents a TPM 2.0 space with its own resource context.
///
/// Spaces provide isolation between different TPM sessions, similar to
/// how Linux's tpmrm manages resource contexts.
pub struct TpmSpace {
    /// Unique identifier for this space.
    id: TpmSpaceId,
    /// Resource manager for this space.
    resource_manager: Arc<TpmResourceManager>,
    /// Session handles created in this space.
    sessions: Mutex<BTreeSet<u32>>,
    /// Whether this space has been disposed.
    disposed: Mutex<bool>,
}

impl core::fmt::Debug for TpmSpace {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TpmSpace")
            .field("id", &self.id)
            .field("disposed", &self.disposed)
            .finish()
    }
}

impl TpmSpace {
    /// Creates a new TPM space.
    ///
    /// # Arguments
    /// * `id` - Unique identifier for this space
    pub fn new(id: TpmSpaceId) -> Self {
        debug!("TPM: creating space with id {}", id);
        Self {
            id,
            resource_manager: Arc::new(TpmResourceManager::new()),
            sessions: Mutex::new(BTreeSet::new()),
            disposed: Mutex::new(false),
        }
    }

    /// Returns the space ID.
    pub fn id(&self) -> TpmSpaceId {
        self.id
    }

    /// Returns a reference to the resource manager.
    pub fn resource_manager(&self) -> &TpmResourceManager {
        &self.resource_manager
    }

    /// Tracks a session handle in this space.
    pub fn track_session(&self, handle: u32) {
        self.sessions.lock().insert(handle);
        debug!(
            "TPM: tracking session 0x{:08x} in space {}",
            handle, self.id
        );
    }

    /// Removes a session handle from this space.
    pub fn untrack_session(&self, handle: u32) -> bool {
        let removed = self.sessions.lock().remove(&handle);
        if removed {
            debug!(
                "TPM: untracked session 0x{:08x} from space {}",
                handle, self.id
            );
        }
        removed
    }

    /// Returns all session handles in this space.
    pub fn session_handles(&self) -> Vec<u32> {
        self.sessions.lock().iter().copied().collect()
    }

    /// Returns the number of sessions in this space.
    pub fn session_count(&self) -> usize {
        self.sessions.lock().len()
    }

    /// Disposes the space and cleans up all resources and sessions.
    pub fn dispose(&self) {
        let mut disposed = self.disposed.lock();
        if *disposed {
            return;
        }
        *disposed = true;

        info!("TPM: disposing space with id {}", self.id);

        // Clear sessions
        let sessions: Vec<u32> = self.sessions.lock().iter().copied().collect();
        if !sessions.is_empty() {
            debug!(
                "TPM: clearing {} sessions from space {}",
                sessions.len(),
                self.id
            );
            self.sessions.lock().clear();
        }

        // Clear resources
        self.resource_manager.clear_all();
    }

    /// Returns true if this space has been disposed.
    pub fn is_disposed(&self) -> bool {
        *self.disposed.lock()
    }
}

impl Drop for TpmSpace {
    fn drop(&mut self) {
        self.dispose();
    }
}

/// Manages multiple TPM spaces.
pub struct TpmSpaceManager {
    /// Map of space ID to space.
    spaces: Mutex<alloc::collections::BTreeMap<TpmSpaceId, Arc<TpmSpace>>>,
    /// Next space ID to allocate.
    next_id: Mutex<TpmSpaceId>,
}

impl core::fmt::Debug for TpmSpaceManager {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TpmSpaceManager").finish()
    }
}

impl TpmSpaceManager {
    /// Creates a new space manager.
    pub fn new() -> Self {
        Self {
            spaces: Mutex::new(alloc::collections::BTreeMap::new()),
            next_id: Mutex::new(FIRST_SPACE_ID),
        }
    }

    /// Creates a new space and returns its ID.
    pub fn create_space(&self) -> Arc<TpmSpace> {
        let mut next_id = self.next_id.lock();
        let id = *next_id;
        *next_id = next_id.wrapping_add(1);

        let space = Arc::new(TpmSpace::new(id));
        self.spaces.lock().insert(id, space.clone());

        info!("TPM: created space with id {}", id);
        space
    }

    /// Gets a space by ID.
    pub fn get_space(&self, id: TpmSpaceId) -> Option<Arc<TpmSpace>> {
        self.spaces.lock().get(&id).cloned()
    }

    /// Disposes a space by ID.
    pub fn dispose_space(&self, id: TpmSpaceId) -> bool {
        if let Some(space) = self.spaces.lock().remove(&id) {
            space.dispose();
            info!("TPM: disposed space with id {}", id);
            true
        } else {
            false
        }
    }

    /// Returns the number of active spaces.
    pub fn space_count(&self) -> usize {
        self.spaces.lock().len()
    }
}

impl Default for TpmSpaceManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_space_creation() {
        let manager = TpmSpaceManager::new();
        let space = manager.create_space();
        assert!(space.id() >= FIRST_SPACE_ID);
        assert!(!space.is_disposed());
    }

    #[test]
    fn test_space_isolation() {
        let manager = TpmSpaceManager::new();
        let space1 = manager.create_space();
        let space2 = manager.create_space();

        assert_ne!(space1.id(), space2.id());

        // Each space has its own resource manager
        let handle1 = space1
            .resource_manager()
            .create_resource(crate::resource::TpmResourceType::Key, vec![1, 2, 3]);

        // Resource from space1 should not be visible in space2
        assert!(space2.resource_manager().get_resource(handle1).is_none());
    }

    #[test]
    fn test_space_disposal() {
        let manager = TpmSpaceManager::new();
        let space = manager.create_space();
        let id = space.id();

        assert!(manager.get_space(id).is_some());
        assert!(manager.dispose_space(id));
        assert!(manager.get_space(id).is_none());
    }

    #[test]
    fn test_space_resource_cleanup() {
        let manager = TpmSpaceManager::new();
        let space = manager.create_space();
        let id = space.id();

        // Create resource in space
        let handle = space
            .resource_manager()
            .create_resource(crate::resource::TpmResourceType::Key, vec![]);

        // Resource should exist
        assert!(space.resource_manager().get_resource(handle).is_some());

        // Dispose space
        manager.dispose_space(id);

        // Resources should be cleaned up
        assert_eq!(space.resource_manager().resource_count(), 0);
    }

    #[test]
    fn test_space_session_tracking() {
        let space = TpmSpace::new(1);

        // Track sessions
        space.track_session(0x02000001);
        space.track_session(0x02000002);

        assert_eq!(space.session_count(), 2);

        // Untrack a session
        assert!(space.untrack_session(0x02000001));
        assert_eq!(space.session_count(), 1);
        assert!(!space.untrack_session(0x02000001)); // Already removed
    }

    #[test]
    fn test_space_session_isolation() {
        let space1 = TpmSpace::new(1);
        let space2 = TpmSpace::new(2);

        // Track session in space1
        space1.track_session(0x02000001);

        // Session should not be in space2
        assert_eq!(space1.session_count(), 1);
        assert_eq!(space2.session_count(), 0);
        assert!(space2.session_handles().is_empty());
    }

    #[test]
    fn test_space_session_cleanup_on_dispose() {
        let space = TpmSpace::new(1);

        space.track_session(0x02000001);
        space.track_session(0x02000002);
        assert_eq!(space.session_count(), 2);

        space.dispose();
        assert_eq!(space.session_count(), 0);
    }
}
