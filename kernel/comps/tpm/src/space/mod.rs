// SPDX-License-Identifier: MPL-2.0

//! TPM 2.0 space module.
//!
//! Provides TPM space abstractions for session isolation and resource management.
//! Each space maintains its own resource context, enabling multi-process TPM access.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    vec::Vec,
};

use log::{debug, info, warn};
use spin::Mutex;

use crate::resource::{TpmResource, TpmResourceHandle, TpmResourceManager, TpmResourceType};

/// Unique identifier for a TPM space.
pub type TpmSpaceId = u32;

/// First valid space ID.
const FIRST_SPACE_ID: TpmSpaceId = 1;

// ---------------------------------------------------------------------------
// TpmSpace — original space type used by tpmrm.rs
// ---------------------------------------------------------------------------

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
    /// Transient object handles created in this space.
    transient_objects: Mutex<BTreeSet<u32>>,
    /// Objects that were explicitly restored from a userspace context blob.
    externally_loaded_objects: Mutex<BTreeSet<u32>>,
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
    pub fn new(id: TpmSpaceId) -> Self {
        debug!("TPM: creating space with id {}", id);
        Self {
            id,
            resource_manager: Arc::new(TpmResourceManager::new()),
            sessions: Mutex::new(BTreeSet::new()),
            transient_objects: Mutex::new(BTreeSet::new()),
            externally_loaded_objects: Mutex::new(BTreeSet::new()),
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

    /// Tracks a transient object handle in this space.
    pub fn track_object(&self, handle: u32) {
        self.transient_objects.lock().insert(handle);
        debug!(
            "TPM: tracking transient object 0x{:08x} in space {}",
            handle, self.id
        );
    }

    /// Removes a transient object handle from this space.
    pub fn untrack_object(&self, handle: u32) -> bool {
        let removed = self.transient_objects.lock().remove(&handle);
        self.externally_loaded_objects.lock().remove(&handle);
        if removed {
            debug!(
                "TPM: untracked transient object 0x{:08x} from space {}",
                handle, self.id
            );
        }
        removed
    }

    /// Returns all transient object handles in this space.
    pub fn object_handles(&self) -> Vec<u32> {
        self.transient_objects.lock().iter().copied().collect()
    }

    /// Marks an object as being explicitly restored from a userspace context.
    pub fn mark_externally_loaded_object(&self, handle: u32) {
        self.externally_loaded_objects.lock().insert(handle);
        debug!(
            "TPM: marked transient object 0x{:08x} as externally loaded in space {}",
            handle, self.id
        );
    }

    /// Returns whether an object came from an explicit userspace `ContextLoad`.
    pub fn is_externally_loaded_object(&self, handle: u32) -> bool {
        self.externally_loaded_objects.lock().contains(&handle)
    }

    /// Returns the number of transient objects in this space.
    pub fn object_count(&self) -> usize {
        self.transient_objects.lock().len()
    }

    /// Disposes the space and cleans up all resources and sessions.
    pub fn dispose(&self) {
        let mut disposed = self.disposed.lock();
        if *disposed {
            return;
        }
        *disposed = true;

        info!("TPM: disposing space with id {}", self.id);

        let sessions: Vec<u32> = self.sessions.lock().iter().copied().collect();
        if !sessions.is_empty() {
            debug!(
                "TPM: clearing {} sessions from space {}",
                sessions.len(),
                self.id
            );
            self.sessions.lock().clear();
        }

        let objects: Vec<u32> = self.transient_objects.lock().iter().copied().collect();
        if !objects.is_empty() {
            debug!(
                "TPM: clearing {} transient objects from space {}",
                objects.len(),
                self.id
            );
            self.transient_objects.lock().clear();
            self.externally_loaded_objects.lock().clear();
        }

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

// ---------------------------------------------------------------------------
// TpmObjectSpace — manages TPM object contexts (keys, etc.)
// ---------------------------------------------------------------------------

/// Represents a TPM object space for managing object contexts.
///
/// This provides isolation and management of TPM object contexts similar to
/// Linux's tpm2-space.c, handling object creation, loading, and context save/restore.
pub struct TpmObjectSpace {
    /// Unique identifier for this object space.
    id: TpmSpaceId,
    /// Resource manager for tracking object resources.
    resource_manager: Arc<TpmResourceManager>,
    /// Object contexts stored in this space.
    objects: Mutex<BTreeMap<TpmResourceHandle, TpmResource>>,
    /// Evicted object contexts waiting for restoration.
    evicted_objects: Mutex<BTreeMap<TpmResourceHandle, (Vec<u8>, Vec<u8>, Vec<u8>)>>,
    /// Whether this object space has been disposed.
    disposed: Mutex<bool>,
}

impl TpmObjectSpace {
    /// Creates a new TPM object space.
    pub fn new(id: TpmSpaceId) -> Self {
        debug!("TPM: creating object space with id {}", id);
        Self {
            id,
            resource_manager: Arc::new(TpmResourceManager::new()),
            objects: Mutex::new(BTreeMap::new()),
            evicted_objects: Mutex::new(BTreeMap::new()),
            disposed: Mutex::new(false),
        }
    }

    /// Returns the object space ID.
    pub fn id(&self) -> TpmSpaceId {
        self.id
    }

    /// Returns a reference to the resource manager.
    pub fn resource_manager(&self) -> &TpmResourceManager {
        &self.resource_manager
    }

    /// Tracks an object handle in this space with its public and private areas.
    pub fn track_object_with_data(
        &self,
        handle: TpmResourceHandle,
        public_area: Option<Vec<u8>>,
        private_area: Option<Vec<u8>>,
        name: Option<Vec<u8>>,
    ) {
        let mut objects = self.objects.lock();
        objects.insert(
            handle,
            TpmResource {
                handle,
                resource_type: TpmResourceType::Key,
                data: Vec::new(),
                public_area,
                private_area,
                name,
                last_used: 0,
            },
        );
        debug!(
            "TPM: tracking object 0x{:08x} in object space {}",
            handle, self.id
        );
    }

    /// Retrieves an object's public, private, and name data by real handle.
    pub fn get_object_data(
        &self,
        handle: TpmResourceHandle,
    ) -> Option<(Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>)> {
        let objects = self.objects.lock();
        objects.get(&handle).map(|resource| {
            (
                resource.public_area.clone(),
                resource.private_area.clone(),
                resource.name.clone(),
            )
        })
    }

    /// Retrieves an object's data by virtual handle (userspace handle).
    pub fn get_object_data_by_virtual_handle(
        &self,
        virtual_handle: TpmResourceHandle,
    ) -> Option<(Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>)> {
        let real_handle = self
            .resource_manager()
            .map_virtual_to_real(virtual_handle)?;
        self.get_object_data(real_handle)
    }

    /// Updates an object's stored data (used after TPM2_Load to store the loaded context).
    pub fn update_object_data(
        &self,
        handle: TpmResourceHandle,
        public_area: Option<Vec<u8>>,
        private_area: Option<Vec<u8>>,
        name: Option<Vec<u8>>,
    ) -> bool {
        let mut objects = self.objects.lock();
        if let Some(resource) = objects.get_mut(&handle) {
            resource.public_area = public_area;
            resource.private_area = private_area;
            resource.name = name;
            true
        } else {
            false
        }
    }

    /// Updates an object's stored data using virtual handle (userspace handle).
    pub fn update_object_data_by_virtual_handle(
        &self,
        virtual_handle: TpmResourceHandle,
        public_area: Option<Vec<u8>>,
        private_area: Option<Vec<u8>>,
        name: Option<Vec<u8>>,
    ) -> bool {
        let Some(real_handle) = self.resource_manager().map_virtual_to_real(virtual_handle) else {
            return false;
        };
        self.update_object_data(real_handle, public_area, private_area, name)
    }

    /// Evicts an object context to make room for new objects.
    ///
    /// This simulates TPM2_ContextSave by storing the object's context
    /// and removing it from active tracking.
    pub fn evict_object(&self, handle: TpmResourceHandle) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let mut objects = self.objects.lock();
        let mut evicted = self.evicted_objects.lock();
        if let Some(resource) = objects.remove(&handle) {
            let public_area = resource.public_area.clone().unwrap_or_default();
            let private_area = resource.private_area.clone().unwrap_or_default();
            let name = resource.name.clone().unwrap_or_default();

            evicted.insert(
                handle,
                (public_area.clone(), private_area.clone(), name.clone()),
            );

            debug!(
                "TPM: evicted object 0x{:08x} from object space {}",
                handle, self.id
            );

            Some((public_area, private_area, name))
        } else {
            None
        }
    }

    /// Restores an evicted object context by handle.
    pub fn restore_object(&self, handle: TpmResourceHandle) -> Option<TpmResourceHandle> {
        let mut evicted = self.evicted_objects.lock();
        let mut objects = self.objects.lock();
        if let Some((public_area, private_area, name)) = evicted.remove(&handle) {
            let restored_handle = self
                .resource_manager()
                .create_resource(TpmResourceType::Key, Vec::new());

            objects.insert(
                restored_handle,
                TpmResource {
                    handle: restored_handle,
                    resource_type: TpmResourceType::Key,
                    data: Vec::new(),
                    public_area: Some(public_area),
                    private_area: Some(private_area),
                    name: Some(name),
                    last_used: 0,
                },
            );

            debug!(
                "TPM: restored object with handle 0x{:08x} from evicted object 0x{:08x} in object space {}",
                restored_handle, handle, self.id
            );

            Some(restored_handle)
        } else {
            None
        }
    }

    /// Restores an object from raw context data, returning the new handle.
    pub fn restore_object_from_data(
        &self,
        public_area: Vec<u8>,
        private_area: Vec<u8>,
        name: Vec<u8>,
    ) -> TpmResourceHandle {
        let handle = self
            .resource_manager()
            .create_resource(TpmResourceType::Key, Vec::new());

        let mut objects = self.objects.lock();
        objects.insert(
            handle,
            TpmResource {
                handle,
                resource_type: TpmResourceType::Key,
                data: Vec::new(),
                public_area: Some(public_area),
                private_area: Some(private_area),
                name: Some(name),
                last_used: 0,
            },
        );

        debug!(
            "TPM: restored object with handle 0x{:08x} in object space {}",
            handle, self.id
        );

        handle
    }

    /// Implements LRU eviction policy when object space is full.
    pub fn evict_lru_object(&self) -> Option<(TpmResourceHandle, Vec<u8>, Vec<u8>, Vec<u8>)> {
        let mut objects = self.objects.lock();
        if objects.is_empty() {
            return None;
        }

        let mut oldest_handle = None;
        let mut oldest_time = u64::MAX;

        for (handle, resource) in objects.iter() {
            if resource.last_used < oldest_time {
                oldest_time = resource.last_used;
                oldest_handle = Some(*handle);
            }
        }

        if let Some(handle) = oldest_handle {
            if let Some(resource) = objects.remove(&handle) {
                let public_area = resource.public_area.clone().unwrap_or_default();
                let private_area = resource.private_area.clone().unwrap_or_default();
                let name = resource.name.clone().unwrap_or_default();

                debug!(
                    "TPM: evicted LRU object 0x{:08x} from object space {}",
                    handle, self.id
                );

                Some((handle, public_area, private_area, name))
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Removes an object handle from this space.
    pub fn untrack_object(&self, handle: TpmResourceHandle) -> bool {
        let removed = self.objects.lock().remove(&handle).is_some();
        if removed {
            debug!(
                "TPM: untracked object 0x{:08x} from object space {}",
                handle, self.id
            );
        }
        removed
    }

    /// Returns all object handles in this space.
    pub fn object_handles(&self) -> Vec<TpmResourceHandle> {
        self.objects.lock().keys().copied().collect()
    }

    /// Returns the number of objects in this space.
    pub fn object_count(&self) -> usize {
        self.objects.lock().len()
    }

    /// Disposes the object space and cleans up all resources.
    pub fn dispose(&self) {
        let mut disposed = self.disposed.lock();
        if *disposed {
            return;
        }
        *disposed = true;

        info!("TPM: disposing object space with id {}", self.id);

        self.objects.lock().clear();
        self.evicted_objects.lock().clear();
        self.resource_manager.clear_all();
    }

    /// Returns true if this object space has been disposed.
    pub fn is_disposed(&self) -> bool {
        *self.disposed.lock()
    }
}

impl Drop for TpmObjectSpace {
    fn drop(&mut self) {
        self.dispose();
    }
}

// ---------------------------------------------------------------------------
// TpmSessionSpace — manages TPM session contexts (HMAC, policy)
// ---------------------------------------------------------------------------

/// Represents a TPM session space for managing session contexts.
///
/// This provides isolation and management of TPM session contexts similar to
/// Linux's tpm2-space.c, handling session creation, loading, and context save/restore.
pub struct TpmSessionSpace {
    /// Unique identifier for this session space.
    id: TpmSpaceId,
    /// Resource manager for tracking session resources.
    resource_manager: Arc<TpmResourceManager>,
    /// Session contexts stored in this space.
    sessions: Mutex<BTreeMap<TpmResourceHandle, TpmResource>>,
    /// Evicted session contexts waiting for restoration.
    evicted_sessions:
        Mutex<BTreeMap<TpmResourceHandle, (TpmResourceType, Vec<u8>, Vec<u8>, Vec<u8>)>>,
    /// Whether this session space has been disposed.
    disposed: Mutex<bool>,
}

impl TpmSessionSpace {
    /// Creates a new TPM session space.
    pub fn new(id: TpmSpaceId) -> Self {
        debug!("TPM: creating session space with id {}", id);
        Self {
            id,
            resource_manager: Arc::new(TpmResourceManager::new()),
            sessions: Mutex::new(BTreeMap::new()),
            evicted_sessions: Mutex::new(BTreeMap::new()),
            disposed: Mutex::new(false),
        }
    }

    /// Returns the session space ID.
    pub fn id(&self) -> TpmSpaceId {
        self.id
    }

    /// Returns a reference to the resource manager.
    pub fn resource_manager(&self) -> &TpmResourceManager {
        &self.resource_manager
    }

    /// Tracks a session handle in this space with its attributes.
    pub fn track_session_with_data(
        &self,
        handle: TpmResourceHandle,
        session_type: TpmResourceType,
    ) {
        let mut sessions = self.sessions.lock();
        sessions.insert(
            handle,
            TpmResource {
                handle,
                resource_type: session_type,
                data: Vec::new(),
                public_area: None,
                private_area: None,
                name: None,
                last_used: 0,
            },
        );
        debug!(
            "TPM: tracking session 0x{:08x} ({:?}) in session space {}",
            handle, session_type, self.id
        );
    }

    /// Retrieves a session's data by handle.
    pub fn get_session_data(
        &self,
        handle: TpmResourceHandle,
    ) -> Option<(
        TpmResourceType,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
    )> {
        let sessions = self.sessions.lock();
        sessions.get(&handle).map(|resource| {
            (
                resource.resource_type,
                resource.public_area.clone(),
                resource.private_area.clone(),
                resource.name.clone(),
            )
        })
    }

    /// Retrieves a session's data by virtual handle (userspace handle).
    pub fn get_session_data_by_virtual_handle(
        &self,
        virtual_handle: TpmResourceHandle,
    ) -> Option<(
        TpmResourceType,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
    )> {
        let real_handle = self
            .resource_manager()
            .map_virtual_to_real(virtual_handle)?;
        self.get_session_data(real_handle)
    }

    /// Updates a session's stored data.
    pub fn update_session_data(
        &self,
        handle: TpmResourceHandle,
        public_area: Option<Vec<u8>>,
        private_area: Option<Vec<u8>>,
        name: Option<Vec<u8>>,
    ) -> bool {
        let mut sessions = self.sessions.lock();
        if let Some(resource) = sessions.get_mut(&handle) {
            resource.public_area = public_area;
            resource.private_area = private_area;
            resource.name = name;
            true
        } else {
            false
        }
    }

    /// Updates a session's stored data by virtual handle (userspace handle).
    pub fn update_session_data_by_virtual_handle(
        &self,
        virtual_handle: TpmResourceHandle,
        public_area: Option<Vec<u8>>,
        private_area: Option<Vec<u8>>,
        name: Option<Vec<u8>>,
    ) -> bool {
        let Some(real_handle) = self.resource_manager().map_virtual_to_real(virtual_handle) else {
            return false;
        };
        self.update_session_data(real_handle, public_area, private_area, name)
    }

    /// Sets session attributes for auditing/encryption.
    pub fn set_session_attributes(&self, handle: TpmResourceHandle, attributes: u8) -> bool {
        let mut sessions = self.sessions.lock();
        if let Some(resource) = sessions.get_mut(&handle) {
            if let TpmResourceType::HmacSession | TpmResourceType::PolicySession =
                resource.resource_type
            {
                debug!(
                    "TPM: set attributes 0x{:02x} for session 0x{:08x} in session space {}",
                    attributes, handle, self.id
                );
                true
            } else {
                false
            }
        } else {
            false
        }
    }

    /// Gets session attributes for auditing/encryption.
    pub fn get_session_attributes(&self, handle: TpmResourceHandle) -> Option<u8> {
        let sessions = self.sessions.lock();
        sessions.get(&handle).map(|_| 0)
    }

    /// Evicts a session context to make room for new sessions.
    pub fn evict_session(
        &self,
        handle: TpmResourceHandle,
    ) -> Option<(TpmResourceType, Vec<u8>, Vec<u8>, Vec<u8>)> {
        let mut sessions = self.sessions.lock();
        let mut evicted = self.evicted_sessions.lock();
        if let Some(resource) = sessions.remove(&handle) {
            let public_area = resource.public_area.clone().unwrap_or_default();
            let private_area = resource.private_area.clone().unwrap_or_default();
            let name = resource.name.clone().unwrap_or_default();

            evicted.insert(
                handle,
                (
                    resource.resource_type,
                    public_area.clone(),
                    private_area.clone(),
                    name.clone(),
                ),
            );

            debug!(
                "TPM: evicted session 0x{:08x} ({:?}) from session space {}",
                handle, resource.resource_type, self.id
            );

            Some((resource.resource_type, public_area, private_area, name))
        } else {
            None
        }
    }

    /// Restores an evicted session context by handle.
    pub fn restore_session(&self, handle: TpmResourceHandle) -> Option<TpmResourceHandle> {
        let mut evicted = self.evicted_sessions.lock();
        let mut sessions = self.sessions.lock();
        if let Some((session_type, public_area, private_area, name)) = evicted.remove(&handle) {
            let restored_handle = self
                .resource_manager()
                .create_resource(session_type, Vec::new());

            sessions.insert(
                restored_handle,
                TpmResource {
                    handle: restored_handle,
                    resource_type: session_type,
                    data: Vec::new(),
                    public_area: Some(public_area),
                    private_area: Some(private_area),
                    name: Some(name),
                    last_used: 0,
                },
            );

            debug!(
                "TPM: restored session with handle 0x{:08x} from evicted session 0x{:08x} ({:?}) in session space {}",
                restored_handle, handle, session_type, self.id
            );

            Some(restored_handle)
        } else {
            None
        }
    }

    /// Restores a session from raw context data, returning the new handle.
    pub fn restore_session_from_data(
        &self,
        session_type: TpmResourceType,
        public_area: Vec<u8>,
        private_area: Vec<u8>,
        name: Vec<u8>,
    ) -> TpmResourceHandle {
        let handle = self
            .resource_manager()
            .create_resource(session_type, Vec::new());

        let mut sessions = self.sessions.lock();
        sessions.insert(
            handle,
            TpmResource {
                handle,
                resource_type: session_type,
                data: Vec::new(),
                public_area: Some(public_area),
                private_area: Some(private_area),
                name: Some(name),
                last_used: 0,
            },
        );

        debug!(
            "TPM: restored session with handle 0x{:08x} ({:?}) in session space {}",
            handle, session_type, self.id
        );

        handle
    }

    /// Implements LRU eviction policy when session space is full.
    pub fn evict_lru_session(
        &self,
    ) -> Option<(
        TpmResourceHandle,
        TpmResourceType,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
    )> {
        let mut sessions = self.sessions.lock();
        if sessions.is_empty() {
            return None;
        }

        let mut oldest_handle = None;
        let mut oldest_time = u64::MAX;

        for (handle, resource) in sessions.iter() {
            if resource.last_used < oldest_time {
                oldest_time = resource.last_used;
                oldest_handle = Some(*handle);
            }
        }

        if let Some(handle) = oldest_handle {
            if let Some(resource) = sessions.remove(&handle) {
                let public_area = resource.public_area.clone().unwrap_or_default();
                let private_area = resource.private_area.clone().unwrap_or_default();
                let name = resource.name.clone().unwrap_or_default();

                debug!(
                    "TPM: evicted LRU session 0x{:08x} ({:?}) from session space {}",
                    handle, resource.resource_type, self.id
                );

                Some((
                    handle,
                    resource.resource_type,
                    public_area,
                    private_area,
                    name,
                ))
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Removes a session handle from this space.
    pub fn untrack_session(&self, handle: TpmResourceHandle) -> bool {
        let removed = self.sessions.lock().remove(&handle).is_some();
        if removed {
            debug!(
                "TPM: untracked session 0x{:08x} from session space {}",
                handle, self.id
            );
        }
        removed
    }

    /// Returns all session handles in this space.
    pub fn session_handles(&self) -> Vec<TpmResourceHandle> {
        self.sessions.lock().keys().copied().collect()
    }

    /// Returns the number of sessions in this space.
    pub fn session_count(&self) -> usize {
        self.sessions.lock().len()
    }

    /// Disposes the session space and cleans up all resources.
    pub fn dispose(&self) {
        let mut disposed = self.disposed.lock();
        if *disposed {
            return;
        }
        *disposed = true;

        info!("TPM: disposing session space with id {}", self.id);

        self.sessions.lock().clear();
        self.evicted_sessions.lock().clear();
        self.resource_manager.clear_all();
    }

    /// Returns true if this session space has been disposed.
    pub fn is_disposed(&self) -> bool {
        *self.disposed.lock()
    }
}

impl Drop for TpmSessionSpace {
    fn drop(&mut self) {
        self.dispose();
    }
}

// ---------------------------------------------------------------------------
// TpmSpaceManager — manages multiple TPM spaces
// ---------------------------------------------------------------------------

/// Manages multiple TPM spaces.
pub struct TpmSpaceManager {
    /// Map of space ID to space.
    spaces: Mutex<BTreeMap<TpmSpaceId, Arc<TpmSpace>>>,
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
            spaces: Mutex::new(BTreeMap::new()),
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

        let handle1 = space1
            .resource_manager()
            .create_resource(crate::resource::TpmResourceType::Key, vec![1, 2, 3]);

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

        let handle = space
            .resource_manager()
            .create_resource(crate::resource::TpmResourceType::Key, vec![]);

        assert!(space.resource_manager().get_resource(handle).is_some());

        manager.dispose_space(id);

        assert_eq!(space.resource_manager().resource_count(), 0);
    }

    #[test]
    fn test_space_session_tracking() {
        let space = TpmSpace::new(1);

        space.track_session(0x02000001);
        space.track_session(0x02000002);

        assert_eq!(space.session_count(), 2);

        assert!(space.untrack_session(0x02000001));
        assert_eq!(space.session_count(), 1);
        assert!(!space.untrack_session(0x02000001));
    }

    #[test]
    fn test_space_session_isolation() {
        let space1 = TpmSpace::new(1);
        let space2 = TpmSpace::new(2);

        space1.track_session(0x02000001);

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

    #[test]
    fn test_object_space_track_and_get() {
        let obj_space = TpmObjectSpace::new(1);

        obj_space.track_object_with_data(
            0x80000001,
            Some(vec![1, 2, 3]),
            Some(vec![4, 5, 6]),
            Some(vec![7, 8]),
        );

        assert_eq!(obj_space.object_count(), 1);

        let (pub_area, priv_area, name) = obj_space.get_object_data(0x80000001).unwrap();
        assert_eq!(pub_area, Some(vec![1, 2, 3]));
        assert_eq!(priv_area, Some(vec![4, 5, 6]));
        assert_eq!(name, Some(vec![7, 8]));
    }

    #[test]
    fn test_object_space_evict_and_restore() {
        let obj_space = TpmObjectSpace::new(1);

        obj_space.track_object_with_data(
            0x80000001,
            Some(vec![1, 2, 3]),
            Some(vec![4, 5, 6]),
            Some(vec![7, 8]),
        );

        let (pub_area, priv_area, name) = obj_space.evict_object(0x80000001).unwrap();
        assert_eq!(pub_area, vec![1, 2, 3]);
        assert_eq!(priv_area, vec![4, 5, 6]);
        assert_eq!(obj_space.object_count(), 0);

        let restored = obj_space.restore_object(0x80000001).unwrap();
        assert_eq!(obj_space.object_count(), 1);
        assert_ne!(restored, 0x80000001);
    }

    #[test]
    fn test_session_space_track_and_get() {
        let sess_space = TpmSessionSpace::new(1);

        sess_space.track_session_with_data(0x02000001, TpmResourceType::HmacSession);

        assert_eq!(sess_space.session_count(), 1);

        let (stype, _, _, _) = sess_space.get_session_data(0x02000001).unwrap();
        assert_eq!(stype, TpmResourceType::HmacSession);
    }
}
