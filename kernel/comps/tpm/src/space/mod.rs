// SPDX-License-Identifier: MPL-2.0

//! TPM 2.0 space module.
//!
//! Provides TPM space abstractions for session isolation and resource management.
//! Each space maintains its own resource context, enabling multi-process TPM access.

use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};

use log::{debug, info};
use ostd::sync::Mutex as SleepMutex;
use spin::Mutex;

use crate::resource::{TpmResource, TpmResourceHandle, TpmResourceManager, TpmResourceType};

/// Unique identifier for a TPM space.
pub type TpmSpaceId = u32;

/// First valid space ID.
const FIRST_SPACE_ID: TpmSpaceId = 1;

/// Session entry tracked by a TPM space.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct TpmSessionEntry {
    pub has_context_blob: bool,
    pub loaded: bool,
    pub real_handle: Option<u32>,
}

/// Object entry tracked by a TPM space.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct TpmObjectEntry {
    pub externally_loaded: bool,
    pub has_context_blob: bool,
    pub loaded: bool,
    pub real_handle: Option<u32>,
}

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
    /// Serializes the full command lifecycle within this space.
    transaction_lock: SleepMutex<()>,
    /// Resource manager for this space.
    resource_manager: Arc<TpmResourceManager>,
    /// Session table for this space.
    session_table: Mutex<BTreeMap<u32, TpmSessionEntry>>,
    /// Transient object table for this space.
    object_table: Mutex<BTreeMap<u32, TpmObjectEntry>>,
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
    fn allocate_object_logical_handle(&self) -> Option<u32> {
        let object_table = self.object_table.lock();
        let mut candidate = TpmResourceType::Key.handle_range_end();
        loop {
            if !object_table.contains_key(&candidate) {
                return Some(candidate);
            }

            if candidate == TpmResourceType::Key.handle_range_start() {
                return None;
            }

            candidate = candidate.checked_sub(1)?;
        }
    }

    /// Creates a new TPM space.
    pub fn new(id: TpmSpaceId) -> Self {
        debug!("TPM: creating space with id {}", id);
        Self {
            id,
            transaction_lock: SleepMutex::new(()),
            resource_manager: Arc::new(TpmResourceManager::new()),
            session_table: Mutex::new(BTreeMap::new()),
            object_table: Mutex::new(BTreeMap::new()),
            disposed: Mutex::new(false),
        }
    }

    /// Returns the space ID.
    pub fn id(&self) -> TpmSpaceId {
        self.id
    }

    /// Returns the transaction lock for this space.
    pub(crate) fn transaction_lock(&self) -> &SleepMutex<()> {
        &self.transaction_lock
    }

    /// Returns a reference to the resource manager.
    pub fn resource_manager(&self) -> &TpmResourceManager {
        &self.resource_manager
    }

    /// Tracks a session handle in this space.
    pub(crate) fn track_session(&self, handle: u32) {
        self.session_table.lock().insert(
            handle,
            TpmSessionEntry {
                has_context_blob: false,
                loaded: true,
                real_handle: Some(handle),
            },
        );
        debug!(
            "TPM: tracking session 0x{:08x} in space {}",
            handle, self.id
        );
    }

    /// Removes a session handle from this space.
    pub(crate) fn untrack_session(&self, handle: u32) -> bool {
        let removed = self.session_table.lock().remove(&handle).is_some();
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
        self.session_table.lock().keys().copied().collect()
    }

    /// Returns all session handles that are currently loaded in the TPM.
    pub(crate) fn loaded_session_handles(&self) -> Vec<u32> {
        self.session_table
            .lock()
            .iter()
            .filter_map(|(&handle, entry)| entry.loaded.then_some(handle))
            .collect()
    }

    /// Returns the number of sessions in this space.
    pub fn session_count(&self) -> usize {
        self.session_table.lock().len()
    }

    /// Returns the tracked session entry for `handle`.
    pub(crate) fn session_entry(&self, handle: u32) -> Option<TpmSessionEntry> {
        self.session_table.lock().get(&handle).copied()
    }

    /// Marks a tracked session as currently loaded in the TPM under `real_handle`.
    pub(crate) fn mark_session_loaded_with_real(&self, handle: u32, real_handle: u32) {
        if let Some(entry) = self.session_table.lock().get_mut(&handle) {
            entry.has_context_blob = false;
            entry.loaded = true;
            entry.real_handle = Some(real_handle);
        }
    }

    /// Stores a context blob for a tracked session.
    pub(crate) fn store_session_context_blob(&self, handle: u32, context_blob: Vec<u8>) {
        self.resource_manager
            .store_context_blob(handle, context_blob);
        if let Some(entry) = self.session_table.lock().get_mut(&handle) {
            entry.has_context_blob = true;
            entry.loaded = false;
            entry.real_handle = None;
        }
    }

    /// Returns the stored context blob for a tracked session.
    pub(crate) fn session_context_blob(&self, handle: u32) -> Option<Vec<u8>> {
        self.session_entry(handle)
            .filter(|entry| entry.has_context_blob)
            .and_then(|_| self.resource_manager.get_context_blob(handle))
    }

    /// Removes the stored context blob for a tracked session.
    pub(crate) fn remove_session_context_blob(&self, handle: u32) -> Option<Vec<u8>> {
        let removed = self.resource_manager.remove_context_blob(handle);
        if removed.is_some() {
            if let Some(entry) = self.session_table.lock().get_mut(&handle) {
                entry.has_context_blob = false;
            }
        }
        removed
    }

    /// Returns whether a tracked session is currently loaded in the TPM.
    pub(crate) fn session_is_loaded(&self, handle: u32) -> bool {
        self.session_entry(handle).is_some_and(|entry| entry.loaded)
    }

    /// Returns whether a tracked session should be restored before use.
    pub(crate) fn session_needs_context_load(&self, handle: u32) -> bool {
        self.session_entry(handle)
            .is_some_and(|entry| entry.has_context_blob && !entry.loaded)
    }

    /// Marks a tracked session as saved back to its context blob.
    pub(crate) fn mark_session_saved(&self, handle: u32) {
        if let Some(entry) = self.session_table.lock().get_mut(&handle) {
            entry.has_context_blob = true;
            entry.loaded = false;
            entry.real_handle = None;
        }
    }

    /// Applies the state transition for an explicit session `ContextSave`.
    pub(crate) fn finish_explicit_session_context_save(&self, handle: u32) {
        self.mark_session_saved(handle);
    }

    /// Starts tracking a newly created or restored live session.
    pub(crate) fn insert_loaded_session(&self, handle: u32) {
        self.track_session(handle);
    }

    /// Tracks a transient object handle in this space.
    pub(crate) fn track_object(&self, handle: u32) {
        self.resource_manager
            .set_virtual_handle_mapping(handle, handle, TpmResourceType::Key);
        self.object_table.lock().insert(
            handle,
            TpmObjectEntry {
                externally_loaded: false,
                has_context_blob: false,
                loaded: true,
                real_handle: Some(handle),
            },
        );
        debug!(
            "TPM: tracking transient object 0x{:08x} in space {}",
            handle, self.id
        );
    }

    /// Removes a transient object handle from this space.
    pub(crate) fn untrack_object(&self, handle: u32) -> bool {
        self.resource_manager.remove_virtual_mapping(handle);
        let removed = self.object_table.lock().remove(&handle).is_some();
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
        self.object_table.lock().keys().copied().collect()
    }

    /// Returns all transient object handles that are currently loaded in the TPM.
    pub(crate) fn loaded_object_handles(&self) -> Vec<u32> {
        self.object_table
            .lock()
            .iter()
            .filter_map(|(&handle, entry)| entry.loaded.then_some(handle))
            .collect()
    }

    /// Returns the tracked object entry for `handle`.
    pub(crate) fn object_entry(&self, handle: u32) -> Option<TpmObjectEntry> {
        self.object_table.lock().get(&handle).copied()
    }

    /// Stores a context blob for a tracked object.
    pub(crate) fn store_object_context_blob(&self, handle: u32, context_blob: Vec<u8>) {
        self.resource_manager
            .store_context_blob(handle, context_blob);
        self.resource_manager.remove_virtual_mapping(handle);
        if let Some(entry) = self.object_table.lock().get_mut(&handle) {
            entry.has_context_blob = true;
            entry.loaded = false;
            entry.real_handle = None;
        }
    }

    /// Returns the stored context blob for a tracked object.
    pub(crate) fn object_context_blob(&self, handle: u32) -> Option<Vec<u8>> {
        self.object_entry(handle)
            .filter(|entry| entry.has_context_blob)
            .and_then(|_| self.resource_manager.get_context_blob(handle))
    }

    /// Returns whether a tracked object should be restored before command execution.
    pub(crate) fn object_needs_context_load(&self, handle: u32) -> bool {
        self.object_entry(handle)
            .is_some_and(|entry| entry.has_context_blob && !entry.loaded)
    }

    /// Removes the stored context blob for a tracked object.
    pub(crate) fn remove_object_context_blob(&self, handle: u32) -> Option<Vec<u8>> {
        let removed = self.resource_manager.remove_context_blob(handle);
        if removed.is_some() {
            if let Some(entry) = self.object_table.lock().get_mut(&handle) {
                entry.has_context_blob = false;
            }
        }
        removed
    }

    /// Marks a tracked object as currently loaded in the TPM under `real_handle`.
    pub(crate) fn mark_object_loaded_with_real(&self, handle: u32, real_handle: u32) {
        self.resource_manager
            .set_virtual_handle_mapping(handle, real_handle, TpmResourceType::Key);
        if let Some(entry) = self.object_table.lock().get_mut(&handle) {
            entry.externally_loaded = false;
            entry.has_context_blob = false;
            entry.loaded = true;
            entry.real_handle = Some(real_handle);
        }
    }

    /// Marks an object as being explicitly restored from a userspace context.
    pub fn mark_externally_loaded_object(&self, handle: u32) {
        self.resource_manager
            .set_virtual_handle_mapping(handle, handle, TpmResourceType::Key);
        let mut object_table = self.object_table.lock();
        let entry = object_table.entry(handle).or_default();
        entry.externally_loaded = true;
        entry.has_context_blob = false;
        entry.loaded = true;
        entry.real_handle = Some(handle);
        debug!(
            "TPM: marked transient object 0x{:08x} as externally loaded in space {}",
            handle, self.id
        );
    }

    /// Returns whether a tracked object is currently loaded in the TPM.
    pub(crate) fn object_is_loaded(&self, handle: u32) -> bool {
        self.object_entry(handle).is_some_and(|entry| entry.loaded)
    }

    /// Marks a tracked object as saved back to its context blob.
    pub(crate) fn mark_object_saved(&self, handle: u32) {
        self.resource_manager.remove_virtual_mapping(handle);
        if let Some(entry) = self.object_table.lock().get_mut(&handle) {
            entry.externally_loaded = false;
            entry.has_context_blob = true;
            entry.loaded = false;
            entry.real_handle = None;
        }
    }

    /// Returns the current real TPM handle for a loaded tracked object.
    pub(crate) fn object_real_handle(&self, handle: u32) -> Option<u32> {
        self.object_entry(handle)
            .and_then(|entry| entry.real_handle)
    }

    /// Returns the logical handle that currently maps to `real_handle`.
    pub(crate) fn logical_object_handle_for_real(&self, real_handle: u32) -> Option<u32> {
        self.resource_manager
            .map_real_to_virtual(real_handle)
            .filter(|logical_handle| self.object_entry(*logical_handle).is_some())
    }

    /// Applies the state transition for an explicit object `ContextLoad`.
    pub(crate) fn finish_explicit_object_context_load(
        &self,
        saved_handle: u32,
        loaded_handle: u32,
        externally_loaded: bool,
        reuse_saved_handle: bool,
    ) -> Option<u32> {
        if reuse_saved_handle {
            self.remove_object_context_blob(saved_handle);
            self.resource_manager.set_virtual_handle_mapping(
                saved_handle,
                loaded_handle,
                TpmResourceType::Key,
            );
            let mut object_table = self.object_table.lock();
            let entry = object_table.entry(saved_handle).or_default();
            entry.externally_loaded = externally_loaded;
            entry.has_context_blob = false;
            entry.loaded = true;
            entry.real_handle = Some(loaded_handle);
            return Some(saved_handle);
        }

        let logical_handle = self.insert_loaded_object_with_real(loaded_handle)?;
        if externally_loaded {
            if let Some(entry) = self.object_table.lock().get_mut(&logical_handle) {
                entry.externally_loaded = true;
            }
        }
        Some(logical_handle)
    }

    /// Applies the state transition for an explicit session `ContextLoad`.
    pub(crate) fn finish_explicit_session_context_load(
        &self,
        saved_handle: u32,
        loaded_handle: u32,
    ) {
        self.remove_session_context_blob(saved_handle);
        self.mark_session_loaded_with_real(saved_handle, loaded_handle);
    }

    /// Returns the current real TPM handle for a loaded tracked session.
    pub(crate) fn session_real_handle(&self, handle: u32) -> Option<u32> {
        self.session_entry(handle)
            .and_then(|entry| entry.real_handle)
    }

    /// Returns the logical session handle that currently maps to `real_handle`.
    pub(crate) fn logical_session_handle_for_real(&self, real_handle: u32) -> Option<u32> {
        self.session_table
            .lock()
            .iter()
            .find_map(|(&logical_handle, entry)| {
                (entry.real_handle == Some(real_handle)).then_some(logical_handle)
            })
    }

    /// Starts tracking a newly created live object under a stable logical handle.
    ///
    /// Returns the logical handle that should be exposed outside the space.
    pub(crate) fn insert_loaded_object_with_real(&self, real_handle: u32) -> Option<u32> {
        let logical_handle = self.allocate_object_logical_handle()?;
        self.resource_manager.set_virtual_handle_mapping(
            logical_handle,
            real_handle,
            TpmResourceType::Key,
        );
        self.object_table.lock().insert(
            logical_handle,
            TpmObjectEntry {
                externally_loaded: false,
                has_context_blob: false,
                loaded: true,
                real_handle: Some(real_handle),
            },
        );
        debug!(
            "TPM: tracking transient object real=0x{:08x} as logical=0x{:08x} in space {}",
            real_handle, logical_handle, self.id
        );
        Some(logical_handle)
    }

    /// Returns the number of transient objects in this space.
    pub fn object_count(&self) -> usize {
        self.object_table.lock().len()
    }

    /// Disposes the space and cleans up all resources and sessions.
    pub fn dispose(&self) {
        let mut disposed = self.disposed.lock();
        if *disposed {
            return;
        }
        *disposed = true;

        info!("TPM: disposing space with id {}", self.id);

        let sessions: Vec<u32> = self.session_table.lock().keys().copied().collect();
        if !sessions.is_empty() {
            debug!(
                "TPM: clearing {} sessions from space {}",
                sessions.len(),
                self.id
            );
            self.session_table.lock().clear();
        }

        let objects: Vec<u32> = self.object_table.lock().keys().copied().collect();
        if !objects.is_empty() {
            debug!(
                "TPM: clearing {} transient objects from space {}",
                objects.len(),
                self.id
            );
            self.object_table.lock().clear();
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
    fn test_space_explicit_session_context_save_keeps_logical_handle() {
        let space = TpmSpace::new(1);
        let session_handle = 0x02000001;

        space.track_session(session_handle);
        space.store_session_context_blob(session_handle, vec![1, 2, 3]);
        space.finish_explicit_session_context_save(session_handle);

        assert!(space.session_entry(session_handle).is_some());
        assert!(space.session_needs_context_load(session_handle));
        assert_eq!(space.session_real_handle(session_handle), None);
    }

    #[test]
    fn test_space_explicit_session_context_load_keeps_logical_handle() {
        let space = TpmSpace::new(1);
        let logical_handle = 0x02000001;
        let loaded_handle = 0x02000011;

        space.track_session(logical_handle);
        space.store_session_context_blob(logical_handle, vec![1, 2, 3]);
        space.finish_explicit_session_context_load(logical_handle, loaded_handle);

        assert!(space.session_entry(logical_handle).is_some());
        assert!(space.session_is_loaded(logical_handle));
        assert_eq!(
            space.session_real_handle(logical_handle),
            Some(loaded_handle)
        );
        assert_eq!(
            space.logical_session_handle_for_real(loaded_handle),
            Some(logical_handle)
        );
        assert!(space.session_context_blob(logical_handle).is_none());
    }

    #[test]
    fn test_space_explicit_object_context_load_keeps_logical_handle_for_known_object() {
        let space = TpmSpace::new(1);
        let logical_handle = 0x80000000;
        let loaded_handle = 0x80000010;

        space.track_object(logical_handle);
        space.store_object_context_blob(logical_handle, vec![4, 5, 6]);
        let returned_handle = space
            .finish_explicit_object_context_load(logical_handle, loaded_handle, true, true)
            .expect("known object load should succeed");

        assert_eq!(returned_handle, logical_handle);
        assert!(space.object_entry(logical_handle).is_some());
        assert!(space.object_is_loaded(logical_handle));
        assert_eq!(
            space.object_real_handle(logical_handle),
            Some(loaded_handle)
        );
        assert!(
            space
                .object_entry(logical_handle)
                .is_some_and(|entry| entry.externally_loaded)
        );
        assert!(space.object_context_blob(logical_handle).is_none());
    }

    #[test]
    fn test_space_explicit_object_context_load_allocates_fresh_handle_for_external_object() {
        let space = TpmSpace::new(1);
        let saved_handle_from_other_space = 0x80ff_ffff;
        let loaded_handle = 0x8000_0010;

        let returned_handle = space
            .finish_explicit_object_context_load(
                saved_handle_from_other_space,
                loaded_handle,
                true,
                false,
            )
            .expect("external object load should allocate a fresh logical handle");

        assert_ne!(returned_handle, saved_handle_from_other_space);
        assert!((0x8000_0000..=0x80FF_FFFF).contains(&returned_handle));
        assert!(space.object_is_loaded(returned_handle));
        assert_eq!(
            space.object_real_handle(returned_handle),
            Some(loaded_handle)
        );
        assert!(
            space
                .object_entry(returned_handle)
                .is_some_and(|entry| entry.externally_loaded)
        );
    }

    #[test]
    fn test_space_new_object_uses_transient_virtual_handle_mapping() {
        let space = TpmSpace::new(1);
        let real_handle = 0x80000001;

        let logical_handle = space
            .insert_loaded_object_with_real(real_handle)
            .expect("transient virtual handle allocation should succeed");

        assert!((0x8000_0000..=0x80FF_FFFF).contains(&logical_handle));
        assert_eq!(space.object_real_handle(logical_handle), Some(real_handle));
        assert_eq!(
            space.logical_object_handle_for_real(real_handle),
            Some(logical_handle)
        );
    }

    #[test]
    fn test_explicit_object_load_state_becomes_space_managed_after_save_and_reload() {
        let space = TpmSpace::new(1);
        let logical_handle = 0x80ff_ffff;
        let first_real_handle = 0x8000_0010;
        let second_real_handle = 0x8000_0020;

        space.track_object(logical_handle);
        space.store_object_context_blob(logical_handle, vec![1, 2, 3]);
        let returned_handle = space
            .finish_explicit_object_context_load(logical_handle, first_real_handle, true, true)
            .expect("known object load should succeed");
        assert_eq!(returned_handle, logical_handle);
        assert!(
            space
                .object_entry(logical_handle)
                .is_some_and(|entry| entry.externally_loaded)
        );

        space.mark_object_saved(logical_handle);
        assert!(
            !space
                .object_entry(logical_handle)
                .is_some_and(|entry| entry.externally_loaded)
        );

        space.mark_object_loaded_with_real(logical_handle, second_real_handle);
        let entry = space
            .object_entry(logical_handle)
            .expect("object entry should exist after reload");
        assert!(!entry.externally_loaded);
        assert!(entry.loaded);
        assert_eq!(entry.real_handle, Some(second_real_handle));
    }

    #[test]
    fn test_external_object_load_with_same_saved_handle_does_not_alias_existing_object() {
        let space = TpmSpace::new(1);
        let original_logical_handle = 0x80ff_ffff;
        let original_real_handle = 0x8000_0010;
        let colliding_external_real_handle = 0x8000_0020;

        space.track_object(original_logical_handle);
        space.store_object_context_blob(original_logical_handle, vec![1, 2, 3]);
        let original_returned_handle = space
            .finish_explicit_object_context_load(
                original_logical_handle,
                original_real_handle,
                true,
                true,
            )
            .expect("known object load should succeed");
        assert_eq!(original_returned_handle, original_logical_handle);

        space.mark_object_saved(original_logical_handle);

        let fresh_handle = space
            .finish_explicit_object_context_load(
                original_logical_handle,
                colliding_external_real_handle,
                true,
                false,
            )
            .expect("external colliding load should allocate a fresh logical handle");

        assert_ne!(fresh_handle, original_logical_handle);
        assert_eq!(
            space.object_real_handle(fresh_handle),
            Some(colliding_external_real_handle)
        );
        assert!(space.object_context_blob(original_logical_handle).is_some());
    }

    #[test]
    fn test_saved_object_keeps_its_slot_reserved() {
        let space = TpmSpace::new(1);
        let first_real_handle = 0x8000_0010;
        let second_real_handle = 0x8000_0020;

        let first_logical_handle = space
            .insert_loaded_object_with_real(first_real_handle)
            .expect("first object slot should be available");
        assert_eq!(first_logical_handle, 0x80ff_ffff);

        space.mark_object_saved(first_logical_handle);

        let second_logical_handle = space
            .insert_loaded_object_with_real(second_real_handle)
            .expect("second object slot should be available");
        assert_eq!(second_logical_handle, 0x80ff_fffe);
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
