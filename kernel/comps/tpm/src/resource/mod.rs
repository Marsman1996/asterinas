// SPDX-License-Identifier: MPL-2.0

//! TPM resource management module.
//!
//! Provides handle tracking and resource lifecycle management for TPM objects.

extern crate alloc;

use alloc::{collections::BTreeMap, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};

use log::{debug, info, warn};
use spin::Mutex;

use crate::protocol::constants::handle;

/// Type alias for TPM resource handles.
pub type TpmResourceHandle = u32;

/// First valid resource handle value.
const FIRST_HANDLE: TpmResourceHandle = 0x80000000;

/// First virtual handle value for tpmrm-style isolation.
const FIRST_VIRTUAL_HANDLE: TpmResourceHandle = 0x00000001;

/// Monotonic counter for LRU timestamp tracking (no_std safe).
static TIMESTAMP_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Returns a monotonically increasing timestamp for LRU tracking.
fn current_timestamp() -> u64 {
    TIMESTAMP_COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Represents a virtual handle mapping for tpmrm isolation.
///
/// This implements Linux tpmrm-dev.c style handle virtualization
/// where each file open gets its own virtual handle namespace.
#[derive(Debug, Clone)]
pub struct HandleMapping {
    /// Virtual handle (userspace-visible).
    pub virtual_handle: TpmResourceHandle,
    /// Real TPM handle.
    pub real_handle: TpmResourceHandle,
    /// Resource type.
    pub resource_type: TpmResourceType,
}

/// Handle virtualization table for per-file isolation.
///
/// Maps between virtual handles (userspace) and real TPM handles.
pub struct HandleVirtualizer {
    /// Map from virtual handle to real handle.
    virtual_to_real: Mutex<BTreeMap<TpmResourceHandle, HandleMapping>>,
    /// Map from real handle to virtual handle.
    real_to_virtual: Mutex<BTreeMap<TpmResourceHandle, TpmResourceHandle>>,
    /// Next virtual handle to allocate.
    next_virtual: Mutex<TpmResourceHandle>,
}

impl core::fmt::Debug for HandleVirtualizer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HandleVirtualizer").finish()
    }
}

impl HandleVirtualizer {
    /// Creates a new handle virtualizer.
    pub fn new() -> Self {
        Self {
            virtual_to_real: Mutex::new(BTreeMap::new()),
            real_to_virtual: Mutex::new(BTreeMap::new()),
            next_virtual: Mutex::new(FIRST_VIRTUAL_HANDLE),
        }
    }

    /// Allocates a virtual handle for a real TPM handle.
    ///
    /// Returns the virtual handle that should be returned to userspace.
    pub fn allocate_virtual(
        &self,
        real_handle: TpmResourceHandle,
        resource_type: TpmResourceType,
    ) -> TpmResourceHandle {
        let mut next = self.next_virtual.lock();
        let virtual_handle = *next;
        *next = next.wrapping_add(1);

        let mapping = HandleMapping {
            virtual_handle,
            real_handle,
            resource_type,
        };

        self.virtual_to_real.lock().insert(virtual_handle, mapping);
        self.real_to_virtual
            .lock()
            .insert(real_handle, virtual_handle);

        debug!(
            "TPM: mapped real handle 0x{:08x} to virtual handle 0x{:08x}",
            real_handle, virtual_handle
        );

        virtual_handle
    }

    /// Maps a virtual handle to a real TPM handle.
    ///
    /// Returns the real handle if the virtual handle is valid.
    pub fn map_to_real(&self, virtual_handle: TpmResourceHandle) -> Option<TpmResourceHandle> {
        let mappings = self.virtual_to_real.lock();
        mappings.get(&virtual_handle).map(|m| m.real_handle)
    }

    /// Maps a real handle to a virtual handle.
    ///
    /// Returns the virtual handle if the real handle is mapped.
    pub fn map_to_virtual(&self, real_handle: TpmResourceHandle) -> Option<TpmResourceHandle> {
        let mappings = self.real_to_virtual.lock();
        mappings.get(&real_handle).copied()
    }

    /// Removes a mapping by virtual handle.
    ///
    /// Returns true if the mapping was found and removed.
    pub fn remove_by_virtual(&self, virtual_handle: TpmResourceHandle) -> bool {
        let mut v2r = self.virtual_to_real.lock();
        if let Some(mapping) = v2r.remove(&virtual_handle) {
            self.real_to_virtual.lock().remove(&mapping.real_handle);
            debug!(
                "TPM: unmapped virtual handle 0x{:08x} (real 0x{:08x})",
                virtual_handle, mapping.real_handle
            );
            true
        } else {
            false
        }
    }

    /// Clears all mappings.
    pub fn clear_all(&self) {
        let count = self.virtual_to_real.lock().len();
        self.virtual_to_real.lock().clear();
        self.real_to_virtual.lock().clear();
        if count > 0 {
            info!("TPM: cleared {} handle mappings", count);
        }
    }

    /// Returns the number of active mappings.
    pub fn mapping_count(&self) -> usize {
        self.virtual_to_real.lock().len()
    }
}

impl Default for HandleVirtualizer {
    fn default() -> Self {
        Self::new()
    }
}

/// Represents a TPM resource context.
#[derive(Debug, Clone)]
pub struct TpmResource {
    /// The handle assigned to this resource.
    pub handle: TpmResourceHandle,
    /// Type of resource.
    pub resource_type: TpmResourceType,
    /// Additional resource data (if any).
    pub data: Vec<u8>,
    /// Public area of an object (for TPM2_Create/TPM2_Load).
    pub public_area: Option<Vec<u8>>,
    /// Private area of an object (for TPM2_Create/TPM2_Load).
    pub private_area: Option<Vec<u8>>,
    /// Name of the object (derived from public area).
    pub name: Option<Vec<u8>>,
    /// Last used timestamp for LRU eviction.
    pub last_used: u64,
}

/// Types of TPM resources.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpmResourceType {
    /// Loaded key object.
    Key,
    /// NV index.
    NvIndex,
    /// HMAC session context.
    HmacSession,
    /// Policy session context.
    PolicySession,
    /// Permanent handle (owner, platform, etc).
    Permanent,
}

impl TpmResourceType {
    /// Returns the handle range start for this resource type.
    pub fn handle_range_start(&self) -> TpmResourceHandle {
        match self {
            TpmResourceType::Key => 0x80000000,
            TpmResourceType::NvIndex => 0x01000000,
            TpmResourceType::HmacSession => handle::TPM_HT_HMAC_SESSION,
            TpmResourceType::PolicySession => handle::TPM_HT_POLICY_SESSION,
            TpmResourceType::Permanent => handle::TPM_HT_PERMANENT,
        }
    }

    /// Returns the handle range end for this resource type.
    pub fn handle_range_end(&self) -> TpmResourceHandle {
        match self {
            TpmResourceType::Key => 0x80FFFFFF,
            TpmResourceType::NvIndex => 0x01FFFFFF,
            TpmResourceType::HmacSession => handle::TPM_HT_HMAC_SESSION + 0x00FFFFFF,
            TpmResourceType::PolicySession => handle::TPM_HT_POLICY_SESSION + 0x00FFFFFF,
            TpmResourceType::Permanent => handle::TPM_HT_PERMANENT + 0x00FFFFFF,
        }
    }

    /// Determines the resource type from a handle value.
    pub fn from_handle(handle: TpmResourceHandle) -> Option<Self> {
        if handle >= handle::TPM_HT_POLICY_SESSION
            && handle < handle::TPM_HT_POLICY_SESSION + 0x01000000
        {
            Some(TpmResourceType::PolicySession)
        } else if handle >= handle::TPM_HT_HMAC_SESSION
            && handle < handle::TPM_HT_HMAC_SESSION + 0x01000000
        {
            Some(TpmResourceType::HmacSession)
        } else if handle >= handle::TPM_HT_PERMANENT
            && handle < handle::TPM_HT_PERMANENT + 0x01000000
        {
            Some(TpmResourceType::Permanent)
        } else if handle >= 0x80000000 && handle < 0x90000000 {
            Some(TpmResourceType::Key)
        } else if handle >= 0x01000000 && handle < 0x02000000 {
            Some(TpmResourceType::NvIndex)
        } else {
            None
        }
    }

    /// Validates that a handle is within the valid range for its type.
    pub fn validate_handle_for_type(
        handle: TpmResourceHandle,
        expected_type: TpmResourceType,
    ) -> bool {
        let start = expected_type.handle_range_start();
        let end = expected_type.handle_range_end();
        handle >= start && handle <= end
    }
}

/// Manages TPM resource handles and their associated contexts.
///
/// This resource manager tracks TPM resources (objects, sessions, etc.) by their handles.
/// It is designed to be used per-TPM-space to provide isolated resource contexts
/// for resource manager semantics (/dev/tpmrm0).
pub struct TpmResourceManager {
    /// Map of handle to resource context.
    resources: Mutex<BTreeMap<TpmResourceHandle, TpmResource>>,
    /// Next handle to allocate.
    next_handle: Mutex<TpmResourceHandle>,
    /// Handle virtualizer for userspace handle translation.
    handle_virtualizer: HandleVirtualizer,
    /// Stored context blobs for objects and sessions that have been evicted.
    context_blobs: Mutex<BTreeMap<TpmResourceHandle, (Vec<u8>, Vec<u8>, Vec<u8>)>>,
}

impl core::fmt::Debug for TpmResourceManager {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TpmResourceManager").finish()
    }
}

impl TpmResourceManager {
    /// Creates a new resource manager.
    pub fn new() -> Self {
        Self {
            resources: Mutex::new(BTreeMap::new()),
            next_handle: Mutex::new(FIRST_HANDLE),
            handle_virtualizer: HandleVirtualizer::new(),
            context_blobs: Mutex::new(BTreeMap::new()),
        }
    }

    /// Allocates a virtual handle for a real TPM handle.
    ///
    /// Returns the virtual handle that should be returned to userspace.
    pub fn allocate_virtual_handle(
        &self,
        real_handle: TpmResourceHandle,
        resource_type: TpmResourceType,
    ) -> TpmResourceHandle {
        self.handle_virtualizer
            .allocate_virtual(real_handle, resource_type)
    }

    /// Maps a virtual handle to a real TPM handle.
    ///
    /// Returns the real handle if the virtual handle is valid.
    pub fn map_virtual_to_real(
        &self,
        virtual_handle: TpmResourceHandle,
    ) -> Option<TpmResourceHandle> {
        self.handle_virtualizer.map_to_real(virtual_handle)
    }

    /// Maps a real handle to a virtual handle.
    ///
    /// Returns the virtual handle if the real handle is mapped.
    pub fn map_real_to_virtual(&self, real_handle: TpmResourceHandle) -> Option<TpmResourceHandle> {
        self.handle_virtualizer.map_to_virtual(real_handle)
    }

    /// Removes a mapping by virtual handle.
    ///
    /// Returns true if the mapping was found and removed.
    pub fn remove_virtual_mapping(&self, virtual_handle: TpmResourceHandle) -> bool {
        self.handle_virtualizer.remove_by_virtual(virtual_handle)
    }

    /// Allocates a new resource handle for the given type.
    ///
    /// Returns a unique handle within the type's range.
    pub fn allocate_handle(&self, resource_type: TpmResourceType) -> TpmResourceHandle {
        let mut next = self.next_handle.lock();
        let handle = *next;
        *next = next.wrapping_add(1);

        // Skip reserved ranges if needed
        if *next < FIRST_HANDLE {
            *next = FIRST_HANDLE;
        }

        debug!(
            "TPM: allocated handle 0x{:08x} for {:?}",
            handle, resource_type
        );

        handle
    }

    /// Inserts a resource with the given handle.
    pub fn insert_resource(&self, resource: TpmResource) {
        let mut resources = self.resources.lock();
        info!(
            "TPM: inserting resource with handle 0x{:08x}",
            resource.handle
        );
        resources.insert(resource.handle, resource);
    }

    /// Allocates and inserts a new resource.
    ///
    /// Returns the allocated handle.
    pub fn create_resource(
        &self,
        resource_type: TpmResourceType,
        data: Vec<u8>,
    ) -> TpmResourceHandle {
        let handle = self.allocate_handle(resource_type);
        let resource = TpmResource {
            handle,
            resource_type,
            data,
            public_area: None,
            private_area: None,
            name: None,
            last_used: 0,
        };
        self.insert_resource(resource);
        handle
    }

    /// Looks up a resource by handle.
    pub fn get_resource(&self, handle: TpmResourceHandle) -> Option<TpmResource> {
        let mut resources = self.resources.lock();
        if let Some(resource) = resources.get_mut(&handle) {
            resource.last_used = current_timestamp();
            Some(resource.clone())
        } else {
            None
        }
    }

    /// Looks up a resource by handle with type checking.
    ///
    /// Returns the resource only if it matches the expected type.
    pub fn get_resource_with_type(
        &self,
        handle: TpmResourceHandle,
        expected_type: TpmResourceType,
    ) -> Option<TpmResource> {
        let mut resources = self.resources.lock();
        let resource = resources.get_mut(&handle)?;
        if resource.resource_type != expected_type {
            warn!(
                "TPM: handle 0x{:08x} type mismatch: expected {:?}, found {:?}",
                handle, expected_type, resource.resource_type
            );
            return None;
        }
        resource.last_used = current_timestamp();
        Some(resource.clone())
    }

    /// Stores a context blob for a resource that has been evicted.
    ///
    /// This is used by TPM2_ContextSave to store the context blob
    /// so it can be later restored by TPM2_ContextLoad.
    pub fn store_context_blob(
        &self,
        handle: TpmResourceHandle,
        context_blob: (Vec<u8>, Vec<u8>, Vec<u8>),
    ) {
        let mut blobs = self.context_blobs.lock();
        blobs.insert(handle, context_blob);
        debug!("TPM: stored context blob for handle 0x{:08x}", handle);
    }

    /// Retrieves a stored context blob for a resource.
    ///
    /// This is used by TPM2_ContextLoad to retrieve the context blob
    /// that was previously stored by TPM2_ContextSave.
    pub fn get_context_blob(
        &self,
        handle: TpmResourceHandle,
    ) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let blobs = self.context_blobs.lock();
        blobs.get(&handle).cloned()
    }

    /// Removes a stored context blob after it has been used.
    ///
    /// This prevents accumulation of unused context blobs.
    pub fn remove_context_blob(
        &self,
        handle: TpmResourceHandle,
    ) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let mut blobs = self.context_blobs.lock();
        blobs.remove(&handle)
    }

    /// Releases a resource by handle.
    ///
    /// Returns true if the resource was found and removed.
    pub fn release_resource(&self, handle: TpmResourceHandle) -> bool {
        let mut resources = self.resources.lock();
        let removed = resources.remove(&handle).is_some();
        if removed {
            debug!("TPM: released resource with handle 0x{:08x}", handle);
        }
        removed
    }

    /// Releases all resources of a specific type.
    ///
    /// Returns the number of resources released.
    pub fn release_resources_by_type(&self, resource_type: TpmResourceType) -> usize {
        let mut resources = self.resources.lock();
        let to_remove: Vec<TpmResourceHandle> = resources
            .iter()
            .filter(|(_, r)| r.resource_type == resource_type)
            .map(|(&h, _)| h)
            .collect();

        let count = to_remove.len();
        for handle in to_remove {
            resources.remove(&handle);
            debug!(
                "TPM: released {:?} resource with handle 0x{:08x}",
                resource_type, handle
            );
        }

        if count > 0 {
            info!("TPM: released {} {:?} resources", count, resource_type);
        }
        count
    }

    /// Releases all session resources.
    ///
    /// Returns the number of sessions released.
    pub fn release_all_sessions(&self) -> usize {
        let hmac_count = self.release_resources_by_type(TpmResourceType::HmacSession);
        let policy_count = self.release_resources_by_type(TpmResourceType::PolicySession);
        hmac_count + policy_count
    }

    /// Returns the number of tracked resources.
    pub fn resource_count(&self) -> usize {
        let resources = self.resources.lock();
        resources.len()
    }

    /// Returns the number of resources of a specific type.
    pub fn resource_count_by_type(&self, resource_type: TpmResourceType) -> usize {
        let resources = self.resources.lock();
        resources
            .values()
            .filter(|r| r.resource_type == resource_type)
            .count()
    }

    /// Lists all handles of a specific type.
    pub fn list_handles_by_type(&self, resource_type: TpmResourceType) -> Vec<TpmResourceHandle> {
        let resources = self.resources.lock();
        resources
            .values()
            .filter(|r| r.resource_type == resource_type)
            .map(|r| r.handle)
            .collect()
    }

    /// Clears all resources.
    ///
    /// This should be called during cleanup.
    pub fn clear_all(&self) {
        let mut resources = self.resources.lock();
        let count = resources.len();
        resources.clear();
        if count > 0 {
            info!("TPM: cleared {} resources", count);
        }
    }
}

impl Default for TpmResourceManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handle_allocation() {
        let manager = TpmResourceManager::new();
        let handle1 = manager.allocate_handle(TpmResourceType::Key);
        let handle2 = manager.allocate_handle(TpmResourceType::Key);
        assert_ne!(handle1, handle2);
        assert!(handle1 >= FIRST_HANDLE);
    }

    #[test]
    fn test_resource_insert_and_lookup() {
        let manager = TpmResourceManager::new();
        let handle = manager.create_resource(TpmResourceType::Key, vec![1, 2, 3]);

        let resource = manager.get_resource(handle);
        assert!(resource.is_some());
        assert_eq!(resource.unwrap().resource_type, TpmResourceType::Key);
    }

    #[test]
    fn test_resource_release() {
        let manager = TpmResourceManager::new();
        let handle = manager.create_resource(TpmResourceType::Key, vec![]);

        assert!(manager.release_resource(handle));
        assert!(manager.get_resource(handle).is_none());
        assert!(!manager.release_resource(handle));
    }

    #[test]
    fn test_clear_all() {
        let manager = TpmResourceManager::new();
        manager.create_resource(TpmResourceType::Key, vec![]);
        manager.create_resource(TpmResourceType::NvIndex, vec![]);

        assert_eq!(manager.resource_count(), 2);
        manager.clear_all();
        assert_eq!(manager.resource_count(), 0);
    }

    #[test]
    fn test_handle_range_validation() {
        assert!(TpmResourceType::validate_handle_for_type(
            0x02000001,
            TpmResourceType::HmacSession
        ));
        assert!(!TpmResourceType::validate_handle_for_type(
            0x02000001,
            TpmResourceType::Key
        ));

        assert!(TpmResourceType::validate_handle_for_type(
            0x80000001,
            TpmResourceType::Key
        ));
        assert!(!TpmResourceType::validate_handle_for_type(
            0x80000001,
            TpmResourceType::HmacSession
        ));
    }

    #[test]
    fn test_resource_type_from_handle() {
        assert_eq!(
            TpmResourceType::from_handle(0x02000001),
            Some(TpmResourceType::HmacSession)
        );
        assert_eq!(
            TpmResourceType::from_handle(0x03000001),
            Some(TpmResourceType::PolicySession)
        );
        assert_eq!(
            TpmResourceType::from_handle(0x80000001),
            Some(TpmResourceType::Key)
        );
        assert_eq!(
            TpmResourceType::from_handle(0x01000001),
            Some(TpmResourceType::NvIndex)
        );
        assert_eq!(TpmResourceType::from_handle(0x00000000), None);
    }

    #[test]
    fn test_get_resource_with_type() {
        let manager = TpmResourceManager::new();
        let handle = manager.create_resource(TpmResourceType::HmacSession, vec![]);

        assert!(manager
            .get_resource_with_type(handle, TpmResourceType::HmacSession)
            .is_some());

        assert!(manager
            .get_resource_with_type(handle, TpmResourceType::PolicySession)
            .is_none());
    }

    #[test]
    fn test_release_resources_by_type() {
        let manager = TpmResourceManager::new();
        manager.create_resource(TpmResourceType::HmacSession, vec![]);
        manager.create_resource(TpmResourceType::HmacSession, vec![]);
        manager.create_resource(TpmResourceType::PolicySession, vec![]);
        manager.create_resource(TpmResourceType::Key, vec![]);

        assert_eq!(manager.resource_count(), 4);

        let released = manager.release_resources_by_type(TpmResourceType::HmacSession);
        assert_eq!(released, 2);
        assert_eq!(manager.resource_count(), 2);

        assert_eq!(
            manager.resource_count_by_type(TpmResourceType::HmacSession),
            0
        );
        assert_eq!(
            manager.resource_count_by_type(TpmResourceType::PolicySession),
            1
        );
        assert_eq!(manager.resource_count_by_type(TpmResourceType::Key), 1);
    }

    #[test]
    fn test_release_all_sessions() {
        let manager = TpmResourceManager::new();
        manager.create_resource(TpmResourceType::HmacSession, vec![]);
        manager.create_resource(TpmResourceType::PolicySession, vec![]);
        manager.create_resource(TpmResourceType::Key, vec![]);

        let released = manager.release_all_sessions();
        assert_eq!(released, 2);
        assert_eq!(manager.resource_count(), 1);
        assert_eq!(manager.resource_count_by_type(TpmResourceType::Key), 1);
    }

    #[test]
    fn test_list_handles_by_type() {
        let manager = TpmResourceManager::new();
        let handle1 = manager.create_resource(TpmResourceType::HmacSession, vec![]);
        let handle2 = manager.create_resource(TpmResourceType::HmacSession, vec![]);
        manager.create_resource(TpmResourceType::Key, vec![]);

        let handles = manager.list_handles_by_type(TpmResourceType::HmacSession);
        assert_eq!(handles.len(), 2);
        assert!(handles.contains(&handle1));
        assert!(handles.contains(&handle2));
    }

    #[test]
    fn test_handle_virtualizer_allocate() {
        let virt = HandleVirtualizer::new();
        let real_handle = 0x80000001;
        let virtual_handle = virt.allocate_virtual(real_handle, TpmResourceType::Key);

        assert!(virtual_handle >= FIRST_VIRTUAL_HANDLE);
        assert_eq!(virt.mapping_count(), 1);
    }

    #[test]
    fn test_handle_virtualizer_mapping() {
        let virt = HandleVirtualizer::new();
        let real_handle = 0x80000001;
        let virtual_handle = virt.allocate_virtual(real_handle, TpmResourceType::Key);

        assert_eq!(virt.map_to_real(virtual_handle), Some(real_handle));
        assert_eq!(virt.map_to_virtual(real_handle), Some(virtual_handle));
    }

    #[test]
    fn test_handle_virtualizer_isolation() {
        let virt1 = HandleVirtualizer::new();
        let virt2 = HandleVirtualizer::new();
        let real_handle = 0x80000001;

        let vh1 = virt1.allocate_virtual(real_handle, TpmResourceType::Key);
        let vh2 = virt2.allocate_virtual(real_handle, TpmResourceType::Key);

        assert_ne!(vh1, vh2);

        assert_eq!(virt1.map_to_real(vh1), Some(real_handle));
        assert_eq!(virt2.map_to_real(vh2), Some(real_handle));

        assert_eq!(virt1.map_to_real(vh2), None);
        assert_eq!(virt2.map_to_real(vh1), None);
    }

    #[test]
    fn test_handle_virtualizer_remove() {
        let virt = HandleVirtualizer::new();
        let real_handle = 0x80000001;
        let virtual_handle = virt.allocate_virtual(real_handle, TpmResourceType::Key);

        assert!(virt.remove_by_virtual(virtual_handle));
        assert_eq!(virt.map_to_real(virtual_handle), None);
        assert_eq!(virt.map_to_virtual(real_handle), None);
        assert_eq!(virt.mapping_count(), 0);
    }

    #[test]
    fn test_handle_virtualizer_clear() {
        let virt = HandleVirtualizer::new();
        virt.allocate_virtual(0x80000001, TpmResourceType::Key);
        virt.allocate_virtual(0x80000002, TpmResourceType::Key);

        assert_eq!(virt.mapping_count(), 2);
        virt.clear_all();
        assert_eq!(virt.mapping_count(), 0);
    }
}
