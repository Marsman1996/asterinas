// SPDX-License-Identifier: MPL-2.0

//! This module defines struct `ProcessVm`
//! to represent the layout of user space process virtual memory.
//!
//! The `ProcessVm` struct contains `Vmar`,
//! which stores all existing memory mappings.
//! The `Vm` also contains
//! the basic info of process level vm segments,
//! like init stack and heap.

mod heap;
mod init_stack;

use aster_rights::Full;
pub use heap::Heap;
use init_stack::ArgEnvBoundaries;

pub use self::{
    heap::USER_HEAP_SIZE_LIMIT,
    init_stack::{
        aux_vec::{AuxKey, AuxVec},
        InitStack, InitStackReader, INIT_STACK_SIZE, MAX_ARGV_NUMBER, MAX_ARG_LEN, MAX_ENVP_NUMBER,
        MAX_ENV_LEN,
    },
};
use crate::{prelude::*, vm::vmar::Vmar};

/*
 * The user's virtual memory space layout looks like below.
 * TODO: The layout of the userheap does not match the current implementation,
 * And currently the initial program break is a fixed value.
 *
 *  (high address)
 *  +---------------------+ <------+ The top of Vmar, which is the highest address usable
 *  |                     |          Randomly padded pages
 *  +---------------------+ <------+ The base of the initial user stack
 *  | User stack          |
 *  |                     |
 *  +---------||----------+ <------+ The user stack limit, can be extended lower
 *  |         \/          |
 *  | ...                 |
 *  |                     |
 *  | MMAP Spaces         |
 *  |                     |
 *  | ...                 |
 *  |         /\          |
 *  +---------||----------+ <------+ The current program break
 *  | User heap           |
 *  |                     |
 *  +---------------------+ <------+ The original program break
 *  |                     |          Randomly padded pages
 *  +---------------------+ <------+ The end of the program's last segment
 *  |                     |
 *  | Loaded segments     |
 *  | .text, .data, .bss  |
 *  | , etc.              |
 *  |                     |
 *  +---------------------+ <------+ The bottom of Vmar at 0x1_0000
 *  |                     |          64 KiB unusable space
 *  +---------------------+
 *  (low address)
 */

// The process user space virtual memory
pub struct ProcessVm {
    root_vmar: Vmar<Full>,
    init_stack: InitStack,
    heap: Heap,
    /// The pointer to arg and env in stack
    arg_start: RwLock<Vaddr>,
    arg_end: RwLock<Vaddr>,
    env_start: RwLock<Vaddr>,
    env_end: RwLock<Vaddr>,
}

impl Clone for ProcessVm {
    fn clone(&self) -> Self {
        Self {
            root_vmar: self.root_vmar.dup().unwrap(),
            init_stack: self.init_stack.clone(),
            heap: self.heap.clone(),
            arg_start: RwLock::new(*self.arg_start.read()),
            arg_end: RwLock::new(*self.arg_end.read()),
            env_start: RwLock::new(*self.env_start.read()),
            env_end: RwLock::new(*self.env_end.read()),
        }
    }
}

impl ProcessVm {
    /// Allocates a new `ProcessVm`
    pub fn alloc() -> Self {
        let root_vmar = Vmar::<Full>::new_root();
        let init_stack = InitStack::new();
        let heap = Heap::new();
        heap.alloc_and_map_vmo(&root_vmar).unwrap();
        Self {
            root_vmar,
            heap,
            init_stack,
            arg_start: RwLock::new(0),
            arg_end: RwLock::new(0),
            env_start: RwLock::new(0),
            env_end: RwLock::new(0),
        }
    }

    /// Forks a `ProcessVm` from `other`.
    ///
    /// The returned `ProcessVm` will have a forked `Vmar`.
    pub fn fork_from(other: &ProcessVm) -> Result<Self> {
        let root_vmar = Vmar::<Full>::fork_from(&other.root_vmar)?;
        Ok(Self {
            root_vmar,
            heap: other.heap.clone(),
            init_stack: other.init_stack.clone(),
            arg_start: RwLock::new(*other.arg_start.read()),
            arg_end: RwLock::new(*other.arg_end.read()),
            env_start: RwLock::new(*other.env_start.read()),
            env_end: RwLock::new(*other.env_end.read()),
        })
    }

    pub fn root_vmar(&self) -> &Vmar<Full> {
        &self.root_vmar
    }

    /// Returns a reader for reading contents from
    /// the `InitStack`.
    pub fn init_stack_reader(&self) -> InitStackReader {
        self.init_stack.reader(
            self.root_vmar().vm_space(),
            ArgEnvBoundaries::new(
                *self.arg_start.read(),
                *self.arg_end.read(),
                *self.env_start.read(),
                *self.env_end.read(),
            ),
        )
    }

    /// Returns the top address of the user stack.
    pub fn user_stack_top(&self) -> Vaddr {
        self.init_stack.user_stack_top()
    }

    pub(super) fn map_and_write_init_stack(
        &self,
        argv: Vec<CString>,
        envp: Vec<CString>,
        aux_vec: AuxVec,
    ) -> Result<()> {
        let arg_env_bound = self
            .init_stack
            .map_and_write(self.root_vmar(), argv, envp, aux_vec)?;
        *self.arg_start.write() = arg_env_bound.arg_start;
        *self.arg_end.write() = arg_env_bound.arg_end;
        *self.env_start.write() = arg_env_bound.env_start;
        *self.env_end.write() = arg_env_bound.env_end;

        Ok(())
    }

    pub(super) fn heap(&self) -> &Heap {
        &self.heap
    }

    /// Clears existing mappings and then maps stack and heap vmo.
    pub(super) fn clear_and_map(&self) {
        self.root_vmar.clear().unwrap();
        self.heap.alloc_and_map_vmo(&self.root_vmar).unwrap();
    }
}
