use crate::net::socket::SendRecvFlags;
use crate::util::{
    read_val_from_user, write_bytes_to_user, write_socket_addr_to_user, write_val_to_user,
};
use crate::{fs::file_table::FileDescripter, prelude::*};
use crate::{get_socket_without_holding_filetable_lock, log_syscall_entry};

use super::SyscallReturn;
use super::SYS_RECVFROM;

pub fn sys_recvfrom(
    sockfd: FileDescripter,
    buf: Vaddr,
    len: usize,
    flags: i32,
    src_addr: Vaddr,
    addrlen: Vaddr,
) -> Result<SyscallReturn> {
    log_syscall_entry!(SYS_RECVFROM);
    let flags = SendRecvFlags::from_bits_truncate(flags);
    debug!("sockfd = {sockfd}, buf = 0x{buf:x}, len = {len}, flags = {flags:?}, src_addr = 0x{src_addr:x}, addrlen = 0x{addrlen:x}");
    let current = current!();
    get_socket_without_holding_filetable_lock!(socket, current, sockfd);
    let mut buffer = vec![0u8; len];
    let (recv_size, socket_addr) = socket.recvfrom(&mut buffer, flags)?;
    if buf != 0 {
        write_bytes_to_user(buf, &buffer[..recv_size])?;
    }
    if src_addr != 0 {
        debug_assert!(addrlen != 0);
        let max_len: u32 = read_val_from_user(addrlen)?;
        let write_size = write_socket_addr_to_user(&socket_addr, src_addr, max_len as usize)?;
        write_val_to_user(addrlen, &(write_size as u32))?;
    }
    Ok(SyscallReturn::Return(recv_size as _))
}