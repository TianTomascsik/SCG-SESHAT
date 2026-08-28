//! DSCP tag utilities (F-10, F-13a).
//!
//! Provides helpers to:
//! 1. Parse DSCP tag names (EF, AF41, BE, CS0..CS7) to numeric values.
//! 2. Set DSCP on outgoing sockets via `IP_TOS`.
//! 3. Read DSCP from incoming packets via `IP_RECVTOS` + `recvmsg` ancillary.
//!
//! DSCP occupies bits 2–7 of the IP TOS byte (the 6 most-significant bits of
//! the DS field). The low 2 bits are ECN and ignored for DSCP purposes.
//!
//! Linux only delivers ancillary TOS data for **datagram** sockets, so DSCP
//! preservation is observable from userspace on the UDP path and not on the TCP
//! one. `enable_recvtos` + `recv_one_with_tos` back that observation for
//! datagram transports (see [`crate::transport::DataSource::recv_msg_with_tos`]
//! and `workload::streams`); a stream transport reports "unobserved" rather than
//! fabricating a verdict. Verifying the mark on the *inter-gateway* hop, rather
//! than on the harness leg, still needs a packet capture.
//!
//! `get_tos` reads back a socket's own outgoing TOS and has no caller yet.
#![allow(dead_code)]

use std::io;

/// Parse a DSCP tag name to a 6-bit value (0..63).
///
/// Supports: `EF`, `AF{1..4}{1..3}`, `CS{0..7}`, `BE` (alias for CS0),
/// and numeric literals.
pub fn parse_dscp_tag(tag: &str) -> Option<u8> {
    let tag = tag.trim().to_uppercase();
    match tag.as_str() {
        "EF" => Some(46),
        "BE" | "CS0" | "DF" => Some(0),
        "CS1" => Some(8),
        "CS2" => Some(16),
        "CS3" => Some(24),
        "CS4" => Some(32),
        "CS5" => Some(40),
        "CS6" => Some(48),
        "CS7" => Some(56),
        "AF11" => Some(10),
        "AF12" => Some(12),
        "AF13" => Some(14),
        "AF21" => Some(18),
        "AF22" => Some(20),
        "AF23" => Some(22),
        "AF31" => Some(26),
        "AF32" => Some(28),
        "AF33" => Some(30),
        "AF41" => Some(34),
        "AF42" => Some(36),
        "AF43" => Some(38),
        _ => tag.parse::<u8>().ok().filter(|&v| v < 64),
    }
}

/// Convert a 6-bit DSCP value to the full 8-bit TOS byte (shift left by 2).
pub fn dscp_to_tos(dscp: u8) -> u8 {
    dscp << 2
}

/// Extract the 6-bit DSCP value from a TOS byte.
pub fn tos_to_dscp(tos: u8) -> u8 {
    tos >> 2
}

/// Set `IP_TOS` on a socket file descriptor so outgoing packets carry the given
/// DSCP value.
pub fn set_dscp(fd: i32, dscp: u8) -> io::Result<()> {
    let tos = dscp_to_tos(dscp) as libc::c_int;
    // SAFETY: `fd` is the caller-supplied socket descriptor; the option pointer/len
    // pair points to a fully-initialised stack `libc::c_int` (`tos`) whose size is
    // passed as `socklen_t`, matching the `IP_TOS` option kernel expects. The
    // return value is checked below and converted to `io::Error::last_os_error()`.
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_TOS,
            &tos as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Enable `IP_RECVTOS` on a socket so `recvmsg` delivers the TOS byte as
/// ancillary data (for UDP). Returns an error on non-UDP or unsupported OS.
pub fn enable_recvtos(fd: i32) -> io::Result<()> {
    let one: libc::c_int = 1;
    // SAFETY: `fd` is the caller-supplied socket descriptor; the option pointer/len
    // pair points to a fully-initialised stack `libc::c_int` (`one`) whose size is
    // passed as `socklen_t`, matching the boolean flag the `IP_RECVTOS` option
    // expects. The return value is checked below and turned into an `io::Error`.
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_RECVTOS,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Read the TOS byte from a UDP socket using `getsockopt(IP_TOS)`.
///
/// NOTE: This reads the *outgoing* TOS set on the socket, which is useful for
/// verifying that the SCG correctly sets IP_TOS on the backend-facing socket.
/// For per-packet incoming TOS, use `recvmsg` + `IP_RECVTOS` ancillary data.
pub fn get_tos(fd: i32) -> io::Result<u8> {
    let mut tos: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `fd` is the caller-supplied socket descriptor; `tos` is an
    // initialised, writable stack `libc::c_int` and `len` is an initialised,
    // writable `socklen_t` holding its size, so the kernel writes at most
    // `len` bytes into `tos` for the `IP_TOS` option. The return value is
    // checked below before `tos` is read.
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_TOS,
            &mut tos as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(tos as u8)
    }
}

/// Receive one packet from `fd` via `recvmsg` and extract the IP TOS byte from
/// the `IP_RECVTOS` ancillary data. `IP_RECVTOS` must already be enabled on `fd`.
///
/// Returns `(bytes_read, Some(tos_byte))` when the kernel delivered a TOS
/// control message, and `(bytes_read, None)` when it did not — which happens on
/// a socket where `IP_RECVTOS` is not (or cannot be) enabled. The distinction
/// matters: a missing cmsg must never be reported as a TOS byte of zero, or a
/// caller comparing against an expected DSCP would record a fabricated mismatch.
pub fn recv_one_with_tos(fd: i32, buf: &mut [u8]) -> io::Result<(usize, Option<u8>)> {
    // cmsg buffer: big enough for one IP_TOS cmsg (1 byte payload).
    let mut cmsg_buf = [0u8; 64];

    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };

    // SAFETY: `libc::msghdr` is a plain C struct of integers and raw pointers for
    // which the all-zeroes bit pattern is a valid initialised value (null pointers,
    // zero lengths); every field used by `recvmsg` is overwritten with valid values
    // immediately below before the struct is passed to the kernel.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_buf.len() as libc::size_t;

    // SAFETY: `fd` is the caller-supplied socket descriptor and `msg` is a fully
    // populated `msghdr` whose `msg_iov`/`msg_control` point to the live, mutable
    // `iov`/`cmsg_buf` stack buffers for the duration of the call, with lengths
    // matching those buffers. The return value is checked below before any
    // ancillary data is read.
    let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }

    // Walk cmsg headers looking for IP_TOS. Absent means "not observed".
    let mut tos: Option<u8> = None;
    // SAFETY: `msg` was just populated by a successful `recvmsg`, so its control
    // buffer and `msg_controllen` describe valid kernel-written cmsg data. Each
    // `cmsg` returned by `CMSG_FIRSTHDR`/`CMSG_NXTHDR` is either null (loop exits)
    // or points to a live `cmsghdr` within that buffer, so dereferencing it and
    // reading the single TOS byte at `CMSG_DATA(cmsg)` (the IP_TOS payload, checked
    // via cmsg_level/cmsg_type) stays in bounds and references initialised memory.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::IPPROTO_IP && (*cmsg).cmsg_type == libc::IP_TOS {
                let data_ptr = libc::CMSG_DATA(cmsg);
                tos = Some(*data_ptr);
                break;
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }

    Ok((n as usize, tos))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_known_tags() {
        assert_eq!(parse_dscp_tag("EF"), Some(46));
        assert_eq!(parse_dscp_tag("BE"), Some(0));
        assert_eq!(parse_dscp_tag("CS5"), Some(40));
        assert_eq!(parse_dscp_tag("AF41"), Some(34));
        assert_eq!(parse_dscp_tag("af21"), Some(18));
        assert_eq!(parse_dscp_tag("46"), Some(46));
        assert_eq!(parse_dscp_tag("64"), None); // out of range
        assert_eq!(parse_dscp_tag("invalid"), None);
    }

    #[test]
    fn tos_dscp_round_trip() {
        for dscp in 0..64u8 {
            assert_eq!(tos_to_dscp(dscp_to_tos(dscp)), dscp);
        }
    }
}
