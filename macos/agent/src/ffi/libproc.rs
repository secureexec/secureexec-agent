use std::ffi::CStr;
use std::mem;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const PROC_PIDTASKALLINFO: libc::c_int = 2;
const MAXPATHLEN: u32 = 1024;

// ---------------------------------------------------------------------------
// Raw C structs from <sys/proc_info.h>
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcBsdInfo {
    pub pbi_flags: u32,
    pub pbi_status: u32,
    pub pbi_xstatus: u32,
    pub pbi_pid: u32,
    pub pbi_ppid: u32,
    pub pbi_uid: libc::uid_t,
    pub pbi_gid: libc::gid_t,
    pub pbi_ruid: libc::uid_t,
    pub pbi_rgid: libc::gid_t,
    pub pbi_svuid: libc::uid_t,
    pub pbi_svgid: libc::gid_t,
    pub pbi_rfu_1: u32,
    pub pbi_comm: [libc::c_char; 16],
    pub pbi_name: [libc::c_char; 32],
    pub pbi_nfiles: u32,
    pub pbi_pgid: u32,
    pub pbi_pjobc: u32,
    pub e_tdev: u32,
    pub e_tpgid: u32,
    pub pbi_nice: i32,
    pub pbi_start_tvsec: u64,
    pub pbi_start_tvusec: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcTaskInfo {
    pub pti_virtual_size: u64,
    pub pti_resident_size: u64,
    pub pti_total_user: u64,
    pub pti_total_system: u64,
    pub pti_threads_user: u64,
    pub pti_threads_system: u64,
    pub pti_policy: i32,
    pub pti_faults: i32,
    pub pti_pageins: i32,
    pub pti_cow_faults: i32,
    pub pti_messages_sent: i32,
    pub pti_messages_received: i32,
    pub pti_syscalls_mach: i32,
    pub pti_syscalls_unix: i32,
    pub pti_csw: i32,
    pub pti_threadnum: i32,
    pub pti_numrunning: i32,
    pub pti_priority: i32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcTaskAllInfo {
    pub pbsd: ProcBsdInfo,
    pub ptinfo: ProcTaskInfo,
}

// ---------------------------------------------------------------------------
// extern declarations — libproc.dylib (loaded automatically on macOS)
// ---------------------------------------------------------------------------

extern "C" {
    fn proc_listallpids(buffer: *mut libc::pid_t, buffersize: libc::c_int) -> libc::c_int;
    fn proc_pidinfo(
        pid: libc::c_int,
        flavor: libc::c_int,
        arg: u64,
        buffer: *mut libc::c_void,
        buffersize: libc::c_int,
    ) -> libc::c_int;
    fn proc_pidpath(
        pid: libc::c_int,
        buffer: *mut libc::c_void,
        buffersize: u32,
    ) -> libc::c_int;
}

// ---------------------------------------------------------------------------
// Safe high-level wrappers
// ---------------------------------------------------------------------------

/// Information extracted from `proc_pidinfo(PROC_PIDTASKALLINFO)` for a single
/// process.
#[derive(Debug, Clone)]
pub struct ProcInfo {
    pub pid: u32,
    pub parent_pid: u32,
    pub uid: u32,
    pub name: String,
    pub start_time: SystemTime,
}

/// Return the list of all PIDs currently known to the kernel.
pub fn list_all_pids() -> Vec<u32> {
    unsafe {
        let count = proc_listallpids(std::ptr::null_mut(), 0);
        if count <= 0 {
            return Vec::new();
        }
        let capacity = (count as usize) + 64;
        let mut buf: Vec<libc::pid_t> = vec![0; capacity];
        let ret = proc_listallpids(
            buf.as_mut_ptr(),
            (capacity * mem::size_of::<libc::pid_t>()) as libc::c_int,
        );
        if ret <= 0 {
            return Vec::new();
        }
        buf.truncate(ret as usize);
        buf.into_iter().filter(|&p| p > 0).map(|p| p as u32).collect()
    }
}

/// Fetch per-process information for `pid`.  Returns `None` when the process
/// has already exited or when we lack permission.
pub fn pid_info(pid: u32) -> Option<ProcInfo> {
    unsafe {
        let mut info: ProcTaskAllInfo = mem::zeroed();
        let size = mem::size_of::<ProcTaskAllInfo>() as libc::c_int;
        let ret = proc_pidinfo(
            pid as libc::c_int,
            PROC_PIDTASKALLINFO,
            0,
            &mut info as *mut _ as *mut libc::c_void,
            size,
        );
        if ret <= 0 {
            return None;
        }

        let name = if info.pbsd.pbi_name[0] != 0 {
            CStr::from_ptr(info.pbsd.pbi_name.as_ptr())
                .to_string_lossy()
                .into_owned()
        } else {
            CStr::from_ptr(info.pbsd.pbi_comm.as_ptr())
                .to_string_lossy()
                .into_owned()
        };

        let start = UNIX_EPOCH
            + Duration::from_secs(info.pbsd.pbi_start_tvsec)
            + Duration::from_micros(info.pbsd.pbi_start_tvusec);

        Some(ProcInfo {
            pid: info.pbsd.pbi_pid,
            parent_pid: info.pbsd.pbi_ppid,
            uid: info.pbsd.pbi_uid,
            name,
            start_time: start,
        })
    }
}

/// Return the full command line (argv joined by spaces) for `pid` using
/// `sysctl(KERN_PROCARGS2)`.
pub fn pid_cmdline(pid: u32) -> Option<String> {
    let mut mib: [libc::c_int; 3] = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid as libc::c_int];
    let mut size: libc::size_t = 0;

    // First call to determine buffer size
    unsafe {
        if libc::sysctl(
            mib.as_mut_ptr(),
            3,
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            0,
        ) != 0
        {
            return None;
        }
    }
    if size == 0 {
        return None;
    }

    let mut buf: Vec<u8> = vec![0u8; size];
    unsafe {
        if libc::sysctl(
            mib.as_mut_ptr(),
            3,
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        ) != 0
        {
            return None;
        }
    }
    buf.truncate(size);

    // Layout: [argc: i32] [exec_path\0] [padding\0...] [argv[0]\0] [argv[1]\0] ...
    if buf.len() < mem::size_of::<i32>() {
        return None;
    }
    let argc = i32::from_ne_bytes(buf[..4].try_into().ok()?) as usize;
    let rest = &buf[4..];

    // Skip exec_path (null-terminated)
    let exec_end = rest.iter().position(|&b| b == 0)?;
    let mut pos = exec_end + 1;

    // Skip padding nulls
    while pos < rest.len() && rest[pos] == 0 {
        pos += 1;
    }

    // Collect argc arguments
    let mut args = Vec::with_capacity(argc);
    for _ in 0..argc {
        if pos >= rest.len() {
            break;
        }
        let end = rest[pos..]
            .iter()
            .position(|&b| b == 0)
            .map(|e| pos + e)
            .unwrap_or(rest.len());
        args.push(String::from_utf8_lossy(&rest[pos..end]).into_owned());
        pos = end + 1;
    }

    if args.is_empty() {
        None
    } else {
        Some(args.join(" "))
    }
}

/// Return the full executable path for `pid`, or `None`.
pub fn pid_path(pid: u32) -> Option<String> {
    unsafe {
        let mut buf = vec![0u8; MAXPATHLEN as usize];
        let ret = proc_pidpath(
            pid as libc::c_int,
            buf.as_mut_ptr() as *mut libc::c_void,
            MAXPATHLEN,
        );
        if ret <= 0 {
            return None;
        }
        let c = CStr::from_ptr(buf.as_ptr() as *const libc::c_char);
        Some(c.to_string_lossy().into_owned())
    }
}
