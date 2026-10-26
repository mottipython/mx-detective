//! The few operating-system calls the tool needs that the standard library does not cover.

pub use imp::*;

#[cfg(not(windows))]
mod imp {
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    use std::net::IpAddr;

    /// Nameservers from `/etc/resolv.conf`.
    pub fn system_dns_servers() -> Vec<IpAddr> {
        let Ok(file) = File::open("/etc/resolv.conf") else {
            return Vec::new();
        };
        BufReader::new(file)
            .lines()
            .map_while(Result::ok)
            .filter_map(|line| {
                let mut words = line.split_whitespace();
                if words.next()? != "nameserver" {
                    return None;
                }
                // An IPv6 zone index ("fe80::1%eth0") is not part of the address.
                words.next()?.split('%').next()?.parse().ok()
            })
            .collect()
    }

    pub fn console_owned_alone() -> bool {
        false
    }

    pub fn detach_console() {}

    /// Whether escape sequences for colors work on stderr.
    pub fn enable_ansi() -> bool {
        true
    }

    pub fn error_dialog(_message: &str) {}
}

#[cfg(windows)]
mod imp {
    use std::net::IpAddr;

    use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{GetNetworkParams, FIXED_INFO_W2KSP1, IP_ADDR_STRING};
    use windows_sys::Win32::System::Console::{
        FreeConsole, GetConsoleMode, GetConsoleProcessList, GetStdHandle, SetConsoleMode,
        ENABLE_VIRTUAL_TERMINAL_PROCESSING, STD_ERROR_HANDLE,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR};

    /// The IPv4 DNS servers Windows is configured with. Public resolvers are often blocked
    /// on managed networks, and internal names only resolve through these.
    pub fn system_dns_servers() -> Vec<IpAddr> {
        let mut len = 0u32;
        // SAFETY: a null buffer with a zero length asks the call to report the size it needs.
        if unsafe { GetNetworkParams(std::ptr::null_mut(), &mut len) } != ERROR_BUFFER_OVERFLOW || len == 0 {
            return Vec::new();
        }
        // u64 elements keep the buffer aligned for the structure written into it.
        let mut buf = vec![0u64; (len as usize).div_ceil(8)];
        let info = buf.as_mut_ptr().cast::<FIXED_INFO_W2KSP1>();
        // SAFETY: `buf` is at least `len` bytes, as the first call requested.
        if unsafe { GetNetworkParams(info, &mut len) } != NO_ERROR {
            return Vec::new();
        }

        let mut servers = Vec::new();
        // SAFETY: on success the list is a chain of valid entries inside `buf`, ending in null.
        let mut node: *const IP_ADDR_STRING = unsafe { &(*info).DnsServerList };
        while !node.is_null() {
            let entry = unsafe { &*node };
            let text: Vec<u8> = entry
                .IpAddress
                .String
                .iter()
                .take_while(|&&c| c != 0)
                .map(|&c| c as u8)
                .collect();
            if let Some(ip) = std::str::from_utf8(&text).ok().and_then(|t| t.parse().ok()) {
                if !servers.contains(&ip) {
                    servers.push(ip);
                }
            }
            node = entry.Next;
        }
        servers
    }

    /// True when no other process (such as cmd.exe) shares this console, as after a double-click.
    pub fn console_owned_alone() -> bool {
        let mut list = [0u32; 2];
        // SAFETY: `list` holds the two entries the call is told about.
        unsafe { GetConsoleProcessList(list.as_mut_ptr(), 2) == 1 }
    }

    pub fn detach_console() {
        // SAFETY: takes no arguments; detaches this process from its console.
        unsafe { FreeConsole() };
    }

    /// Turns on escape-sequence handling for stderr; false when it is not a console that supports it.
    pub fn enable_ansi() -> bool {
        // SAFETY: the handle comes from GetStdHandle and `mode` is a valid out pointer.
        unsafe {
            let handle = GetStdHandle(STD_ERROR_HANDLE);
            let mut mode = 0;
            GetConsoleMode(handle, &mut mode) != 0
                && SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0
        }
    }

    pub fn error_dialog(message: &str) {
        let wide = |s: &str| s.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
        // SAFETY: both buffers are NUL-terminated and outlive the call.
        unsafe {
            MessageBoxW(
                std::ptr::null_mut(),
                wide(message).as_ptr(),
                wide("MX Detective").as_ptr(),
                MB_ICONERROR,
            );
        }
    }
}
