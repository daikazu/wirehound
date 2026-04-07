use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter};

pub struct ResolverState {
    pub enabled: AtomicBool,
    thread_started: AtomicBool,
    cache: Mutex<HashMap<String, Option<String>>>,
    pending: Mutex<Vec<String>>,
}

impl ResolverState {
    pub fn new() -> Self {
        Self {
            thread_started: AtomicBool::new(false),
            enabled: AtomicBool::new(false),
            cache: Mutex::new(HashMap::new()),
            pending: Mutex::new(Vec::new()),
        }
    }

    /// Queue an IP for resolution if not already cached or pending.
    pub fn queue_ip(&self, ip: &str) {
        if !self.enabled.load(Ordering::Relaxed) || ip.is_empty() {
            return;
        }

        if let Ok(cache) = self.cache.lock() {
            if cache.contains_key(ip) {
                return;
            }
        }

        if let Ok(mut pending) = self.pending.lock() {
            if !pending.contains(&ip.to_string()) {
                pending.push(ip.to_string());
            }
        }
    }

    pub fn reset(&self) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.clear();
        }
        if let Ok(mut pending) = self.pending.lock() {
            pending.clear();
        }
    }
}

/// Start the resolver background thread. Drains the pending queue,
/// does reverse DNS lookups, caches results, and emits them to the frontend.
/// Only spawns once — subsequent calls are no-ops.
pub fn start_resolver_thread(app: AppHandle, state: Arc<ResolverState>) {
    if state.thread_started.swap(true, Ordering::Relaxed) {
        return; // Already started
    }
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_millis(500));

            if !state.enabled.load(Ordering::Relaxed) {
                continue;
            }

            // Drain pending IPs
            let ips: Vec<String> = if let Ok(mut pending) = state.pending.lock() {
                pending.drain(..).collect()
            } else {
                continue;
            };

            for ip_str in ips {
                // Check cache again (might have been resolved by now)
                if let Ok(cache) = state.cache.lock() {
                    if cache.contains_key(&ip_str) {
                        continue;
                    }
                }

                // Do the reverse DNS lookup
                let hostname = if let Ok(addr) = ip_str.parse::<IpAddr>() {
                    dns_lookup(&addr)
                } else {
                    None
                };

                // Cache result
                if let Ok(mut cache) = state.cache.lock() {
                    cache.insert(ip_str.clone(), hostname.clone());
                }

                // Emit to frontend if we got a hostname
                if let Some(ref name) = hostname {
                    let _ = app.emit(
                        "dns-resolved",
                        serde_json::json!({ "ip": ip_str, "hostname": name }),
                    );
                }
            }
        }
    });
}

fn dns_lookup(addr: &IpAddr) -> Option<String> {
    use std::net::SocketAddr;

    // Use getnameinfo via std — construct a socket addr and use to_string tricks
    // Actually, the simplest way is dns_lookup crate, but let's use libc directly
    // via std's internal resolution. We'll use a simple approach:
    let socket_addr = SocketAddr::new(*addr, 0);

    // std doesn't expose reverse DNS directly, so we use libc's getnameinfo
    #[cfg(unix)]
    {
        use std::ffi::CStr;
        use std::mem;

        unsafe {
            let (sa_ptr, sa_len) = match socket_addr {
                SocketAddr::V4(ref v4) => {
                    let mut sa: libc::sockaddr_in = mem::zeroed();
                    sa.sin_family = libc::AF_INET as libc::sa_family_t;
                    sa.sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
                    (
                        &sa as *const libc::sockaddr_in as *const libc::sockaddr,
                        mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    )
                }
                SocketAddr::V6(ref v6) => {
                    let mut sa: libc::sockaddr_in6 = mem::zeroed();
                    sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                    sa.sin6_addr.s6_addr = v6.ip().octets();
                    (
                        &sa as *const libc::sockaddr_in6 as *const libc::sockaddr,
                        mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                    )
                }
            };

            let mut host_buf = [0u8; 256];
            let ret = libc::getnameinfo(
                sa_ptr,
                sa_len,
                host_buf.as_mut_ptr() as *mut libc::c_char,
                host_buf.len() as libc::socklen_t,
                std::ptr::null_mut(),
                0,
                0, // no flags — do full reverse lookup
            );

            if ret == 0 {
                let hostname = CStr::from_ptr(host_buf.as_ptr() as *const libc::c_char)
                    .to_string_lossy()
                    .to_string();

                // If getnameinfo just returned the IP address back, treat as no result
                if hostname == addr.to_string() {
                    None
                } else {
                    Some(hostname)
                }
            } else {
                None
            }
        }
    }

    #[cfg(not(unix))]
    {
        let _ = socket_addr;
        None
    }
}
