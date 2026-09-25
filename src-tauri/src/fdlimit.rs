//! File descriptor budgeting.
//!
//! Apps launched from Finder get a soft RLIMIT_NOFILE of 256 on macOS. A scan
//! with dozens of hosts in flight, each holding several sockets plus ping's
//! pipes, blows straight through that - and when it does, `ping` fails to spawn
//! and connects fail instantly, so live hosts silently look dead. So: raise the
//! limit where we can, and never hold more descriptors than it allows.

use std::sync::OnceLock;
use tokio::sync::{Semaphore, SemaphorePermit};

/// Descriptors kept back for the webview, SQLite, stdio and friends.
const RESERVED: u64 = 64;
/// No point queueing more work than this even with a huge limit.
const MAX_BUDGET: u64 = 4096;

/// Cost of spawning a child process: stdin/stdout/stderr pipes (two ends
/// each, briefly) plus the spawn's status pipe.
pub const PROCESS: u32 = 4;
pub const SOCKET: u32 = 1;

static BUDGET: OnceLock<Semaphore> = OnceLock::new();

/// Raise the soft open-file limit as far as the OS allows. Returns the
/// resulting soft limit.
pub fn raise() -> u64 {
    #[cfg(unix)]
    unsafe {
        let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) != 0 {
            return 256;
        }
        // macOS rejects values above kern.maxfilesperproc (and "unlimited"),
        // so walk down until one sticks.
        for want in [lim.rlim_max, 65_536, 24_576, 10_240, 4_096, 1_024] {
            if want <= lim.rlim_cur || want > lim.rlim_max {
                continue;
            }
            let new = libc::rlimit { rlim_cur: want, rlim_max: lim.rlim_max };
            if libc::setrlimit(libc::RLIMIT_NOFILE, &new) == 0 {
                return want as u64;
            }
        }
        lim.rlim_cur as u64
    }
    #[cfg(not(unix))]
    {
        8_192
    }
}

fn budget() -> &'static Semaphore {
    BUDGET.get_or_init(|| {
        let limit = raise();
        let permits = limit.saturating_sub(RESERVED).clamp(32, MAX_BUDGET);
        Semaphore::new(permits as usize)
    })
}

/// Wait until `n` descriptors are available; they're returned on drop.
pub async fn acquire(n: u32) -> SemaphorePermit<'static> {
    budget().acquire_many(n).await.expect("fd budget semaphore is never closed")
}

/// Raise the limit and size the budget up front; returns the budget size.
pub fn init() -> usize {
    budget().available_permits()
}
