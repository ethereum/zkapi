//! C1 (design §6.3): one process-wide lock per wallet.
//!
//! Request preparation, successor installation and every exit decision run
//! under the same mutex, so an exit decision never interleaves with a
//! request proof: either the request's bound and journal are durable before
//! the decision reads them, or the decision's exit lock is durable before
//! the request checks it. The lock is per state directory and shared by
//! every `AuthService` (and the exit-kit command) in the process; the
//! on-disk `.wallet.lock` additionally keeps a second process out.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

/// The process-wide lock of a wallet state directory.
pub struct WalletLock;

impl WalletLock {
    /// The mutex for `state_dir`; every caller naming the same directory
    /// gets the same mutex.
    pub fn for_state_dir(state_dir: &Path) -> Arc<Mutex<()>> {
        static LOCKS: OnceLock<Mutex<HashMap<PathBuf, Arc<Mutex<()>>>>> = OnceLock::new();
        let key = std::fs::canonicalize(state_dir).unwrap_or_else(|_| state_dir.to_path_buf());
        let mut locks = LOCKS
            .get_or_init(Default::default)
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        locks.entry(key).or_default().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_mutex_per_state_directory() {
        let directory = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let first = WalletLock::for_state_dir(directory.path());
        let again = WalletLock::for_state_dir(&directory.path().join("."));
        assert!(Arc::ptr_eq(&first, &again));
        assert!(!Arc::ptr_eq(
            &first,
            &WalletLock::for_state_dir(other.path())
        ));
    }
}
