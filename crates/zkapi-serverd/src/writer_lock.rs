//! One live signing/issuance processor per file-backed SQLite database.
//!
//! This is separate from SQLite's short transaction locks: provider I/O and
//! signing must remain serialized across the entire processor lifetime. The
//! challenger can keep reading the database without taking this lock.

use std::fs::{File, OpenOptions};
use std::path::Path;

use crate::error::ServerError;

pub(crate) struct ServerWriterLock {
    // Dropping releases the advisory lock. Never unlink the sidecar: another
    // process could otherwise lock a different inode at the same path.
    file: File,
}

impl Drop for ServerWriterLock {
    fn drop(&mut self) {
        // Unlock explicitly instead of relying on the close alone. A child
        // process spawned concurrently holds a duplicate of this descriptor
        // until its exec closes it, and the lock belongs to the shared open
        // file description: a close would leave it held until then.
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

impl ServerWriterLock {
    pub(crate) fn acquire(database_path: &Path) -> Result<Self, ServerError> {
        let path = database_path.canonicalize().map_err(|error| {
            ServerError::Database(format!(
                "cannot resolve server database for writer lock: {error}"
            ))
        })?;
        let metadata = path.metadata().map_err(|error| {
            ServerError::Database(format!(
                "cannot inspect server database for writer lock: {error}"
            ))
        })?;
        if !metadata.is_file() {
            return Err(ServerError::Database(
                "server database writer lock requires a regular file".into(),
            ));
        }
        // Canonical paths collapse symlinks but not hard links. Reject the
        // latter instead of letting aliases obtain independent sidecar locks.
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.nlink() != 1 {
                return Err(ServerError::Database(
                    "server database must not have hard-link aliases".into(),
                ));
            }
        }
        let mut filename = path
            .file_name()
            .ok_or_else(|| ServerError::Database("server database has no filename".into()))?
            .to_os_string();
        filename.push(".server-writer.lock");
        let lock_path = path.with_file_name(filename);
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(lock_path).map_err(|error| {
            ServerError::Database(format!("cannot open server database writer lock: {error}"))
        })?;
        fs2::FileExt::try_lock_exclusive(&file).map_err(|error| {
            ServerError::Database(format!(
                "cannot acquire exclusive server database writer lock; another server may be running: {error}"
            ))
        })?;
        Ok(Self { file })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nullifier_store::NullifierStore;

    #[test]
    fn lock_excludes_other_processors_but_allows_challenger_reads() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("server.db");
        let store = NullifierStore::new(&path).unwrap();
        let lock = store.acquire_writer_lock().unwrap().unwrap();
        let other = NullifierStore::new(&path).unwrap();
        assert!(other.acquire_writer_lock().is_err());
        assert!(other.due_openrouter_leases(0).is_empty());
        drop(lock);
        assert!(other.acquire_writer_lock().unwrap().is_some());
        assert!(path.with_file_name("server.db.server-writer.lock").exists());
    }

    #[test]
    fn memory_stores_do_not_acquire_a_filesystem_lock() {
        assert!(NullifierStore::in_memory()
            .unwrap()
            .acquire_writer_lock()
            .unwrap()
            .is_none());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_aliases_share_lock_and_hard_links_are_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("server.db");
        let store = NullifierStore::new(&path).unwrap();
        let lock = store.acquire_writer_lock().unwrap();
        let alias = directory.path().join("alias.db");
        std::os::unix::fs::symlink(&path, &alias).unwrap();
        assert!(ServerWriterLock::acquire(&alias).is_err());
        drop(lock);
        assert!(ServerWriterLock::acquire(&alias).is_ok());
        let hard_link = directory.path().join("hard-link.db");
        std::fs::hard_link(&path, &hard_link).unwrap();
        assert!(ServerWriterLock::acquire(&hard_link).is_err());
        assert!(ServerWriterLock::acquire(&path).is_err());
    }

    #[test]
    fn process_lock_probe() {
        let Some(path) = std::env::var_os("ZKAPI_TEST_WRITER_LOCK_PATH") else {
            return;
        };
        assert!(ServerWriterLock::acquire(Path::new(&path)).is_err());
    }

    #[test]
    fn writer_lock_excludes_a_second_process() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("server.db");
        let store = NullifierStore::new(&path).unwrap();
        let _lock = store.acquire_writer_lock().unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "writer_lock::tests::process_lock_probe"])
            .env("ZKAPI_TEST_WRITER_LOCK_PATH", &path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
