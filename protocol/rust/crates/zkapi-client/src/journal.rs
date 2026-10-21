//! Write-ahead request journal (spec section 5.2).
//!
//! The journal records the essential identifiers of an in-flight request so
//! that the wallet can recover to a consistent state after a crash. A journal
//! entry is written *before* calling the server and cleared only after the
//! resulting next state has been persisted atomically.
//!
//! A transmitted request may have been admitted even when an unsigned reply
//! says otherwise, and its rerandomization cannot be rebuilt. A journal that
//! is set aside without installing its response is therefore moved into an
//! append-only archive (`request_archive/<nullifier>/`), never deleted, so a
//! later finalized receipt can still be installed from it.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use zkapi_types::wire::{ApiRequestV2, RequestResponseV2};
use zkapi_types::Felt252;

use crate::error::ClientError;

/// A write-ahead journal entry for a pending API request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingRequestJournal {
    /// Whether a pending request exists (always `true` when written to disk).
    pub exists: bool,
    /// UUID of the client request.
    pub client_request_id: String,
    /// The nullifier consumed by this request.
    pub nullifier: Felt252,
    /// Hash of the request payload.
    pub payload_hash: Felt252,
    /// Client-side rerandomization used to build the request proof.
    pub user_rerandomization: Felt252,
    /// Wall-clock time when the journal was created (milliseconds since epoch).
    pub created_at_ms: u64,
    /// Complete prepared request for idempotent transport retry. This contains
    /// only public proof material and the already-authorized payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prepared_request: Option<ApiRequestV2>,
}

impl PendingRequestJournal {
    /// Atomically and durably write a journal entry to disk.
    ///
    /// The entry is written and synced under a temporary name, renamed into
    /// place, and the rename is synced too, all before this returns and so
    /// before the request can be transmitted: a crash, even a power loss,
    /// then leaves either no entry (nothing was sent) or the complete one.
    pub fn write(path: &Path, journal: &PendingRequestJournal) -> Result<(), ClientError> {
        let json = serde_json::to_string_pretty(journal)
            .map_err(|e| ClientError::Serialization(e.to_string()))?;

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        replace_file_durably(path, json.as_bytes())
    }

    /// Read the journal from disk, if it exists.
    ///
    /// Returns `None` when no journal file is present (normal steady state).
    pub fn read(path: &Path) -> Result<Option<PendingRequestJournal>, ClientError> {
        if !path.exists() {
            return Ok(None);
        }
        let data = fs::read_to_string(path)?;
        let journal: PendingRequestJournal =
            serde_json::from_str(&data).map_err(|e| ClientError::Serialization(e.to_string()))?;
        if journal.exists {
            Ok(Some(journal))
        } else {
            Ok(None)
        }
    }

    /// Delete the journal file after the next state has been persisted
    /// successfully. The removal is synced before this returns.
    pub fn clear(path: &Path) -> Result<(), ClientError> {
        remove_file_durably(path)
    }

    /// Move the journal at `path`, if any, into the append-only archive under
    /// `archive_dir`. The record is durable before the journal is removed, so
    /// a crash leaves both, never neither.
    pub fn archive(path: &Path, archive_dir: &Path, disposition: &str) -> Result<(), ClientError> {
        Self::archive_with_response(path, archive_dir, disposition, None)
    }

    /// Like `archive`, keeping `response` with the record: a late successor
    /// (§6.4 E4 step 6) is installed from it once the exit lock is released.
    pub fn archive_with_response(
        path: &Path,
        archive_dir: &Path,
        disposition: &str,
        response: Option<&RequestResponseV2>,
    ) -> Result<(), ClientError> {
        let Some(journal) = Self::read(path)? else {
            return Ok(());
        };
        archive_request_with_response(archive_dir, &journal, disposition, response)?;
        remove_file_durably(path)
    }
}

/// A request journal that left the pending slot without its response being
/// installed. Records are written once and never changed or removed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchivedRequest {
    pub version: u8,
    /// Why the journal was set aside, for example `discarded_stale_root`.
    pub disposition: String,
    /// Wall-clock time of archiving (milliseconds since epoch); informational.
    pub archived_at_ms: u64,
    pub journal: PendingRequestJournal,
    /// The signed response a `late_successor` or `invalid_successor` record
    /// was set aside with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response: Option<RequestResponseV2>,
}

fn archive_directory(archive_dir: &Path, nullifier: &Felt252) -> PathBuf {
    archive_dir.join(hex::encode(nullifier.0))
}

/// Append one archive record for `journal` and return its path. The record
/// is written and synced under a temporary name and only then linked into
/// place, so a record name never holds a partial record.
pub fn archive_request(
    archive_dir: &Path,
    journal: &PendingRequestJournal,
    disposition: &str,
) -> Result<PathBuf, ClientError> {
    archive_request_with_response(archive_dir, journal, disposition, None)
}

/// Like `archive_request`, keeping `response` with the record.
pub fn archive_request_with_response(
    archive_dir: &Path,
    journal: &PendingRequestJournal,
    disposition: &str,
    response: Option<&RequestResponseV2>,
) -> Result<PathBuf, ClientError> {
    crash::point()?;
    let directory = archive_directory(archive_dir, &journal.nullifier);
    for path in [archive_dir, directory.as_path()] {
        if !path.exists() {
            fs::create_dir_all(path)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
            }
            if let Some(parent) = path.parent() {
                sync_directory(parent)?;
            }
        }
    }
    let record = ArchivedRequest {
        version: 1,
        disposition: disposition.to_string(),
        archived_at_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|time| time.as_millis() as u64)
            .unwrap_or_default(),
        journal: journal.clone(),
        response: response.cloned(),
    };
    let json = serde_json::to_vec_pretty(&record)
        .map_err(|e| ClientError::Serialization(e.to_string()))?;
    // Hidden and without the record suffix: never read as a record.
    let temporary = directory.join(format!(".tmp-{}", uuid::Uuid::new_v4()));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let written = options.open(&temporary).and_then(|mut file| {
        file.write_all(&json)?;
        file.sync_all()
    });
    if let Err(error) = written {
        let _ = fs::remove_file(&temporary);
        return Err(error.into());
    }
    let published = (0u32..)
        .map(|sequence| directory.join(format!("{}-{sequence}.json", record.archived_at_ms)))
        .find_map(|path| match publish_record(&temporary, &path) {
            Ok(true) => Some(Ok(path)),
            Ok(false) => None,
            Err(error) => Some(Err(error)),
        })
        .expect("the archive sequence space is non-empty");
    let _ = fs::remove_file(&temporary);
    let path = published?;
    sync_directory(&directory)?;
    Ok(path)
}

/// Give the complete record at `temporary` the name `path` without replacing
/// an existing record: false when that name is taken.
fn publish_record(temporary: &Path, path: &Path) -> std::io::Result<bool> {
    match fs::hard_link(temporary, path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        // A file system without hard links. Writers hold the wallet lock, so
        // nothing can take the free name between the check and the rename.
        Err(_) if !path.exists() => fs::rename(temporary, path).map(|()| true),
        Err(error) => Err(error),
    }
}

/// Whether `name` is an archive record's name, `<ms>-<sequence>.json`.
/// Anything else in an archive directory (an interrupted write's temporary
/// file, or a file another program left there) is not a record.
fn is_record_name(name: &str) -> bool {
    name.strip_suffix(".json")
        .and_then(|stem| stem.split_once('-'))
        .is_some_and(|(time, sequence)| {
            [time, sequence]
                .iter()
                .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
        })
}

/// The archive of one nullifier: its readable records, oldest first, and the
/// record files that could not be read or do not belong to that nullifier.
#[derive(Debug, Default)]
pub struct ArchiveListing {
    pub records: Vec<ArchivedRequest>,
    pub unreadable: Vec<PathBuf>,
}

impl ArchiveListing {
    /// Whether anything was archived for the nullifier, readable or not.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty() && self.unreadable.is_empty()
    }
}

/// Read the archive of `nullifier`. Only files named like records are read;
/// a record that cannot be read is listed in `unreadable`, never dropped
/// silently and never mistaken for absence.
pub fn read_archive(
    archive_dir: &Path,
    nullifier: &Felt252,
) -> Result<ArchiveListing, ClientError> {
    let directory = archive_directory(archive_dir, nullifier);
    let entries = match fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ArchiveListing::default())
        }
        Err(error) => return Err(error.into()),
    };
    let mut listing = ArchiveListing::default();
    let mut records = Vec::new();
    for entry in entries {
        let path = entry?.path();
        if !path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(is_record_name)
        {
            continue;
        }
        match fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<ArchivedRequest>(&bytes).ok())
        {
            Some(record) if record.version == 1 && record.journal.nullifier == *nullifier => {
                records.push((path, record))
            }
            _ => listing.unreadable.push(path),
        }
    }
    records.sort_by(|(left_path, left), (right_path, right)| {
        left.archived_at_ms
            .cmp(&right.archived_at_ms)
            .then_with(|| left_path.cmp(right_path))
    });
    listing.unreadable.sort();
    listing.records = records.into_iter().map(|(_, record)| record).collect();
    Ok(listing)
}

/// The latest record of each request in `listing`, in order of each
/// request's first record. Records are append-only, so a request's latest
/// disposition is its newest record's.
pub fn latest_records(listing: &ArchiveListing) -> Vec<&ArchivedRequest> {
    let mut order: Vec<&str> = Vec::new();
    let mut latest: std::collections::HashMap<&str, &ArchivedRequest> =
        std::collections::HashMap::new();
    for record in &listing.records {
        let id = record.journal.client_request_id.as_str();
        if latest.insert(id, record).is_none() {
            order.push(id);
        }
    }
    order.into_iter().map(|id| latest[id]).collect()
}

/// Every archived request for `nullifier`, oldest first. An unreadable
/// record is an error: callers must not mistake it for absence.
pub fn archived_requests(
    archive_dir: &Path,
    nullifier: &Felt252,
) -> Result<Vec<ArchivedRequest>, ClientError> {
    let listing = read_archive(archive_dir, nullifier)?;
    if let Some(path) = listing.unreadable.first() {
        return Err(ClientError::Serialization(format!(
            "archived request {} is unreadable or does not belong to its nullifier",
            path.display()
        )));
    }
    Ok(listing.records)
}

fn sync_directory(path: &Path) -> Result<(), ClientError> {
    #[cfg(unix)]
    fs::File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    #[cfg(test)]
    durability::record("dir", path);
    Ok(())
}

/// Sync the directory holding `path`, so a rename into it or a removal from
/// it survives a crash.
pub(crate) fn sync_parent(path: &Path) -> Result<(), ClientError> {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => sync_directory(parent),
        _ => sync_directory(Path::new(".")),
    }
}

/// Replace `path` with `bytes` so that a crash at any point, including a
/// power loss, leaves either the old file or the complete new one: the bytes
/// are written and synced under a temporary name, renamed into place, and
/// the rename is synced. Without the syncs a new file's name could reach the
/// disk before its contents (an empty file), or not at all.
pub(crate) fn replace_file_durably(path: &Path, bytes: &[u8]) -> Result<(), ClientError> {
    crash::point()?;
    let tmp_path = path.with_extension("tmp");
    write_private_file(&tmp_path, bytes)?;
    fs::rename(&tmp_path, path)?;
    sync_parent(path)
}

/// Remove `path`, if present, and sync the removal before returning.
pub(crate) fn remove_file_durably(path: &Path) -> Result<(), ClientError> {
    if path.exists() {
        crash::point()?;
        fs::remove_file(path)?;
        sync_parent(path)?;
    }
    Ok(())
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), ClientError> {
    let mut options = fs::OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(bytes)?;
    file.sync_all()?;
    #[cfg(test)]
    durability::record("file", path);
    Ok(())
}

/// Crash injection for the write-order tests (§11 WP-E "crash tests at each
/// step of the §6.2 write orders"). Every durable step (a replace, an
/// archive record, a removal) passes `point()` first. In tests,
/// `crash::after(n)` lets `n` steps complete and fails the next one before
/// it touches the disk, as a process killed there would leave it.
pub(crate) mod crash {
    #[cfg(test)]
    use std::cell::Cell;

    #[cfg(test)]
    thread_local! {
        static REMAINING: Cell<Option<usize>> = const { Cell::new(None) };
    }

    #[inline]
    pub(crate) fn point() -> std::io::Result<()> {
        #[cfg(test)]
        {
            let remaining = REMAINING.with(Cell::get);
            match remaining {
                Some(0) => {
                    return Err(std::io::Error::other("injected crash"));
                }
                Some(left) => REMAINING.with(|cell| cell.set(Some(left - 1))),
                None => {}
            }
        }
        Ok(())
    }

    /// Let `steps` durable steps complete, then fail every later one.
    #[cfg(test)]
    pub(crate) fn after(steps: usize) {
        REMAINING.with(|cell| cell.set(Some(steps)));
    }

    #[cfg(test)]
    pub(crate) fn disarm() {
        REMAINING.with(|cell| cell.set(None));
    }
}

/// The syncs this thread made, in order, so tests can check that a write is
/// durable before it returns.
#[cfg(test)]
pub(crate) mod durability {
    use std::cell::RefCell;
    use std::path::{Path, PathBuf};

    thread_local! {
        static SYNCED: RefCell<Vec<(&'static str, PathBuf)>> = const { RefCell::new(Vec::new()) };
    }

    pub(crate) fn record(kind: &'static str, path: &Path) {
        SYNCED.with(|synced| synced.borrow_mut().push((kind, path.to_path_buf())));
    }

    /// The syncs since the last call: `("file", path)` for a file's
    /// contents, `("dir", path)` for a directory's entries.
    pub(crate) fn take() -> Vec<(&'static str, PathBuf)> {
        SYNCED.with(|synced| std::mem::take(&mut *synced.borrow_mut()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("zkapi_journal_{}", name));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_write_and_read() {
        let dir = test_dir("write_and_read");
        let path = dir.join("journal.json");
        let journal = PendingRequestJournal {
            exists: true,
            client_request_id: "test-uuid-1234".to_string(),
            nullifier: Felt252::from_u64(999),
            payload_hash: Felt252::from_u64(0xabcd),
            user_rerandomization: Felt252::from_u64(7),
            created_at_ms: 1700000000000,
            prepared_request: None,
        };
        PendingRequestJournal::write(&path, &journal).unwrap();
        let loaded = PendingRequestJournal::read(&path).unwrap().unwrap();
        assert_eq!(loaded.client_request_id, "test-uuid-1234");
        assert_eq!(loaded.nullifier, Felt252::from_u64(999));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    /// A journal is written before its request is transmitted. Its contents
    /// and its new name are synced before `write` returns, and its removal
    /// before `clear` returns: a power loss could otherwise leave a sent
    /// request with no journal, or an empty journal file.
    #[test]
    fn journal_writes_and_removals_are_durable_before_they_return() {
        let dir = test_dir("durable");
        let path = dir.join("pending_journal.json");
        let journal = PendingRequestJournal {
            exists: true,
            client_request_id: "durable".to_string(),
            nullifier: Felt252::from_u64(5),
            payload_hash: Felt252::ONE,
            user_rerandomization: Felt252::from_u64(7),
            created_at_ms: 1,
            prepared_request: None,
        };
        durability::take();
        PendingRequestJournal::write(&path, &journal).unwrap();
        assert_eq!(
            durability::take(),
            [
                ("file", dir.join("pending_journal.tmp")),
                ("dir", dir.clone())
            ]
        );
        assert!(!dir.join("pending_journal.tmp").exists());
        PendingRequestJournal::clear(&path).unwrap();
        assert_eq!(durability::take(), [("dir", dir.clone())]);
        assert!(!path.exists());
        // Clearing no journal changes nothing.
        PendingRequestJournal::clear(&path).unwrap();
        assert!(durability::take().is_empty());
    }

    #[test]
    fn test_read_missing_returns_none() {
        let dir = test_dir("read_missing");
        let path = dir.join("nonexistent.json");
        assert!(PendingRequestJournal::read(&path).unwrap().is_none());
    }

    #[test]
    fn archive_keeps_every_set_aside_journal_append_only() {
        let dir = test_dir("archive");
        let path = dir.join("pending_journal.json");
        let archive = dir.join("request_archive");
        let journal = |id: &str, nullifier: u64| PendingRequestJournal {
            exists: true,
            client_request_id: id.to_string(),
            nullifier: Felt252::from_u64(nullifier),
            payload_hash: Felt252::ONE,
            user_rerandomization: Felt252::from_u64(7),
            created_at_ms: 1,
            prepared_request: None,
        };
        PendingRequestJournal::archive(&path, &archive, "none").unwrap();
        assert!(!archive.exists(), "archiving no journal must write nothing");
        for (id, nullifier) in [("a", 5), ("b", 5), ("c", 6)] {
            PendingRequestJournal::write(&path, &journal(id, nullifier)).unwrap();
            PendingRequestJournal::archive(&path, &archive, "discarded_stale_root").unwrap();
            assert!(!path.exists());
        }
        let five = archived_requests(&archive, &Felt252::from_u64(5)).unwrap();
        assert_eq!(
            five.iter()
                .map(|r| r.journal.client_request_id.as_str())
                .collect::<Vec<_>>(),
            ["a", "b"]
        );
        assert!(five.iter().all(|r| r.disposition == "discarded_stale_root"
            && r.journal.user_rerandomization == Felt252::from_u64(7)));
        assert_eq!(
            archived_requests(&archive, &Felt252::from_u64(6))
                .unwrap()
                .len(),
            1
        );
        assert!(archived_requests(&archive, &Felt252::from_u64(9))
            .unwrap()
            .is_empty());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let directory = archive.join(hex::encode(Felt252::from_u64(5).0));
            assert_eq!(
                fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
                0o700
            );
            for entry in fs::read_dir(&directory).unwrap() {
                assert_eq!(
                    entry.unwrap().metadata().unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }
        // An unreadable record is never mistaken for absence.
        fs::write(
            archive
                .join(hex::encode(Felt252::from_u64(6).0))
                .join("1-0.json"),
            b"{",
        )
        .unwrap();
        assert!(archived_requests(&archive, &Felt252::from_u64(6)).is_err());
    }

    #[test]
    fn records_are_published_whole_and_other_files_are_not_records() {
        let dir = test_dir("archive_files");
        let archive = dir.join("request_archive");
        let nullifier = Felt252::from_u64(8);
        let journal = PendingRequestJournal {
            exists: true,
            client_request_id: "kept".to_string(),
            nullifier,
            payload_hash: Felt252::ONE,
            user_rerandomization: Felt252::from_u64(7),
            created_at_ms: 1,
            prepared_request: None,
        };
        let first = archive_request(&archive, &journal, "discarded_stale_root").unwrap();
        let directory = first.parent().unwrap().to_path_buf();
        // Only the published record remains: no temporary file is left behind.
        let names = || {
            let mut names = fs::read_dir(&directory)
                .unwrap()
                .map(|entry| entry.unwrap().file_name().into_string().unwrap())
                .collect::<Vec<_>>();
            names.sort();
            names
        };
        assert_eq!(names().len(), 1);
        assert!(is_record_name(&names()[0]), "{:?}", names());
        // A finder or editor file, or an interrupted write's temporary file,
        // beside the records is not a record and hides none of them.
        fs::write(directory.join(".DS_Store"), b"\0\0\0\x01Bud1").unwrap();
        fs::write(directory.join(".tmp-interrupted"), b"{\"version\":1").unwrap();
        fs::write(directory.join("notes.txt"), b"backup").unwrap();
        let listing = read_archive(&archive, &nullifier).unwrap();
        assert_eq!(listing.records.len(), 1);
        assert!(listing.unreadable.is_empty());
        assert_eq!(archived_requests(&archive, &nullifier).unwrap().len(), 1);
        // A damaged record is listed as unreadable next to the readable one.
        let torn = directory.join("2-0.json");
        fs::write(&torn, b"").unwrap();
        let listing = read_archive(&archive, &nullifier).unwrap();
        assert_eq!(listing.records.len(), 1);
        assert_eq!(listing.unreadable, vec![torn]);
        assert!(!listing.is_empty());
        assert!(archived_requests(&archive, &nullifier).is_err());
        // A second record is added beside the first, and publishing never
        // replaces a record that already has the name.
        let second = archive_request(&archive, &journal, "superseded").unwrap();
        assert_ne!(first, second);
        assert_eq!(read_archive(&archive, &nullifier).unwrap().records.len(), 2);
        let before = fs::read(&first).unwrap();
        let temporary = directory.join(".tmp-other");
        fs::write(&temporary, b"other").unwrap();
        assert!(!publish_record(&temporary, &first).unwrap());
        assert_eq!(fs::read(&first).unwrap(), before);
        assert!(is_record_name("1700000000000-12.json"));
        for name in [
            "1-0.json.tmp",
            "-0.json",
            "1-.json",
            "a-0.json",
            "1_0.json",
            ".tmp-x",
            "1-0",
        ] {
            assert!(!is_record_name(name), "{name}");
        }
    }

    #[test]
    fn test_clear() {
        let dir = test_dir("clear");
        let path = dir.join("journal.json");
        let journal = PendingRequestJournal {
            exists: true,
            client_request_id: "x".to_string(),
            nullifier: Felt252::ZERO,
            payload_hash: Felt252::ZERO,
            user_rerandomization: Felt252::ZERO,
            created_at_ms: 0,
            prepared_request: None,
        };
        PendingRequestJournal::write(&path, &journal).unwrap();
        assert!(path.exists());
        PendingRequestJournal::clear(&path).unwrap();
        assert!(!path.exists());
        assert!(PendingRequestJournal::read(&path).unwrap().is_none());
    }
}
