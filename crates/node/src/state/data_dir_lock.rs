//! Process-exclusive datadir lock, acquired before schema/epoch inspection.
//!
//! Capability-scoped open rejects symlinks and nonregular files (Core's `LockDirectory`
//! in `init.cpp`). Every writable store retains a `StoreGuard` clone and drops it after
//! its engine/file handles, so detached consumers cannot outlive lock ownership.
//! `DATA_DIR_LOCK_FILE` belongs to storage's checkpoint classifier, which exempts it
//! from fresh-directory checks.

use bitcoin_rs_storage::checkpoint::fs::DATA_DIR_LOCK_FILE;
use cap_fs_ext::FollowSymlinks;
use cap_fs_ext::OpenOptionsFollowExt as _;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use thiserror::Error;

/// Failure to acquire the data-directory lock.
#[derive(Debug, Error)]
pub enum DataDirLockError {
    /// Another live node (process or open) holds the directory.
    #[error("Cannot obtain a lock on directory {path}. bitcoin-rs is probably already running.")]
    InUse {
        /// The contended data directory.
        path: PathBuf,
    },
    /// The directory or lock file could not be opened.
    #[error("Cannot write to directory '{path}'; check permissions.")]
    Io {
        /// The data directory that could not be locked.
        path: PathBuf,
        /// The open or lock failure.
        source: io::Error,
    },
    /// `.lock` exists but is not a regular file.
    #[error("{path}/{DATA_DIR_LOCK_FILE} is not a regular file")]
    NotRegularFile {
        /// The data directory holding the non-regular lock entry.
        path: PathBuf,
    },
}

/// The held data-directory lock; dropping it releases the directory.
#[derive(Debug)]
pub(crate) struct DataDirLock {
    _file: std::fs::File,
}

impl DataDirLock {
    /// Acquires the process-exclusive lock on `data_dir`, creating the lock
    /// file when absent. The file is never deleted: a stale `.lock` is just a
    /// file, and the open-file lock — not its existence — is the ownership
    /// proof.
    pub(crate) fn acquire(data_dir: &Path) -> Result<Self, DataDirLockError> {
        let io_error = |source| DataDirLockError::Io {
            path: data_dir.to_path_buf(),
            source,
        };
        let dir = cap_std::fs::Dir::open_ambient_dir(data_dir, cap_std::ambient_authority())
            .map_err(io_error)?;
        let mut options = cap_std::fs::OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create(true)
            .follow(FollowSymlinks::No);
        let locked = dir
            .open_with(DATA_DIR_LOCK_FILE, &options)
            .map_err(io_error)?;
        // Directory-entry type is only a precheck; validate the opened inode
        // so a substituted FIFO can never be locked or held.
        let metadata = locked.metadata().map_err(io_error)?;
        if !metadata.is_file() {
            return Err(DataDirLockError::NotRegularFile {
                path: data_dir.to_path_buf(),
            });
        }
        let file = locked.into_std();
        match file.try_lock() {
            Ok(()) => Ok(Self { _file: file }),
            Err(std::fs::TryLockError::WouldBlock) => Err(DataDirLockError::InUse {
                path: data_dir.to_path_buf(),
            }),
            Err(std::fs::TryLockError::Error(source)) => Err(io_error(source)),
        }
    }
}
