//! Atomic File Staging & Streaming Storage Engine
//!
//! Provides zero-copy, bounded-memory file streaming into staging `.part` files,
//! concurrent SHA-256 hash calculation, atomic destination renaming, and RAII orphan cleanup.

use futures_util::StreamExt;
use localsend_protocol::{resolve_collision, sanitize_filename, SanitizeError};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncWriteExt, BufWriter};

/// Default buffer capacity for BufWriter streaming (512 KiB).
pub const STREAM_BUFFER_CAPACITY: usize = 512 * 1024;

/// Errors returned by the storage engine.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// Filesystem I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Filename sanitization error.
    #[error("Filename sanitization rejected: {0}")]
    Sanitize(#[from] SanitizeError),
    /// SHA-256 digest mismatch.
    #[error("SHA-256 hash mismatch: expected {expected}, calculated {calculated}")]
    HashMismatch {
        /// Expected SHA-256 hash from manifest.
        expected: String,
        /// Actual calculated hash over received bytes.
        calculated: String,
    },
    /// Stream payload exceeded manifest expected size.
    #[error("File size exceeded: expected {expected} bytes, received at least {received} bytes")]
    SizeExceeded {
        /// Expected size in bytes.
        expected: u64,
        /// Actual size received before abort.
        received: u64,
    },
    /// Stream payload ended prematurely before expected size.
    #[error("File truncated: expected {expected} bytes, received only {received} bytes")]
    SizeTruncated {
        /// Expected size in bytes.
        expected: u64,
        /// Actual received bytes.
        received: u64,
    },
    /// Network stream error.
    #[error("Stream error: {0}")]
    Stream(String),
}

/// RAII Guard ensuring staging `.part` files are deleted on abort, error, or client disconnect.
pub struct TempFileGuard {
    path: PathBuf,
    armed: bool,
}

impl TempFileGuard {
    /// Creates a new armed guard for the specified temporary path.
    pub fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    /// Disarms the guard when transfer succeeds, preventing file deletion upon drop.
    pub fn disarm(&mut self) {
        self.armed = false;
    }

    /// Access the underlying path.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if self.armed && self.path.exists() {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Generate standardized temporary staging path: `.localsend_<sessionId>_<fileId>.part`.
pub fn get_temp_file_path(dest_dir: &Path, session_id: &str, file_id: &str) -> PathBuf {
    let filename = format!(".localsend_{session_id}_{file_id}.part");
    dest_dir.join(filename)
}

/// Stream an incoming request body directly to disk with concurrent SHA-256 hashing.
///
/// Ensures bounded memory consumption using a 512 KiB `BufWriter` and computes running
/// SHA-256 hash over borrowed chunk slices. Enforces size boundaries and hash verification.
pub async fn stream_to_disk_and_hash(
    body: axum::body::Body,
    temp_path: &Path,
    expected_size: Option<u64>,
    expected_hash: Option<&str>,
) -> Result<String, StorageError> {
    // Open staging file with create_new(true) and POSIX 0o600 permissions
    let file = {
        let mut opts = tokio::fs::OpenOptions::new();
        opts.write(true).create_new(true);

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }

        opts.open(temp_path).await?
    };

    let mut guard = TempFileGuard::new(temp_path.to_path_buf());
    let mut writer = BufWriter::with_capacity(STREAM_BUFFER_CAPACITY, file);
    let mut hasher = Sha256::new();
    let mut total_bytes: u64 = 0;

    let mut stream = body.into_data_stream();

    while let Some(chunk_res) = stream.next().await {
        let chunk = chunk_res.map_err(|e| StorageError::Stream(e.to_string()))?;
        let bytes = chunk.as_ref();

        total_bytes += bytes.len() as u64;

        if let Some(exp_size) = expected_size {
            if total_bytes > exp_size {
                return Err(StorageError::SizeExceeded {
                    expected: exp_size,
                    received: total_bytes,
                });
            }
        }

        hasher.update(bytes);
        writer.write_all(bytes).await?;
    }

    if let Some(exp_size) = expected_size {
        if total_bytes != exp_size {
            return Err(StorageError::SizeTruncated {
                expected: exp_size,
                received: total_bytes,
            });
        }
    }

    writer.flush().await?;
    let inner_file = writer.into_inner();
    inner_file.sync_all().await?;

    let calculated_hash = hex::encode_upper(hasher.finalize());

    if let Some(expected) = expected_hash {
        let expected_clean = expected.trim().to_ascii_uppercase();
        if !calculated_hash.eq_ignore_ascii_case(&expected_clean) {
            return Err(StorageError::HashMismatch {
                expected: expected_clean,
                calculated: calculated_hash,
            });
        }
    }

    // Success: disarm the guard so the file remains on disk for atomic rename
    guard.disarm();

    Ok(calculated_hash)
}

/// Atomically commit staging file to final destination filename in `dest_dir`.
///
/// Sanitizes the target filename, prevents collision by incrementing names,
/// renames staging path to target path, and syncs parent directory metadata.
pub async fn commit_file_atomically(
    temp_path: &Path,
    dest_dir: &Path,
    final_filename: &str,
) -> Result<PathBuf, StorageError> {
    let sanitized = sanitize_filename(final_filename)?;
    let target_path = resolve_collision(dest_dir, &sanitized);

    tokio::fs::rename(temp_path, &target_path).await?;

    // Synchronize parent directory metadata on platforms supporting directory fsync
    #[cfg(unix)]
    {
        if let Ok(dir_file) = tokio::fs::File::open(dest_dir).await {
            let _ = dir_file.sync_all().await;
        }
    }

    Ok(target_path)
}

/// Scavenges abandoned `.localsend_*.part` staging files older than `max_age` in `dest_dir`.
pub async fn scavenge_orphaned_parts(
    dest_dir: &Path,
    max_age: Duration,
) -> Result<usize, std::io::Error> {
    let mut dir = match tokio::fs::read_dir(dest_dir).await {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    };

    let mut removed = 0;

    while let Ok(Some(entry)) = dir.next_entry().await {
        let path = entry.path();
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if name.starts_with(".localsend_") && name.ends_with(".part") {
                if let Ok(metadata) = entry.metadata().await {
                    if let Ok(modified) = metadata.modified() {
                        if let Ok(elapsed) = modified.elapsed() {
                            if elapsed > max_age {
                                if tokio::fs::remove_file(&path).await.is_ok() {
                                    removed += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_temp_file_guard_drops_armed() {
        let temp_dir = std::env::temp_dir().join(format!("guard_test_{}", uuid::Uuid::new_v4()));
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();

        let temp_file = temp_dir.join(".localsend_test.part");
        tokio::fs::write(&temp_file, b"sample data").await.unwrap();
        assert!(temp_file.exists());

        {
            let _guard = TempFileGuard::new(temp_file.clone());
            // Drops here while armed
        }

        assert!(!temp_file.exists(), "Armed guard should unlink file on drop");
        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_temp_file_guard_preserves_disarmed() {
        let temp_dir = std::env::temp_dir().join(format!("guard_test_2_{}", uuid::Uuid::new_v4()));
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();

        let temp_file = temp_dir.join(".localsend_test_disarmed.part");
        tokio::fs::write(&temp_file, b"sample data").await.unwrap();

        {
            let mut guard = TempFileGuard::new(temp_file.clone());
            guard.disarm();
        }

        assert!(temp_file.exists(), "Disarmed guard must not unlink file on drop");
        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_stream_to_disk_and_hash_success() {
        let temp_dir = std::env::temp_dir().join(format!("stream_test_{}", uuid::Uuid::new_v4()));
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();
        let temp_file = temp_dir.join(".localsend_s1_f1.part");

        let payload = b"Hello LocalSend Streaming World!";
        let mut hasher = Sha256::new();
        hasher.update(payload);
        let expected_hash = hex::encode_upper(hasher.finalize());

        let body = axum::body::Body::from(payload.to_vec());
        let calculated = stream_to_disk_and_hash(
            body,
            &temp_file,
            Some(payload.len() as u64),
            Some(&expected_hash),
        )
        .await
        .expect("Stream should succeed");

        assert_eq!(calculated, expected_hash);
        assert!(temp_file.exists());

        // Commit atomically
        let final_path = commit_file_atomically(&temp_file, &temp_dir, "hello.txt")
            .await
            .unwrap();

        assert!(!temp_file.exists());
        assert!(final_path.exists());
        let read_back = tokio::fs::read(&final_path).await.unwrap();
        assert_eq!(read_back, payload);

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_stream_hash_mismatch_cleans_up() {
        let temp_dir = std::env::temp_dir().join(format!("stream_err_{}", uuid::Uuid::new_v4()));
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();
        let temp_file = temp_dir.join(".localsend_s2_f2.part");

        let payload = b"Corrupted data stream";
        let bad_hash = "0000000000000000000000000000000000000000000000000000000000000000";

        let body = axum::body::Body::from(payload.to_vec());
        let res = stream_to_disk_and_hash(
            body,
            &temp_file,
            Some(payload.len() as u64),
            Some(bad_hash),
        )
        .await;

        assert!(matches!(res, Err(StorageError::HashMismatch { .. })));
        assert!(!temp_file.exists(), ".part file must be cleaned up on mismatch");

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_scavenge_orphaned_parts() {
        let temp_dir = std::env::temp_dir().join(format!("scavenge_{}", uuid::Uuid::new_v4()));
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();

        let old_part = temp_dir.join(".localsend_old_1.part");
        tokio::fs::write(&old_part, b"stale").await.unwrap();

        let regular_file = temp_dir.join("normal.txt");
        tokio::fs::write(&regular_file, b"keep").await.unwrap();

        // Scavenge with 0ms age will immediately sweep old_part
        let swept = scavenge_orphaned_parts(&temp_dir, Duration::from_millis(0))
            .await
            .unwrap();

        assert_eq!(swept, 1);
        assert!(!old_part.exists());
        assert!(regular_file.exists());

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }
}
