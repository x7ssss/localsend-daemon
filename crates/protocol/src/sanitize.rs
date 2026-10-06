//! Filesystem Path Sanitization & Collision Avoidance
//!
//! Provides zero-trust path sanitization against directory traversal attacks, Windows DOS
//! device name collisions, and safe non-destructive filename incrementation.

use std::path::{Path, PathBuf};

/// Maximum allowed length for a sanitized filename in bytes (standard Unix/NTFS limit).
pub const MAX_FILENAME_BYTES: usize = 255;

/// Errors returned during filename sanitization.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SanitizeError {
    /// Provided filename is empty or only whitespace.
    #[error("Filename is empty")]
    Empty,
    /// Filename contains a forbidden null byte.
    #[error("Filename contains null byte")]
    NullByte,
    /// Path traversal or absolute path attempted.
    #[error("Path traversal attempt detected: {0}")]
    PathTraversal(String),
    /// Windows DOS reserved device name detected.
    #[error("Windows reserved device name: {0}")]
    WindowsReserved(String),
    /// Filename exceeds the 255-byte ceiling.
    #[error("Filename exceeds 255 bytes (length: {0})")]
    TooLong(usize),
    /// Filename contains forbidden filesystem characters.
    #[error("Filename contains illegal characters: {0}")]
    IllegalCharacters(String),
    /// Invalid filename component.
    #[error("Invalid filename component")]
    InvalidFilename,
}

/// Checks if a filename matches Windows DOS reserved device names (case-insensitive).
///
/// Matches both base device names (e.g. `CON`, `NUL`) and device names with extensions (e.g. `CON.txt`, `aux.json`).
pub fn is_windows_reserved(filename: &str) -> bool {
    let stem = filename.split('.').next().unwrap_or("").trim();
    let upper = stem.to_ascii_uppercase();
    matches!(
        upper.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

/// Sanitize untrusted filename received over network.
///
/// Security constraints:
/// 1. Reject empty names, whitespace, and null bytes (`\0`).
/// 2. Reject directory traversal symbols (`..`) and absolute paths (`/`, `\`, drive letters).
/// 3. Normalize path separators and extract strictly the final basename.
/// 4. Reject Windows reserved DOS device names (e.g., `CON.txt`, `NUL`, `AUX`).
/// 5. Reject illegal filesystem characters (`<>:"/\|?*` and control codes `0x00..=0x1F`).
/// 6. Enforce a hard ceiling of 255 UTF-8 bytes.
pub fn sanitize_filename(untrusted_name: &str) -> Result<String, SanitizeError> {
    let trimmed = untrusted_name.trim();
    if trimmed.is_empty() {
        return Err(SanitizeError::Empty);
    }

    if untrusted_name.contains('\0') {
        return Err(SanitizeError::NullByte);
    }

    // Explicit path traversal and absolute path rejection
    if trimmed == "." || trimmed == ".." || untrusted_name.contains("..") {
        return Err(SanitizeError::PathTraversal(untrusted_name.to_string()));
    }

    if untrusted_name.starts_with('/') || untrusted_name.starts_with('\\') {
        return Err(SanitizeError::PathTraversal(untrusted_name.to_string()));
    }

    // Windows drive prefix detection (e.g. "C:\...")
    if untrusted_name.len() >= 2 {
        let bytes = untrusted_name.as_bytes();
        if bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
            return Err(SanitizeError::PathTraversal(untrusted_name.to_string()));
        }
    }

    // Normalize backslashes to forward slashes for cross-platform basename extraction
    let normalized = untrusted_name.replace('\\', "/");
    let path = Path::new(&normalized);
    let basename = match path.file_name().and_then(|f| f.to_str()) {
        Some(name) => name.trim(),
        None => return Err(SanitizeError::PathTraversal(untrusted_name.to_string())),
    };

    if basename.is_empty() || basename == "." || basename == ".." {
        return Err(SanitizeError::PathTraversal(untrusted_name.to_string()));
    }

    // Enforce 255-byte limit
    if basename.len() > MAX_FILENAME_BYTES {
        return Err(SanitizeError::TooLong(basename.len()));
    }

    // Windows DOS reserved device filtering
    if is_windows_reserved(basename) {
        return Err(SanitizeError::WindowsReserved(basename.to_string()));
    }

    // Reject illegal filesystem characters (< > : " / \ | ? *)
    if basename
        .chars()
        .any(|c| matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*'))
    {
        return Err(SanitizeError::IllegalCharacters(basename.to_string()));
    }

    // Reject ASCII control codes (0x00 to 0x1F)
    if basename.chars().any(|c| (c as u32) < 0x20) {
        return Err(SanitizeError::IllegalCharacters(basename.to_string()));
    }

    Ok(basename.to_string())
}

/// Resolves potential filename collision non-destructively in `dest_dir`.
///
/// If `target_filename` does not exist in `dest_dir`, returns `dest_dir.join(target_filename)`.
/// If it already exists, generates incremental variants:
/// `filename (1).ext`, `filename (2).ext`, etc.
pub fn resolve_collision(dest_dir: &Path, target_filename: &str) -> PathBuf {
    let initial_path = dest_dir.join(target_filename);
    if !initial_path.exists() {
        return initial_path;
    }

    let path = Path::new(target_filename);
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(target_filename);
    let extension = path.extension().and_then(|e| e.to_str());

    let mut counter: u32 = 1;
    loop {
        let candidate_name = match extension {
            Some(ext) => format!("{stem} ({counter}).{ext}"),
            None => format!("{stem} ({counter})"),
        };
        let candidate_path = dest_dir.join(&candidate_name);
        if !candidate_path.exists() {
            return candidate_path;
        }
        counter += 1;
    }
}
