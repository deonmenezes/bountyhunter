//! SHA-256 hashing primitives — faithful Rust port of `core.hash`.
//!
//! The implementation preserves the Python package's observable contracts:
//! paths are part of tree digests, traversal order is deterministic, symlinks
//! are ignored, large files are skipped, file reads are streamed, and chunk
//! sizes smaller than 4 KiB are floored without changing the digest.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use mantishack_core_config::{HASH_CHUNK_SIZE, MAX_FILE_SIZE_FOR_HASH};
use sha2::{Digest, Sha256};

const FS_ENCODING_CHUNK_FLOOR: i64 = 4096;
const MAX_FILE_SIZE_NO_CAP_THRESHOLD: i64 = 1_000_000_000_000;

fn digest_hex(hasher: Sha256) -> String {
    format!("{:x}", hasher.finalize())
}

fn chunk_size(value: Option<i64>) -> usize {
    let value = value
        .unwrap_or(HASH_CHUNK_SIZE)
        .max(FS_ENCODING_CHUNK_FLOOR);
    usize::try_from(value).unwrap_or(usize::MAX)
}

/// Hash bytes already held in memory.
pub fn sha256_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    digest_hex(hasher)
}

/// Hash a valid UTF-8 Rust string.
///
/// Python's lone-surrogate `surrogateescape` behavior is implemented in the
/// PyO3 wrapper, before the resulting raw bytes reach [`sha256_bytes`].
pub fn sha256_string(value: &str) -> String {
    sha256_bytes(value.as_bytes())
}

/// Hash one file in bounded chunks instead of loading it wholly into memory.
pub fn sha256_file(path: &Path, requested_chunk_size: Option<i64>) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; chunk_size(requested_chunk_size)];

    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    Ok(digest_hex(hasher))
}

fn collect_tree_files(root: &Path, current: &Path, files: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(current) {
        Ok(entries) => entries,
        // Python's os.walk() silently skips unreadable or vanished directories
        // when no onerror callback is supplied.
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(_) => continue,
        };
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            collect_tree_files(root, &path, files);
        } else if path.strip_prefix(root).is_ok() {
            files.push(path);
        }
    }
}

#[cfg(unix)]
fn open_nofollow(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

#[cfg(not(unix))]
fn open_nofollow(path: &Path) -> io::Result<File> {
    OpenOptions::new().read(true).open(path)
}

#[cfg(unix)]
fn relative_path_bytes(path: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;

    path.as_os_str().as_bytes().to_vec()
}

#[cfg(not(unix))]
fn relative_path_bytes(path: &Path) -> Vec<u8> {
    path.to_string_lossy().replace('\\', "/").into_bytes()
}

/// Hash a directory tree using each regular file's relative path and contents.
///
/// Missing/unreadable directories and files that cannot be opened are skipped,
/// matching `os.walk` plus the Python implementation's best-effort open path.
/// Read errors after a file is opened are returned to the caller, like Python.
pub fn sha256_tree(
    root: &Path,
    requested_max_file_size: Option<i64>,
    requested_chunk_size: Option<i64>,
) -> io::Result<String> {
    let max_file_size = requested_max_file_size.unwrap_or(MAX_FILE_SIZE_FOR_HASH);
    let cumulative_cap = i128::from(max_file_size) * 100;
    let buffer_size = chunk_size(requested_chunk_size);

    let mut files = Vec::new();
    collect_tree_files(root, root, &mut files);
    files.sort();

    let mut hasher = Sha256::new();
    let mut cumulative_bytes = 0_i128;

    for path in files {
        // Mirrors `Path.is_file()`: skip special files and anything that became
        // a symlink between enumeration and this check.
        let before_open = match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_file() => metadata,
            _ => continue,
        };
        if before_open.file_type().is_symlink() {
            continue;
        }

        let mut file = match open_nofollow(&path) {
            Ok(file) => file,
            // ELOOP/ENOENT/EACCES are all best-effort skips in the Python port.
            Err(_) => continue,
        };
        let metadata = match file.metadata() {
            Ok(metadata) if metadata.is_file() => metadata,
            _ => continue,
        };
        let file_size = i128::from(metadata.len());

        if max_file_size < MAX_FILE_SIZE_NO_CAP_THRESHOLD && file_size > i128::from(max_file_size) {
            continue;
        }
        if cumulative_bytes + file_size > cumulative_cap {
            break;
        }

        let relative = match path.strip_prefix(root) {
            Ok(relative) => relative,
            Err(_) => continue,
        };
        hasher.update(relative_path_bytes(relative));

        let mut buffer = vec![0_u8; buffer_size];
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
            cumulative_bytes += read as i128;
        }
    }

    Ok(digest_hex(hasher))
}

#[cfg(feature = "python")]
// PyO3 0.22's generated wrappers call `.into()` on `PyErr`; newer clippy
// identifies that macro-generated conversion as redundant.
#[allow(clippy::useless_conversion)]
mod python {
    use std::path::PathBuf;

    use pyo3::prelude::*;
    use pyo3::types::{PyBytes, PyString};

    #[pyfunction]
    #[pyo3(signature = (root, max_file_size=None, chunk_size=None))]
    fn sha256_tree(
        root: PathBuf,
        max_file_size: Option<i64>,
        chunk_size: Option<i64>,
    ) -> PyResult<String> {
        super::sha256_tree(&root, max_file_size, chunk_size).map_err(PyErr::from)
    }

    #[pyfunction]
    #[pyo3(signature = (path, chunk_size=None))]
    fn sha256_file(path: PathBuf, chunk_size: Option<i64>) -> PyResult<String> {
        super::sha256_file(&path, chunk_size).map_err(PyErr::from)
    }

    #[pyfunction]
    fn sha256_bytes(data: &[u8]) -> String {
        super::sha256_bytes(data)
    }

    #[pyfunction]
    fn sha256_string(s: &Bound<'_, PyString>) -> PyResult<String> {
        // Asking Python itself to perform surrogateescape preserves lone
        // surrogates that cannot be represented by Rust's UTF-8 `str`.
        let encoded = s.call_method1("encode", ("utf-8", "surrogateescape"))?;
        let bytes = encoded.downcast::<PyBytes>()?;
        Ok(super::sha256_bytes(bytes.as_bytes()))
    }

    #[pymodule]
    pub fn mantishack_core_hash(m: &Bound<'_, PyModule>) -> PyResult<()> {
        m.add_function(wrap_pyfunction!(sha256_tree, m)?)?;
        m.add_function(wrap_pyfunction!(sha256_file, m)?)?;
        m.add_function(wrap_pyfunction!(sha256_bytes, m)?)?;
        m.add_function(wrap_pyfunction!(sha256_string, m)?)?;
        Ok(())
    }
}

#[cfg(feature = "python")]
pub use python::mantishack_core_hash;

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn bytes_match_python_hashlib_vectors() {
        let cases: &[(&[u8], &str)] = &[
            (
                b"",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                b"abc",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                b"\x00\x01\xff",
                "26a66b061e8f48f39927c312f25293959729eee95978e2892d49d3512a5cc092",
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(sha256_bytes(input), *expected);
        }
    }

    #[test]
    fn valid_unicode_string_matches_utf8_hash() {
        assert_eq!(
            sha256_string("café — 日本語 — 🦖"),
            sha256_bytes("café — 日本語 — 🦖".as_bytes())
        );
    }

    #[test]
    fn file_hash_is_chunk_size_independent() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("data.bin");
        let data = vec![b'x'; 100_000];
        fs::write(&path, &data).unwrap();

        let expected = sha256_bytes(&data);
        assert_eq!(sha256_file(&path, Some(128)).unwrap(), expected);
        assert_eq!(sha256_file(&path, Some(1024 * 1024)).unwrap(), expected);
        assert_eq!(sha256_file(&path, None).unwrap(), expected);
    }

    #[test]
    fn missing_file_propagates_io_error() {
        let dir = tempdir().unwrap();
        assert_eq!(
            sha256_file(&dir.path().join("missing"), None)
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn tree_matches_python_golden_digest() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), b"alpha").unwrap();
        fs::create_dir(dir.path().join("sub")).unwrap();
        fs::write(dir.path().join("sub/b.bin"), b"\x00\xff").unwrap();

        assert_eq!(
            sha256_tree(dir.path(), None, None).unwrap(),
            "12374d6b809fb7209c3016240b59ab6a8110959e054d437377f6e8cf8d9d8d10"
        );
    }

    #[test]
    fn empty_and_missing_trees_match_python_empty_digest() {
        let dir = tempdir().unwrap();
        let expected = sha256_bytes(b"");
        assert_eq!(sha256_tree(dir.path(), None, None).unwrap(), expected);
        assert_eq!(
            sha256_tree(&dir.path().join("missing"), None, None).unwrap(),
            expected
        );
    }

    #[test]
    fn tree_skips_files_over_limit() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("small.txt"), b"small content").unwrap();
        let before = sha256_tree(dir.path(), Some(100), None).unwrap();

        fs::write(dir.path().join("large.txt"), vec![b'x'; 200]).unwrap();
        assert_eq!(sha256_tree(dir.path(), Some(100), None).unwrap(), before);
    }

    #[test]
    fn tree_digest_includes_relative_file_path() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("first.txt"), b"same").unwrap();
        let first = sha256_tree(dir.path(), None, None).unwrap();
        fs::rename(dir.path().join("first.txt"), dir.path().join("second.txt")).unwrap();
        let second = sha256_tree(dir.path(), None, None).unwrap();
        assert_ne!(first, second);
    }

    #[cfg(unix)]
    #[test]
    fn tree_skips_file_and_directory_symlinks() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let outside = tempdir().unwrap();
        fs::write(outside.path().join("secret"), b"not part of tree").unwrap();
        symlink(outside.path().join("secret"), dir.path().join("file-link")).unwrap();
        symlink(outside.path(), dir.path().join("dir-link")).unwrap();

        assert_eq!(
            sha256_tree(dir.path(), None, None).unwrap(),
            sha256_bytes(b"")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tree_hashes_non_utf8_filename_with_surrogateescape_bytes() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let dir = tempdir().unwrap();
        let name = OsString::from_vec(b"file-\xff.bin".to_vec());
        fs::write(dir.path().join(&name), b"content").unwrap();

        let mut expected = Sha256::new();
        expected.update(b"file-\xff.bin");
        expected.update(b"content");
        assert_eq!(
            sha256_tree(dir.path(), None, None).unwrap(),
            digest_hex(expected)
        );
    }
}
