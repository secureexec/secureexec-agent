use std::fs;
use std::io::Read as _;
use std::num::NonZeroUsize;
use std::os::unix::fs::MetadataExt;

use lru::LruCache;
use sha2::{Digest, Sha256};

const MAX_READ: u64 = 50 * 1024 * 1024; // 50 MB
const BUF_SIZE: usize = 64 * 1024; // 64 KB read chunks
const CACHE_CAP: usize = 8192;

#[derive(Hash, Eq, PartialEq)]
struct ExeHashKey {
    dev: u64,
    ino: u64,
    mtime: i64,
    ctime: i64,
    size: u64,
}

pub struct ExeHashCache {
    cache: LruCache<ExeHashKey, (String, u64)>,
}

impl ExeHashCache {
    pub fn new() -> Self {
        // Safety: CACHE_CAP is a non-zero constant.
        let cap = NonZeroUsize::new(CACHE_CAP).unwrap();
        Self { cache: LruCache::new(cap) }
    }

    /// Compute (or return cached) SHA-256 hex hash and file size for the
    /// executable of the given pid.  Reads at most 50 MB; for larger files the
    /// hash covers only the first 50 MB.  Returns `("", 0)` on any error.
    pub fn hash_exe(&mut self, pid: u32) -> (String, u64) {
        let exe_path = format!("/proc/{pid}/exe");

        // Open first, then fstat the fd — guarantees metadata and content
        // refer to the same inode (no TOCTOU race).
        let mut file = match fs::File::open(&exe_path) {
            Ok(f) => f,
            Err(_) => return (String::new(), 0),
        };
        let meta = match file.metadata() {
            Ok(m) => m,
            Err(_) => return (String::new(), 0),
        };

        let key = ExeHashKey {
            dev: meta.dev(),
            ino: meta.ino(),
            mtime: meta.mtime(),
            ctime: meta.ctime(),
            size: meta.size(),
        };
        let file_size = meta.size();

        if let Some(cached) = self.cache.get(&key) {
            return cached.clone();
        }

        let hash = match compute_sha256(&mut file, MAX_READ) {
            Some(h) => h,
            None => return (String::new(), file_size),
        };
        let result = (hash, file_size);
        self.cache.put(key, result.clone());
        result
    }
}

fn compute_sha256(file: &mut fs::File, max_bytes: u64) -> Option<String> {
    let mut hasher = Sha256::new();
    let mut buf = [0u8; BUF_SIZE];
    let mut remaining = max_bytes;

    while remaining > 0 {
        let to_read = (remaining as usize).min(buf.len());
        let n = file.read(&mut buf[..to_read]).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        remaining -= n as u64;
    }
    Some(hex::encode(hasher.finalize()))
}
