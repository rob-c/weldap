//! Memory for secrets (decrypted passwords, LDAP bind requests, the directory service password).
//!
//! A `SecretBuf` is page-aligned and page-sized, locked into RAM (never swapped), excluded from core
//! dumps, zeroed with volatile writes before it is freed, fixed-capacity (never reallocated, so no stale
//! copies are left behind), not `Clone`, and impossible to print: `Debug` shows only `<secret>` and there
//! is no `Display`, `Serialize` or accessor that turns it into a `String`.

#![allow(unsafe_code)] // the one place secrets live: raw, locked, page-aligned allocations (see SAFETY notes)

use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::fmt;
use zeroize::Zeroize;

pub struct SecretBuf {
    ptr: *mut u8,
    len: usize,
    layout: Layout,
}

// The buffer is uniquely owned; moving it between threads is fine.
unsafe impl Send for SecretBuf {}

#[derive(Debug)]
pub struct CapacityExceeded;

fn page_size() -> usize {
    // SAFETY: sysconf has no preconditions.
    let p = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    usize::try_from(p).ok().filter(|p| *p > 0).unwrap_or(4096)
}

impl SecretBuf {
    /// A zeroed buffer that can hold at least `capacity` bytes.
    pub fn with_capacity(capacity: usize) -> SecretBuf {
        let page = page_size();
        let size = capacity.max(1).div_ceil(page) * page;
        let layout = Layout::from_size_align(size, page).expect("secret layout");
        // SAFETY: layout has non-zero size. OOM aborts (panic = abort); the dead branch lives inside std.
        let ptr = std::ptr::NonNull::new(unsafe { alloc_zeroed(layout) }).expect("allocation failed").as_ptr();
        // SAFETY: ptr..ptr+size is our allocation. Already locked when mlockall(MCL_FUTURE) is in effect;
        // mlock again so a buffer is locked even if the process-wide lock was not available.
        unsafe {
            libc::mlock(ptr.cast_const().cast(), size);
            #[cfg(target_os = "linux")]
            libc::madvise(ptr.cast(), size, libc::MADV_DONTDUMP);
        }
        SecretBuf { ptr, len: 0, layout }
    }

    pub fn capacity(&self) -> usize {
        self.layout.size()
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// A locked buffer holding exactly `parts` concatenated. It is allocated to fit the whole concatenation, so
    /// each append fits and cannot fail; a secret part is copied straight in, never through a growable `Vec`.
    pub fn concat(parts: &[&[u8]]) -> SecretBuf {
        let total = parts.iter().map(|p| p.len()).sum();
        let mut buf = SecretBuf::with_capacity(total);
        for p in parts {
            let _ = buf.extend_from_slice(p); // cannot fail: capacity >= total
        }
        buf
    }

    pub fn extend_from_slice(&mut self, data: &[u8]) -> Result<(), CapacityExceeded> {
        if data.len() > self.capacity() - self.len {
            return Err(CapacityExceeded);
        }
        // SAFETY: bounds checked above; source and destination do not overlap (data is not inside self
        // except through as_slice, which needs &self while this takes &mut self).
        unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), self.ptr.add(self.len), data.len()) };
        self.len += data.len();
        Ok(())
    }

    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: the first len bytes are initialised (the allocation is zeroed).
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: as above, uniquely borrowed.
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }

    /// Reads at most `max` bytes from `r` straight into locked memory (no intermediate Vec); more is an error.
    /// Takes `&mut dyn Read` (one instantiation) rather than a generic, so every branch is measured once.
    pub fn read_from(r: &mut dyn std::io::Read, max: usize) -> std::io::Result<SecretBuf> {
        let mut buf = SecretBuf::with_capacity(max + 1); // one spare byte to detect "more than max"
        loop {
            if buf.len > max {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "secret too large"));
            }
            // SAFETY: writing into our own spare capacity (len <= max < capacity).
            let spare = unsafe { std::slice::from_raw_parts_mut(buf.ptr.add(buf.len), max + 1 - buf.len) };
            let n = r.read(spare)?;
            if n == 0 {
                return Ok(buf);
            }
            buf.len += n;
        }
    }

    /// Drops trailing CR/LF (secret files written by `echo`).
    pub fn trim_newlines(&mut self) {
        while self.len > 0 && matches!(self.as_slice()[self.len - 1], b'\n' | b'\r') {
            self.len -= 1;
            // SAFETY: index len is inside the allocation; zero the byte we dropped.
            unsafe { std::ptr::write_volatile(self.ptr.add(self.len), 0) };
        }
    }
}

impl Drop for SecretBuf {
    fn drop(&mut self) {
        let size = self.layout.size();
        // SAFETY: our allocation; zeroize uses volatile writes + a compiler fence, so it is not elided.
        unsafe {
            std::slice::from_raw_parts_mut(self.ptr, size).zeroize();
            libc::munlock(self.ptr.cast_const().cast(), size);
            dealloc(self.ptr, self.layout);
        }
    }
}

impl fmt::Debug for SecretBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<secret>") // not even the length
    }
}

#[cfg(test)]
#[path = "tests/unit_secret.rs"]
mod tests;
