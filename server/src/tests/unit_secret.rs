//! Locked secret buffers. Self-contained (no shared test helpers): this module is also compiled into the probe.
//! Zeroing on drop is not observed here: reading freed memory cannot be done soundly.

use super::*;
use std::io::Read;

fn page() -> usize {
    page_size()
}

#[test]
fn page_size_is_sane() {
    let p = page();
    assert!(p >= 4096 && p.is_power_of_two());
}

#[test]
fn capacity_rounds_up_to_pages() {
    let p = page();
    for (asked, pages) in [(0, 1), (1, 1), (p - 1, 1), (p, 1), (p + 1, 2), (3 * p, 3)] {
        assert_eq!(SecretBuf::with_capacity(asked).capacity(), pages * p, "capacity({asked})");
    }
}

#[test]
fn page_aligned() {
    for cap in [1, 100, page(), 3 * page() + 7] {
        let mut s = SecretBuf::with_capacity(cap);
        s.extend_from_slice(b"x").unwrap();
        assert_eq!(s.as_slice().as_ptr() as usize % page(), 0);
    }
}

#[test]
fn new_buffer_is_empty() {
    let s = SecretBuf::with_capacity(10);
    assert!(s.is_empty());
    assert_eq!(s.len(), 0);
    assert_eq!(s.as_slice(), b"");
}

#[test]
fn holds_and_appends() {
    let mut s = SecretBuf::with_capacity(10);
    s.extend_from_slice(b"hunter").unwrap();
    s.extend_from_slice(b"").unwrap();
    s.extend_from_slice(b"2").unwrap();
    assert_eq!(s.as_slice(), b"hunter2");
    assert_eq!(s.len(), 7);
    assert!(!s.is_empty());
}

#[test]
fn fills_exactly_to_capacity() {
    let mut s = SecretBuf::with_capacity(1);
    let cap = s.capacity();
    s.extend_from_slice(&vec![7u8; cap - 1]).unwrap();
    s.extend_from_slice(&[8]).unwrap();
    assert_eq!(s.len(), cap);
    assert!(s.extend_from_slice(&[9]).is_err());
    assert!(s.extend_from_slice(b"").is_ok());
    assert_eq!(s.as_slice()[cap - 1], 8);
}

#[test]
fn overflow_leaves_content_unchanged() {
    let mut s = SecretBuf::with_capacity(1);
    s.extend_from_slice(b"abc").unwrap();
    let too_much = vec![0u8; s.capacity()];
    assert!(s.extend_from_slice(&too_much).is_err());
    assert_eq!(s.as_slice(), b"abc");
}

#[test]
fn mutable_view() {
    let mut s = SecretBuf::with_capacity(4);
    s.extend_from_slice(b"abcd").unwrap();
    s.as_mut_slice().make_ascii_uppercase();
    assert_eq!(s.as_slice(), b"ABCD");
    assert_eq!(s.as_mut_slice().len(), 4);
}

#[test]
fn debug_never_shows_content_or_length() {
    let mut s = SecretBuf::with_capacity(64);
    assert_eq!(format!("{s:?}"), "<secret>");
    s.extend_from_slice(b"hunter2").unwrap();
    assert_eq!(format!("{s:?}"), "<secret>");
    assert_eq!(format!("{s:#?}"), "<secret>");
    assert_eq!(format!("{:?}", Some(&s)), "Some(<secret>)");
}

#[test]
fn is_send() {
    fn send<T: Send>(_: &T) {}
    send(&SecretBuf::with_capacity(1));
}

#[test]
fn trim_newlines_table() {
    for (input, want) in [
        (&b"pw\r\n"[..], &b"pw"[..]),
        (b"pw\n", b"pw"),
        (b"pw\n\n\r\n", b"pw"),
        (b"pw", b"pw"),
        (b"\n", b""),
        (b"\r\n\r\n", b""),
        (b"", b""),
        (b"p\nw", b"p\nw"),
        (b"\npw", b"\npw"),
        (b"pw ", b"pw "),
        (b"pw\t\n", b"pw\t"),
    ] {
        let mut s = SecretBuf::with_capacity(16);
        s.extend_from_slice(input).unwrap();
        s.trim_newlines();
        assert_eq!(s.as_slice(), want, "{input:?}");
    }
}

#[test]
fn trim_then_extend_overwrites() {
    let mut s = SecretBuf::with_capacity(16);
    s.extend_from_slice(b"ab\n\n").unwrap();
    s.trim_newlines();
    s.extend_from_slice(b"c").unwrap();
    assert_eq!(s.as_slice(), b"abc");
}

#[test]
fn read_from_small() {
    let s = SecretBuf::read_from(&mut &b"secret\n"[..], 256).unwrap();
    assert_eq!(s.as_slice(), b"secret\n");
}

#[test]
fn read_from_empty() {
    assert!(SecretBuf::read_from(&mut &b""[..], 16).unwrap().is_empty());
}

#[test]
fn read_from_exactly_max() {
    let data = vec![b'a'; 256];
    assert_eq!(SecretBuf::read_from(&mut data.as_slice(), 256).unwrap().len(), 256);
}

#[test]
fn read_from_over_max() {
    for max in [0, 1, 255, 256, page() - 1, page()] {
        let data = vec![b'a'; max + 1];
        let e = SecretBuf::read_from(&mut data.as_slice(), max).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidData, "max {max}");
    }
}

#[test]
fn read_from_much_larger_input() {
    let data = vec![b'a'; 1 << 20];
    assert!(SecretBuf::read_from(&mut data.as_slice(), 1024).is_err());
}

/// Hands out one byte per read.
struct Trickle<'a>(&'a [u8]);

impl Read for Trickle<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let Some((&b, rest)) = self.0.split_first() else {
            return Ok(0);
        };
        buf[0] = b;
        self.0 = rest;
        Ok(1)
    }
}

#[test]
fn read_from_short_reads() {
    let s = SecretBuf::read_from(&mut Trickle(b"one byte at a time"), 64).unwrap();
    assert_eq!(s.as_slice(), b"one byte at a time");
    assert!(SecretBuf::read_from(&mut Trickle(&[b'x'; 65]), 64).is_err());
}

struct Failing;

impl Read for Failing {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::ErrorKind::PermissionDenied.into())
    }
}

#[test]
fn read_from_propagates_errors() {
    assert_eq!(SecretBuf::read_from(&mut Failing, 64).unwrap_err().kind(), std::io::ErrorKind::PermissionDenied);
}

#[test]
fn many_buffers_alloc_and_free() {
    // Exercise mlock/munlock and the allocator across many pages (a leak or double free would show here).
    let bufs: Vec<_> = (0..256)
        .map(|i| {
            let mut s = SecretBuf::with_capacity(i * 17);
            s.extend_from_slice(&[u8::try_from(i % 256).unwrap(); 3]).unwrap();
            s
        })
        .collect();
    assert!(bufs.iter().enumerate().all(|(i, s)| s.as_slice() == [u8::try_from(i % 256).unwrap(); 3]));
}
