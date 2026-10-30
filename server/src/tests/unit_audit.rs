//! Audit lines: one flat JSON object, allow-listed identifiers only.

use super::*;
use crate::cases;

fn line(fields: &[(&'static str, V)]) -> serde_json::Value {
    capture::take();
    event("test", fields);
    let lines = capture::take();
    assert_eq!(lines.len(), 1);
    assert!(!lines[0].contains('\n'));
    serde_json::from_str(&lines[0]).unwrap()
}

#[test]
fn shape() {
    let v = line(&[("result", V::S("ok")), ("ms", V::N(12)), ("uun", V::Id("alice"))]);
    let obj = v.as_object().unwrap();
    assert_eq!(obj.keys().cloned().collect::<Vec<_>>(), ["event", "ms", "result", "ts", "uun"]);
    assert_eq!(v["event"], "test");
    assert_eq!(v["result"], "ok");
    assert_eq!(v["ms"], 12);
    assert_eq!(v["uun"], "alice");
    assert!(v["ts"].as_u64().unwrap() > 1_700_000_000);
}

#[test]
fn no_fields() {
    let v = line(&[]);
    assert_eq!(v.as_object().unwrap().len(), 2);
}

#[test]
fn numbers_full_range() {
    assert_eq!(line(&[("ms", V::N(u64::MAX))])["ms"], u64::MAX);
    assert_eq!(line(&[("ms", V::N(0))])["ms"], 0);
}

#[test]
fn capture_is_per_thread() {
    capture::take();
    std::thread::spawn(|| event("other_thread", &[])).join().unwrap();
    assert!(capture::take().is_empty());
    assert!(capture::all().iter().any(|l| l.contains("other_thread")));
}

fn hostile(id: &str) {
    assert!(!is_identifier(id));
    assert_eq!(line(&[("device", V::Id(id))])["device"], "?");
}

cases! { hostile;
    id_empty: "";
    id_upper: "Alice";
    id_quote: "a\"b";
    id_json_breakout: "x\",\"admin\":\"true";
    id_newline: "a\nb";
    id_cr: "a\rb";
    id_backslash: "a\\b";
    id_nul: "a\0b";
    id_space: "a b";
    id_tab: "a\tb";
    id_braces: "{}";
    id_path: "../x";
    id_dot: "a.b";
    id_underscore: "a_b";
    id_unicode: "alicé";
    id_rtl_override: "a\u{202e}b";
    id_64_chars: &"a".repeat(64);
    id_long: &"a".repeat(10_000);
    id_ansi: "\u{1b}[31m";
}

fn allowed(id: &str) {
    assert!(is_identifier(id));
    assert_eq!(line(&[("uun", V::Id(id))])["uun"], id);
}

cases! { allowed;
    id_device: "win11-arm64";
    id_digits: "0123456789";
    id_one: "a";
    id_dash_only: "-";
    id_63_chars: &"z".repeat(63);
}
