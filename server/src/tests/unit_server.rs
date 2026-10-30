//! `Server::handle` (pure: frame in, reply out) against a scripted directory, plus framing, rate windows,
//! per-address slots and device names. Every request goes through `send`, which also checks the audit lines.

use super::*;
use crate::audit::capture;
use crate::cases;
use crate::directory::Membership;
use crate::tests::support::{assert_clean, fresh_rid, pki, Call, FakeDirectory};
use serde_json::{json, Value};
use std::cell::RefCell;

const NOW: u64 = 1_800_000_000;
const SKEW: u64 = 120;
const DEV: &str = "laptop-01";
const ALICE: &str = "alice";
const PW: &[u8] = b"correct horse battery staple";
const USER: Membership = Membership { user: true, admin: false };
const ADMIN: Membership = Membership { user: true, admin: true };
const NONE: Membership = Membership { user: false, admin: false };

struct H {
    server: Server,
    dir: FakeDirectory,
    pk1: Vec<u8>,
    pk2: Vec<u8>,
    /// Every plaintext and every enc/ct/rid sent: none may ever appear in an audit line.
    secrets: RefCell<Vec<Vec<u8>>>,
    /// The audit line of the last request.
    last: RefCell<Value>,
}

fn key(kid: &str) -> (PasswordKey, Vec<u8>) {
    let (sk, pk) = seal::generate();
    (PasswordKey::from_scalar(kid.into(), &sk).unwrap(), pk)
}

fn h() -> H {
    let dir = FakeDirectory::default().with_user(ALICE, PW, USER).with_user("root1", b"admin-pass", ADMIN);
    let ((k1, pk1), (k2, pk2)) = (key("k1"), key("k2"));
    H {
        server: Server::new(vec![k1, k2], dir.boxed(), SKEW),
        dir,
        pk1,
        pk2,
        secrets: RefCell::default(),
        last: RefCell::default(),
    }
}

struct Seal<'a> {
    kid: &'a str,
    uun: &'a str,
    scenario: &'a str,
    ts: u64,
    rid: String,
    password: &'a [u8],
}

fn seal_for(uun: &str, password: &[u8]) -> Seal<'static> {
    let uun: &'static str = Box::leak(uun.to_string().into_boxed_str());
    let password: &'static [u8] = Box::leak(password.to_vec().into_boxed_slice());
    Seal { kid: "k1", uun, scenario: "logon", ts: NOW, rid: fresh_rid(), password }
}

impl H {
    fn pk(&self, kid: &str) -> &[u8] {
        if kid == "k2" {
            &self.pk2
        } else {
            &self.pk1
        }
    }

    /// A well-formed auth request for `s`, sealed with the AAD it describes.
    fn request(&self, s: &Seal) -> Value {
        let aad = seal::aad(s.kid, s.uun, s.scenario, s.ts, &s.rid);
        let (enc, ct) = seal::seal(self.pk(s.kid), s.password, &aad).unwrap();
        let (enc, ct) = (B64.encode(enc), B64.encode(ct));
        self.secrets.borrow_mut().extend([
            s.password.to_vec(),
            enc.clone().into(),
            ct.clone().into(),
            s.rid.clone().into(),
        ]);
        json!({"v": 1, "op": "auth", "uun": s.uun, "scenario": s.scenario, "kid": s.kid, "enc": enc, "ct": ct,
               "ts": s.ts, "rid": s.rid})
    }

    fn auth(&self, uun: &str, password: &[u8]) -> Value {
        self.request(&seal_for(uun, password))
    }

    fn send_raw_from(&self, device: &str, frame: &[u8], now: u64) -> Option<Value> {
        capture::take();
        let out = self.server.handle(device, frame, now);
        let lines = capture::take();
        assert_eq!(lines.len(), 1, "exactly one audit line per request: {lines:?}");
        let mut secrets = self.secrets.borrow().clone();
        secrets.push(frame.to_vec());
        assert_clean(&lines, &secrets.iter().map(Vec::as_slice).collect::<Vec<_>>());
        let line: Value = serde_json::from_str(&lines[0]).unwrap();
        let logged_device = line["device"].as_str().unwrap();
        assert!(logged_device == device || logged_device == "?", "{line}");
        *self.last.borrow_mut() = line;
        out.map(|b| serde_json::from_slice(&b).unwrap())
    }

    fn send_raw(&self, frame: &[u8]) -> Option<Value> {
        self.send_raw_from(DEV, frame, NOW)
    }

    fn send(&self, v: &Value) -> Option<Value> {
        self.send_raw(&serde_json::to_vec(v).unwrap())
    }

    fn send_at(&self, v: &Value, now: u64) -> Option<Value> {
        self.send_raw_from(DEV, &serde_json::to_vec(v).unwrap(), now)
    }

    fn send_from(&self, device: &str, v: &Value) -> Option<Value> {
        self.send_raw_from(device, &serde_json::to_vec(v).unwrap(), NOW)
    }

    fn calls(&self) -> Vec<Call> {
        self.dir.calls()
    }

    fn last(&self) -> Value {
        self.last.borrow().clone()
    }

    /// A fresh request whose timestamp is `ts`.
    fn auth_at(&self, ts: u64) -> Value {
        let mut s = seal_for(ALICE, PW);
        s.ts = ts;
        self.request(&s)
    }
}

fn result(r: Option<Value>) -> String {
    r.expect("a reply")["result"].as_str().unwrap().to_string()
}

/// The reply, and that the directory was never consulted.
fn rejected(h: &H, req: &Value) -> Option<Value> {
    let r = h.send(req);
    assert!(h.calls().is_empty(), "directory called for a rejected request: {req}");
    r
}

// ---------- happy paths and reply shape ----------

#[test]
fn auth_ok_user_exact_reply() {
    let h = h();
    let r = h.send(&h.auth(ALICE, PW)).unwrap();
    assert_eq!(r, json!({"v": 1, "result": "ok", "user": true, "admin": false}));
    assert_eq!(h.calls(), vec![Call::Auth { uun: ALICE.into(), password: PW.to_vec() }]);
}

#[test]
fn auth_ok_admin() {
    let h = h();
    let r = h.send(&h.auth("root1", b"admin-pass")).unwrap();
    assert_eq!(r, json!({"v": 1, "result": "ok", "user": true, "admin": true}));
}

#[test]
fn auth_ok_not_member_logs_reason() {
    let h = h();
    h.dir.set_auth(Ok(NONE));
    let r = h.send(&h.auth(ALICE, PW)).unwrap();
    assert_eq!(r, json!({"v": 1, "result": "ok", "user": false, "admin": false}));
}

#[test]
fn auth_admin_only_flags_passed_through() {
    let h = h();
    h.dir.set_auth(Ok(Membership { user: false, admin: true }));
    let r = h.send(&h.auth(ALICE, PW)).unwrap();
    assert_eq!(r, json!({"v": 1, "result": "ok", "user": false, "admin": true}));
}

#[test]
fn auth_audit_line_fields() {
    let h = h();
    capture::take();
    h.server.handle(DEV, &serde_json::to_vec(&h.auth(ALICE, PW)).unwrap(), NOW);
    let lines = capture::take();
    let v: Value = serde_json::from_str(&lines[0]).unwrap();
    assert_eq!(v["event"], "auth");
    assert_eq!(v["device"], DEV);
    assert_eq!(v["uun"], ALICE);
    assert_eq!(v["result"], "ok");
    assert_eq!(v["reason"], "member");
    assert!(v["ms"].is_u64());
}

#[test]
fn unscripted_scenario_unlock_ok() {
    let h = h();
    let mut s = seal_for(ALICE, PW);
    s.scenario = "unlock";
    assert_eq!(result(h.send(&h.request(&s))), "ok");
}

#[test]
fn password_bytes_reach_directory_unchanged() {
    let h = h();
    let pw: Vec<u8> = (1u8..=255).collect();
    h.send(&h.auth(ALICE, &pw));
    assert_eq!(h.calls(), vec![Call::Auth { uun: ALICE.into(), password: pw }]);
}

#[test]
fn password_max_size_accepted() {
    let h = h();
    let pw = vec![b'x'; seal::MAX_PASSWORD_BYTES];
    h.send(&h.auth(ALICE, &pw));
    assert_eq!(h.calls(), vec![Call::Auth { uun: ALICE.into(), password: pw }]);
}

#[test]
fn password_over_max_size_is_error() {
    let h = h();
    let r = rejected(&h, &h.auth(ALICE, &vec![b'x'; seal::MAX_PASSWORD_BYTES + 1]));
    assert_eq!(result(r), "error");
}

#[test]
fn empty_password_is_invalid_without_directory() {
    let h = h();
    let r = rejected(&h, &h.auth(ALICE, b""));
    assert_eq!(r.unwrap(), json!({"v": 1, "result": "invalid"}));
    assert_eq!(h.last()["reason"], "empty_password");
}

// ---------- directory outcomes ----------

fn outcome(f: Failure, expected: &str) {
    let h = h();
    h.dir.set_auth(Err(f));
    let r = h.send(&h.auth(ALICE, PW)).unwrap();
    assert_eq!(r, json!({"v": 1, "result": expected}));
    assert_eq!(h.calls().len(), 1);
}

cases! { outcome;
    directory_invalid: Failure::Invalid, "invalid";
    directory_denied: Failure::Denied, "denied";
    directory_unavailable: Failure::Unavailable, "unavailable";
    directory_error: Failure::Error("directory_protocol"), "error";
    directory_error_self_read: Failure::Error("self_read"), "error";
}

#[test]
fn wrong_password_is_invalid() {
    let h = h();
    assert_eq!(h.send(&h.auth(ALICE, b"wrong")).unwrap(), json!({"v": 1, "result": "invalid"}));
}

#[test]
fn directory_error_reason_is_logged() {
    let h = h();
    h.dir.set_auth(Err(Failure::Error("self_read")));
    capture::take();
    h.server.handle(DEV, &serde_json::to_vec(&h.auth(ALICE, PW)).unwrap(), NOW);
    let v: Value = serde_json::from_str(&capture::take()[0]).unwrap();
    assert_eq!(v["reason"], "self_read");
}

// ---------- strict JSON ----------

const AUTH_FIELDS: [&str; 9] = ["v", "op", "uun", "scenario", "kid", "enc", "ct", "ts", "rid"];

fn missing_auth_field(field: &str) {
    let h = h();
    let mut req = h.auth(ALICE, PW);
    req.as_object_mut().unwrap().remove(field).unwrap();
    assert_eq!(rejected(&h, &req), None);
}

cases! { missing_auth_field;
    auth_missing_v: "v"; auth_missing_op: "op"; auth_missing_uun: "uun"; auth_missing_scenario: "scenario";
    auth_missing_kid: "kid"; auth_missing_enc: "enc"; auth_missing_ct: "ct"; auth_missing_ts: "ts";
    auth_missing_rid: "rid";
}

#[test]
fn auth_fields_list_is_complete() {
    let h = h();
    let req = h.auth(ALICE, PW);
    let mut keys: Vec<_> = req.as_object().unwrap().keys().cloned().collect();
    keys.sort();
    let mut want: Vec<_> = AUTH_FIELDS.iter().map(ToString::to_string).collect();
    want.sort();
    assert_eq!(keys, want);
}

fn with_field(base: &str, field: &str, value: Value) {
    let h = h();
    let mut req = if base == "auth" { h.auth(ALICE, PW) } else { json!({"v": 1, "op": "status", "uuns": [ALICE]}) };
    req.as_object_mut().unwrap().insert(field.into(), value);
    assert_eq!(rejected(&h, &req), None, "{req}");
}

cases! { with_field;
    auth_extra_field: "auth", "extra", json!(1);
    auth_extra_password_field: "auth", "password", json!("hunter2");
    auth_extra_null_field: "auth", "x", Value::Null;
    status_extra_field: "status", "extra", json!(true);
    status_extra_uun_field: "status", "uun", json!(ALICE);
    auth_v_string: "auth", "v", json!("1");
    auth_v_float: "auth", "v", json!(1.0);
    auth_v_negative: "auth", "v", json!(-1);
    auth_v_too_big: "auth", "v", json!(u64::from(u32::MAX) + 1);
    auth_v_null: "auth", "v", Value::Null;
    auth_uun_number: "auth", "uun", json!(7);
    auth_uun_array: "auth", "uun", json!([ALICE]);
    auth_scenario_null: "auth", "scenario", Value::Null;
    auth_kid_number: "auth", "kid", json!(1);
    auth_enc_array: "auth", "enc", json!([1, 2]);
    auth_ct_object: "auth", "ct", json!({});
    auth_ts_string: "auth", "ts", json!("1800000000");
    auth_ts_negative: "auth", "ts", json!(-5);
    auth_ts_float: "auth", "ts", json!(1.8e9);
    auth_ts_bool: "auth", "ts", json!(true);
    auth_rid_number: "auth", "rid", json!(0);
    status_uuns_string: "status", "uuns", json!(ALICE);
    status_uuns_numbers: "status", "uuns", json!([1, 2]);
    status_uuns_nested: "status", "uuns", json!([[ALICE]]);
    status_uuns_null: "status", "uuns", Value::Null;
    status_v_string: "status", "v", json!("1");
    status_v_negative: "status", "v", json!(-1);
}

fn bad_op(op: Value) {
    let h = h();
    let mut req = h.auth(ALICE, PW);
    req["op"] = op;
    assert_eq!(rejected(&h, &req), None);
}

cases! { bad_op;
    op_uppercase: json!("AUTH");
    op_unknown: json!("login");
    op_empty: json!("");
    op_null: Value::Null;
    op_number: json!(1);
    op_status_with_auth_fields: json!("status");
    op_padded: json!(" auth");
}

fn bad_frame(frame: &[u8]) {
    let h = h();
    assert_eq!(h.send_raw(frame), None);
    assert!(h.calls().is_empty());
    assert_eq!(h.last()["reason"], "malformed");
}

cases! { bad_frame;
    frame_empty: b"";
    frame_null: b"null";
    frame_array: b"[]";
    frame_number: b"1";
    frame_string: b"\"auth\"";
    frame_empty_object: b"{}";
    frame_no_op: br#"{"v":1,"uuns":[]}"#;
    frame_truncated: br#"{"v":1,"op":"status","uuns":["#;
    frame_trailing_garbage: br#"{"v":1,"op":"status","uuns":[]}x"#;
    frame_two_objects: br#"{"v":1,"op":"status","uuns":[]}{"v":1,"op":"status","uuns":[]}"#;
    frame_single_quotes: b"{'v':1,'op':'status','uuns':[]}";
    frame_comment: br#"{"v":1,"op":"status","uuns":[]/*x*/}"#;
    frame_bom: b"\xef\xbb\xbf{\"v\":1,\"op\":\"status\",\"uuns\":[]}";
    frame_invalid_utf8_in_string: b"{\"v\":1,\"op\":\"status\",\"uuns\":[\"al\xffce\"]}";
    frame_invalid_utf8_outside: b"\xff\xfe";
    frame_lone_surrogate: br#"{"v":1,"op":"status","uuns":["\ud800"]}"#;
    frame_duplicate_op: br#"{"v":1,"op":"status","op":"status","uuns":[]}"#;
    frame_duplicate_v: br#"{"v":1,"v":1,"op":"status","uuns":[]}"#;
    frame_duplicate_uuns: br#"{"v":1,"op":"status","uuns":[],"uuns":[]}"#;
    frame_nul: b"\0";
}

#[test]
fn whitespace_around_json_is_fine() {
    let h = h();
    let r = h.send_raw(b" \n{\"v\":1,\"op\":\"status\",\"uuns\":[]}\n ");
    assert_eq!(result(r), "ok");
}

#[test]
fn field_order_does_not_matter() {
    let h = h();
    let r = h.send_raw(br#"{"uuns":["alice"],"op":"status","v":1}"#);
    assert_eq!(result(r), "ok");
}

#[test]
fn deep_nesting_is_rejected_on_the_connection_stack() {
    // The connection threads have a small stack: deep nesting must be refused, not overflow it.
    let h = h();
    for inner in ["[".repeat(MAX_FRAME - 64), "{\"a\":".repeat(3000)] {
        let frame = format!("{{\"v\":1,\"op\":\"status\",\"uuns\":{inner}");
        let out = std::thread::scope(|s| {
            std::thread::Builder::new()
                .stack_size(THREAD_STACK)
                .spawn_scoped(s, || h.server.handle(DEV, frame.as_bytes(), NOW))
                .unwrap()
                .join()
                .unwrap()
        });
        assert_eq!(out, None);
    }
    assert!(h.calls().is_empty());
}

#[test]
fn deep_nesting_before_tag_is_rejected() {
    let h = h();
    let frame = format!("{{\"x\":{}\"op\":\"status\"}}", "[".repeat(5000));
    assert_eq!(h.send_raw(frame.as_bytes()), None);
}

#[test]
fn huge_number_array_is_rejected() {
    let h = h();
    let body = format!("{{\"v\":1,\"op\":\"status\",\"uuns\":[{}0]}}", "0,".repeat(100_000));
    assert_eq!(h.send_raw(body.as_bytes()), None);
    assert!(h.calls().is_empty());
}

#[test]
fn huge_uun_array_is_bad_request() {
    let h = h();
    let uuns = vec!["a"; 50_000];
    let r = rejected(&h, &json!({"v": 1, "op": "status", "uuns": uuns}));
    assert_eq!(r.unwrap(), json!({"v": 1, "result": "error"}));
}

#[test]
fn huge_string_field_is_bad_request() {
    let h = h();
    let mut req = h.auth(ALICE, PW);
    req["uun"] = json!("a".repeat(100_000));
    assert_eq!(result(rejected(&h, &req)), "error");
}

fn version(op: &str, v: u64) {
    let h = h();
    let mut req = if op == "auth" { h.auth(ALICE, PW) } else { json!({"op": "status", "uuns": [ALICE]}) };
    req["v"] = json!(v);
    let r = rejected(&h, &req);
    assert_eq!(r.unwrap(), json!({"v": 1, "result": "error"}));
    assert_eq!(h.last()["reason"], "bad_request");
}

cases! { version;
    auth_v0: "auth", 0; auth_v2: "auth", 2; auth_vmax: "auth", u64::from(u32::MAX);
    status_v0: "status", 0; status_v2: "status", 2; status_vmax: "status", u64::from(u32::MAX);
}

// ---------- UUN and scenario rules ----------

#[test]
fn valid_uun_rule() {
    for ok in ["a", "z", "0", "alice", "s1234567", "abcdefghijklmnopqrst", "00000000000000000000"] {
        assert!(valid_uun(ok), "{ok}");
    }
}

fn uun_refused(uun: &str) {
    assert!(!valid_uun(uun));
    let h = h();
    let r = rejected(&h, &h.auth(uun, PW));
    assert_eq!(r.unwrap(), json!({"v": 1, "result": "error"}));
    assert_eq!(h.last()["uun"], "-", "an invalid UUN is never logged");
    let r = rejected(&h, &json!({"v": 1, "op": "status", "uuns": [ALICE, uun]}));
    assert_eq!(r.unwrap(), json!({"v": 1, "result": "error"}));
}

cases! { uun_refused;
    uun_empty: "";
    uun_21_chars: "abcdefghijklmnopqrstu";
    uun_upper: "Alice";
    uun_space: "al ice";
    uun_dash: "al-ice";
    uun_underscore: "al_ice";
    uun_dot: "al.ice";
    uun_comma_dn_injection: "alice,ou=admins";
    uun_equals: "uid=alice";
    uun_star_filter: "*";
    uun_paren: "a)(uid=*";
    uun_backslash: "a\\b";
    uun_nul: "a\0";
    uun_newline: "alice\n";
    uun_unicode: "alicé";
    uun_fullwidth: "ａｌｉｃｅ";
    uun_quote: "a\"b";
}

fn scenario(s: &str, ok: bool) {
    let h = h();
    let mut sealed = seal_for(ALICE, PW);
    sealed.scenario = s;
    let r = h.send(&h.request(&sealed));
    assert_eq!(result(r) == "ok", ok, "{s}");
    assert_eq!(h.calls().is_empty(), !ok);
}

cases! { scenario;
    scenario_logon: "logon", true;
    scenario_unlock: "unlock", true;
    scenario_upper: "Logon", false;
    scenario_empty: "", false;
    scenario_padded: "unlock ", false;
    scenario_credui: "credui", false;
    scenario_change: "change_password", false;
}

// ---------- timestamps ----------

fn skew(ts: u64, ok: bool) {
    let h = h();
    let mut s = seal_for(ALICE, PW);
    s.ts = ts;
    let r = h.send(&h.request(&s));
    if ok {
        assert_eq!(result(r), "ok");
    } else {
        assert_eq!(r.unwrap(), json!({"v": 1, "result": "error"}));
        assert_eq!(h.last()["reason"], "stale_or_future");
        assert!(h.calls().is_empty());
    }
}

cases! { skew;
    ts_now: NOW, true;
    ts_at_max_past: NOW - SKEW, true;
    ts_at_max_future: NOW + SKEW, true;
    ts_one_past_max_past: NOW - SKEW - 1, false;
    ts_one_past_max_future: NOW + SKEW + 1, false;
    ts_zero: 0, false;
    ts_max: u64::MAX, false;
}

#[test]
fn zero_skew_accepts_only_now() {
    let dir = FakeDirectory::default().with_user(ALICE, PW, USER);
    let (k, pk) = key("k1");
    let server = Server::new(vec![k], dir.boxed(), 0);
    for (ts, want) in [(NOW, "ok"), (NOW + 1, "error"), (NOW - 1, "error")] {
        let rid = fresh_rid();
        let (enc, ct) = seal::seal(&pk, PW, &seal::aad("k1", ALICE, "logon", ts, &rid)).unwrap();
        let req = json!({"v":1,"op":"auth","uun":ALICE,"scenario":"logon","kid":"k1","enc":B64.encode(enc),
                         "ct":B64.encode(ct),"ts":ts,"rid":rid});
        let r: Value =
            serde_json::from_slice(&server.handle(DEV, &serde_json::to_vec(&req).unwrap(), NOW).unwrap()).unwrap();
        assert_eq!(r["result"], want, "ts={ts}");
    }
}

// ---------- encodings ----------

fn field_value(field: &str, value: &str, reason: &str) {
    let h = h();
    let mut req = h.auth(ALICE, PW);
    req[field] = json!(value);
    let r = rejected(&h, &req);
    assert_eq!(r.unwrap(), json!({"v": 1, "result": "error"}));
    assert_eq!(h.last()["reason"], reason);
}

cases! { field_value;
    enc_not_base64: "enc", "not base64!", "bad_encoding";
    ct_not_base64: "ct", "%%%%", "bad_encoding";
    rid_not_base64: "rid", "????????????????????????", "bad_encoding";
    enc_urlsafe_alphabet: "enc", "-_-_", "bad_encoding";
    ct_missing_padding: "ct", "YWJj ZA", "bad_encoding";
    enc_empty: "enc", "", "unseal";
    ct_empty: "ct", "", "unseal";
    enc_wrong_length: "enc", "AAAA", "unseal";
    rid_empty: "rid", "", "bad_rid";
    rid_15_bytes: "rid", "AAAAAAAAAAAAAAAAAAAA", "bad_rid";
    rid_17_bytes: "rid", "AAAAAAAAAAAAAAAAAAAAAAA=", "bad_rid";
    rid_32_bytes: "rid", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "bad_rid";
}

// ---------- replay ----------

#[test]
fn replay_same_request_refused() {
    let h = h();
    let req = h.auth(ALICE, PW);
    assert_eq!(result(h.send(&req)), "ok");
    assert_eq!(h.send(&req).unwrap(), json!({"v": 1, "result": "error"}));
    assert_eq!(h.last()["reason"], "replay");
    assert_eq!(h.calls().len(), 1);
}

#[test]
fn replay_rid_with_other_content_refused() {
    let h = h();
    let first = seal_for(ALICE, PW);
    let rid = first.rid.clone();
    assert_eq!(result(h.send(&h.request(&first))), "ok");
    let mut second = seal_for(ALICE, PW);
    second.rid = rid;
    second.scenario = "unlock";
    assert_eq!(result(h.send(&h.request(&second))), "error");
    assert_eq!(h.calls().len(), 1);
}

#[test]
fn rid_consumed_even_when_unseal_fails() {
    let h = h();
    let s = seal_for(ALICE, PW);
    let mut bad = h.request(&s);
    bad["kid"] = json!("k2"); // sealed for k1: fails to open
    assert_eq!(result(h.send(&bad)), "error");
    assert_eq!(h.last()["reason"], "unseal");
    assert_eq!(result(h.send(&h.request(&s))), "error");
    assert_eq!(h.last()["reason"], "replay");
    assert!(h.calls().is_empty());
}

#[test]
fn replay_window_covers_whole_timestamp_window() {
    // Accepted at NOW with ts at the future edge; a replay is refused for as long as the ts is acceptable.
    let h = h();
    let mut s = seal_for(ALICE, PW);
    s.ts = NOW + SKEW;
    let req = h.request(&s);
    assert_eq!(result(h.send_at(&req, NOW)), "ok");
    for later in [NOW + 1, NOW + SKEW, NOW + 2 * SKEW] {
        assert_eq!(result(h.send_at(&req, later)), "error");
        assert_eq!(h.last()["reason"], "replay", "at {later}");
    }
    // Once the rid has left the cache, the timestamp is stale anyway.
    assert_eq!(result(h.send_at(&req, NOW + 2 * SKEW + 1)), "error");
    assert_eq!(h.last()["reason"], "stale_or_future");
    assert_eq!(h.calls().len(), 1);
}

#[test]
fn replay_cache_expires_after_horizon() {
    let h = h();
    let s = seal_for(ALICE, PW);
    let rid: [u8; 16] = B64.decode(&s.rid).unwrap().try_into().unwrap();
    h.send_at(&h.request(&s), NOW);
    assert!(lock_rids(&h).contains_key(&rid));
    // Any later request prunes entries older than 2 * skew.
    h.send_at(&h.auth_at(NOW + 2 * SKEW), NOW + 2 * SKEW);
    assert!(lock_rids(&h).contains_key(&rid), "kept at exactly the horizon");
    h.send_at(&h.auth_at(NOW + 2 * SKEW + 1), NOW + 2 * SKEW + 1);
    assert!(!lock_rids(&h).contains_key(&rid), "pruned past the horizon");
    assert_eq!(lock_rids(&h).len(), 2);
}

fn lock_rids(h: &H) -> std::sync::MutexGuard<'_, HashMap<[u8; 16], u64>> {
    h.server.seen_rids.lock().unwrap()
}

#[test]
fn distinct_rids_both_accepted() {
    let h = h();
    assert_eq!(result(h.send(&h.auth(ALICE, PW))), "ok");
    assert_eq!(result(h.send(&h.auth(ALICE, PW))), "ok");
}

// ---------- keys and AAD binding ----------

#[test]
fn unknown_kid() {
    let h = h();
    let mut s = seal_for(ALICE, PW);
    s.kid = "k3";
    // Sealed to k1's public key but naming k3 (in the AAD too): no such key.
    let aad = seal::aad("k3", ALICE, "logon", NOW, &s.rid);
    let (enc, ct) = seal::seal(&h.pk1, PW, &aad).unwrap();
    let req = json!({"v":1,"op":"auth","uun":ALICE,"scenario":"logon","kid":"k3","enc":B64.encode(enc),
                     "ct":B64.encode(ct),"ts":NOW,"rid":s.rid});
    assert_eq!(rejected(&h, &req).unwrap(), json!({"v": 1, "result": "error"}));
    assert_eq!(h.last()["reason"], "unknown_kid");
}

#[test]
fn rotation_both_keys_work() {
    let h = h();
    for kid in ["k1", "k2"] {
        let mut s = seal_for(ALICE, PW);
        s.kid = kid;
        assert_eq!(result(h.send(&h.request(&s))), "ok", "{kid}");
    }
    assert_eq!(h.calls().len(), 2);
}

#[test]
fn sealed_to_one_key_named_as_other() {
    let h = h();
    let mut s = seal_for(ALICE, PW);
    s.kid = "k2";
    // AAD says k2, ciphertext sealed to k1's public key.
    let aad = seal::aad("k2", ALICE, "logon", NOW, &s.rid);
    let (enc, ct) = seal::seal(&h.pk1, PW, &aad).unwrap();
    let req = json!({"v":1,"op":"auth","uun":ALICE,"scenario":"logon","kid":"k2","enc":B64.encode(enc),
                     "ct":B64.encode(ct),"ts":NOW,"rid":s.rid});
    assert_eq!(result(rejected(&h, &req)), "error");
    assert_eq!(h.last()["reason"], "unseal");
}

#[test]
fn no_keys_at_all() {
    let dir = FakeDirectory::default();
    let server = Server::new(Vec::new(), dir.boxed(), SKEW);
    let (_, pk) = key("k1");
    let rid = fresh_rid();
    let (enc, ct) = seal::seal(&pk, PW, &seal::aad("k1", ALICE, "logon", NOW, &rid)).unwrap();
    let req = json!({"v":1,"op":"auth","uun":ALICE,"scenario":"logon","kid":"k1","enc":B64.encode(enc),
                     "ct":B64.encode(ct),"ts":NOW,"rid":rid});
    let r = server.handle(DEV, &serde_json::to_vec(&req).unwrap(), NOW).unwrap();
    assert_eq!(serde_json::from_slice::<Value>(&r).unwrap()["result"], "error");
    assert!(dir.calls().is_empty());
}

/// Seal for one (kid, uun, scenario, ts, rid), then send the request with `field` changed.
fn aad_binding(field: &str, value: Value) {
    let h = h();
    let mut req = h.auth(ALICE, PW);
    req[field] = value;
    let r = rejected(&h, &req);
    assert_eq!(r.unwrap(), json!({"v": 1, "result": "error"}));
    assert_eq!(h.last()["reason"], "unseal");
}

cases! { aad_binding;
    aad_binds_uun: "uun", json!("bob");
    aad_binds_scenario: "scenario", json!("unlock");
    aad_binds_ts: "ts", json!(NOW + 1);
    aad_binds_ts_past: "ts", json!(NOW - 1);
    aad_binds_rid: "rid", json!(fresh_rid());
    aad_binds_kid: "kid", json!("k2");
}

fn swap_part(field: &str) {
    // enc/ct from one valid request, everything else from another.
    let h = h();
    let a = h.auth(ALICE, PW);
    let mut b = h.auth(ALICE, PW);
    b[field] = a[field].clone();
    assert_eq!(result(rejected(&h, &b)), "error");
}

cases! { swap_part;
    swapped_enc: "enc";
    swapped_ct: "ct";
}

#[test]
fn tampered_ciphertext_every_byte() {
    let h = h();
    for i in 0..PW.len() + seal::TAG_LEN {
        let mut req = h.auth(ALICE, PW);
        let mut ct = B64.decode(req["ct"].as_str().unwrap()).unwrap();
        ct[i] ^= 0x80;
        req["ct"] = json!(B64.encode(&ct));
        assert_eq!(result(h.send_from(&format!("dev-{i}"), &req)), "error"); // one device would be rate limited
        assert_eq!(h.last()["reason"], "unseal");
    }
    assert!(h.calls().is_empty());
}

#[test]
fn tampered_enc_refused() {
    let h = h();
    for i in [0, 1, 32, 64] {
        let mut req = h.auth(ALICE, PW);
        let mut enc = B64.decode(req["enc"].as_str().unwrap()).unwrap();
        enc[i] ^= 0x01;
        req["enc"] = json!(B64.encode(&enc));
        assert_eq!(result(h.send(&req)), "error");
    }
    assert!(h.calls().is_empty());
}

#[test]
fn ciphertext_from_other_user_cannot_be_moved() {
    let h = h();
    let bob = h.auth("bob", b"bobs password");
    let mut moved = bob.clone();
    moved["uun"] = json!(ALICE);
    assert_eq!(result(rejected(&h, &moved)), "error");
}

// ---------- throttling ----------

#[test]
fn failures_throttle_the_user_even_with_right_password() {
    let h = h();
    for _ in 0..FAIL_LIMIT {
        assert_eq!(result(h.send(&h.auth(ALICE, b"wrong"))), "invalid");
    }
    let calls = h.calls().len();
    assert_eq!(h.send(&h.auth(ALICE, PW)).unwrap(), json!({"v": 1, "result": "throttled"}));
    assert_eq!(h.last()["reason"], "user_failures");
    assert_eq!(h.calls().len(), calls, "a throttled user never reaches the directory");
}

#[test]
fn one_failure_below_limit_still_allowed() {
    let h = h();
    for _ in 0..FAIL_LIMIT - 1 {
        h.send(&h.auth(ALICE, b"wrong"));
    }
    assert_eq!(result(h.send(&h.auth(ALICE, PW))), "ok");
}

#[test]
fn failures_are_per_user() {
    let h = h();
    for _ in 0..FAIL_LIMIT {
        h.send(&h.auth(ALICE, b"wrong"));
    }
    assert_eq!(result(h.send(&h.auth("root1", b"admin-pass"))), "ok");
}

#[test]
fn success_does_not_count_as_failure() {
    let h = h();
    for _ in 0..FAIL_LIMIT + 2 {
        assert_eq!(result(h.send(&h.auth(ALICE, PW))), "ok");
    }
}

fn not_counted(f: Failure) {
    let h = h();
    h.dir.set_auth(Err(f));
    for _ in 0..=FAIL_LIMIT {
        assert_ne!(result(h.send(&h.auth(ALICE, PW))), "throttled");
    }
}

cases! { not_counted;
    denied_not_counted: Failure::Denied;
    unavailable_not_counted: Failure::Unavailable;
    error_not_counted: Failure::Error("x");
}

#[test]
fn rejected_requests_not_counted_as_failures() {
    let h = h();
    for _ in 0..=FAIL_LIMIT {
        let mut req = h.auth(ALICE, PW);
        req["uun"] = json!("bob"); // unseal failure: no directory, no failure recorded
        h.send(&req);
    }
    assert_eq!(result(h.send(&h.auth(ALICE, PW))), "ok");
}

#[test]
fn throttled_user_is_logged_with_uun() {
    let h = h();
    for _ in 0..FAIL_LIMIT {
        h.send(&h.auth(ALICE, b"wrong"));
    }
    h.send(&h.auth(ALICE, PW));
    let l = h.last();
    assert_eq!((l["uun"].as_str(), l["result"].as_str()), (Some(ALICE), Some("throttled")));
}

#[test]
fn failures_expire_after_window() {
    let h = h();
    let Some(old) = Instant::now().checked_sub(FAIL_WINDOW + Duration::from_secs(1)) else {
        return;
    };
    h.server.failures.lock().unwrap().insert(ALICE.into(), VecDeque::from(vec![old; FAIL_LIMIT]));
    assert_eq!(result(h.send(&h.auth(ALICE, PW))), "ok");
}

#[test]
fn failures_inside_window_count() {
    let h = h();
    let Some(recent) = Instant::now().checked_sub(FAIL_WINDOW.saturating_sub(Duration::from_secs(5))) else {
        return;
    };
    h.server.failures.lock().unwrap().insert(ALICE.into(), VecDeque::from(vec![recent; FAIL_LIMIT]));
    assert_eq!(result(h.send(&h.auth(ALICE, PW))), "throttled");
}

fn status_req() -> Value {
    json!({"v": 1, "op": "status", "uuns": [ALICE]})
}

#[test]
fn device_rate_limit() {
    let h = h();
    for _ in 0..DEVICE_LIMIT {
        assert_eq!(result(h.send(&status_req())), "ok");
    }
    assert_eq!(h.send(&status_req()).unwrap(), json!({"v": 1, "result": "throttled"}));
    assert_eq!(h.last()["reason"], "device_rate");
    let calls = h.calls().len();
    assert_eq!(result(h.send(&h.auth(ALICE, PW))), "throttled");
    assert_eq!(h.calls().len(), calls);
    // Another device is not affected.
    assert_eq!(result(h.send_from("laptop-02", &status_req())), "ok");
}

#[test]
fn device_rate_counts_auth_and_status_together() {
    let h = h();
    for i in 0..DEVICE_LIMIT {
        let r = if i % 2 == 0 { h.send(&status_req()) } else { h.send(&h.auth(ALICE, PW)) };
        assert_eq!(result(r), "ok");
    }
    assert_eq!(result(h.send(&h.auth(ALICE, PW))), "throttled");
}

#[test]
fn bad_requests_do_not_use_device_budget() {
    let h = h();
    for _ in 0..DEVICE_LIMIT * 2 {
        h.send(&json!({"v": 2, "op": "status", "uuns": []}));
    }
    assert_eq!(result(h.send(&status_req())), "ok");
}

#[test]
fn device_window_expires() {
    let h = h();
    let Some(old) = Instant::now().checked_sub(DEVICE_WINDOW + Duration::from_secs(1)) else {
        return;
    };
    h.server.device_rate.lock().unwrap().insert(DEV.into(), VecDeque::from(vec![old; DEVICE_LIMIT * 2]));
    assert_eq!(result(h.send(&status_req())), "ok");
}

#[test]
fn over_records_and_limits() {
    let w = Window::default();
    for _ in 0..3 {
        assert!(!over(&w, "k", 3, Duration::from_secs(60), true));
    }
    assert!(over(&w, "k", 3, Duration::from_secs(60), true));
    assert!(over(&w, "k", 3, Duration::from_secs(60), false));
    assert!(!over(&w, "other", 3, Duration::from_secs(60), false));
}

#[test]
fn over_check_without_record_leaves_nothing() {
    let w = Window::default();
    for i in 0..100 {
        assert!(!over(&w, &format!("u{i}"), 5, Duration::from_secs(60), false));
    }
    assert!(w.lock().unwrap().is_empty());
}

#[test]
fn over_sweeps_idle_keys() {
    let w = Window::default();
    let Some(old) = Instant::now().checked_sub(Duration::from_secs(120)) else {
        return;
    };
    {
        let mut m = w.lock().unwrap();
        for i in 0..WINDOW_SWEEP {
            m.insert(format!("old{i}"), VecDeque::from(vec![old]));
        }
        m.insert("live".into(), VecDeque::from(vec![Instant::now()]));
    }
    assert!(!over(&w, "new", 5, Duration::from_secs(60), true));
    let m = w.lock().unwrap();
    assert_eq!(m.len(), 2, "only the live and the new key are left");
    assert!(m.contains_key("live") && m.contains_key("new"));
}

#[test]
fn over_fails_closed_when_poisoned() {
    let w = Window::default();
    let _ = std::panic::catch_unwind(|| {
        let _g = w.lock().unwrap();
        panic!("poison");
    });
    assert!(over(&w, "k", 100, Duration::from_secs(60), false));
}

// ---------- status ----------

#[test]
fn status_ok_subsets_sorted_deduped() {
    let h = h();
    let r = h.send(&json!({"v": 1, "op": "status", "uuns": ["zed", "root1", ALICE, "root1", ALICE]})).unwrap();
    assert_eq!(r, json!({"v": 1, "result": "ok", "users": [ALICE, "root1"], "admins": ["root1"]}));
    assert_eq!(h.calls(), vec![Call::Status(vec![ALICE.into(), "root1".into(), "zed".into()])]);
    assert_eq!(h.last()["uuns"], 3);
}

#[test]
fn status_empty_list() {
    let h = h();
    let r = h.send(&json!({"v": 1, "op": "status", "uuns": []})).unwrap();
    assert_eq!(r, json!({"v": 1, "result": "ok", "users": [], "admins": []}));
}

#[test]
fn status_max_uuns_accepted() {
    let h = h();
    let uuns: Vec<String> = (0..MAX_STATUS_UUNS).map(|i| format!("u{i}")).collect();
    assert_eq!(result(h.send(&json!({"v": 1, "op": "status", "uuns": uuns}))), "ok");
}

#[test]
fn status_max_uuns_counted_before_dedupe() {
    let h = h();
    let uuns = vec![ALICE; MAX_STATUS_UUNS + 1];
    assert_eq!(result(rejected(&h, &json!({"v": 1, "op": "status", "uuns": uuns}))), "error");
}

#[test]
fn status_one_over_max_refused() {
    let h = h();
    let uuns: Vec<String> = (0..=MAX_STATUS_UUNS).map(|i| format!("u{i}")).collect();
    let r = rejected(&h, &json!({"v": 1, "op": "status", "uuns": uuns}));
    assert_eq!(r.unwrap(), json!({"v": 1, "result": "error"}));
}

#[test]
fn status_reply_only_contains_requested_uuns() {
    let h = h();
    // A directory that (wrongly) knows more: the reply is still built from the request only.
    h.dir.set_status(Ok(vec![ADMIN]));
    let r = h.send(&json!({"v": 1, "op": "status", "uuns": ["bob"]})).unwrap();
    assert_eq!(r, json!({"v": 1, "result": "ok", "users": ["bob"], "admins": ["bob"]}));
}

fn status_outcome(out: Result<Vec<Membership>, Failure>, expected: &str) {
    let h = h();
    h.dir.set_status(out);
    let r = h.send(&json!({"v": 1, "op": "status", "uuns": [ALICE, "bob"]})).unwrap();
    assert_eq!(r, json!({"v": 1, "result": expected}));
}

cases! { status_outcome;
    status_partial_read: Ok(vec![USER]), "error";
    status_too_many_results: Ok(vec![USER, USER, USER]), "error";
    status_empty_result: Ok(vec![]), "error";
    status_unavailable: Err(Failure::Unavailable), "unavailable";
    status_error: Err(Failure::Error("service_bind")), "error";
    status_invalid_is_error: Err(Failure::Invalid), "error";
    status_denied_is_error: Err(Failure::Denied), "error";
}

#[test]
fn status_error_reasons_logged() {
    let h = h();
    h.dir.set_status(Ok(vec![]));
    h.send(&status_req());
    assert_eq!(h.last()["reason"], "partial_read");
    h.dir.set_status(Err(Failure::Denied));
    h.send(&status_req());
    assert_eq!(h.last()["reason"], "directory_refused");
}

// ---------- framing ----------

fn read(bytes: &[u8]) -> Result<Vec<u8>, ()> {
    read_frame(&mut std::io::Cursor::new(bytes))
}

#[test]
fn frame_round_trip() {
    let mut f = 5u32.to_be_bytes().to_vec();
    f.extend_from_slice(b"hello trailing");
    assert_eq!(read(&f).unwrap(), b"hello");
}

#[test]
fn frame_max_size() {
    let mut f = u32::try_from(MAX_FRAME).unwrap().to_be_bytes().to_vec();
    f.extend(vec![b'x'; MAX_FRAME]);
    assert_eq!(read(&f).unwrap().len(), MAX_FRAME);
}

fn frame_refused(bytes: &[u8]) {
    assert!(read(bytes).is_err());
}

cases! { frame_refused;
    frame_zero_length: &[0, 0, 0, 0];
    frame_over_max: &(u32::try_from(MAX_FRAME).unwrap() + 1).to_be_bytes();
    frame_huge: &[0xff, 0xff, 0xff, 0xff];
    frame_short_header: &[0, 0, 1];
    frame_no_header: &[];
    frame_short_body: &[0, 0, 0, 5, b'a', b'b'];
}

// ---------- per-address slots ----------

#[test]
fn ip_slots_cap_and_release() {
    let map = PerIp::default();
    let ip: IpAddr = "192.0.2.1".parse().unwrap();
    let other: IpAddr = "2001:db8::1".parse().unwrap();
    let mut held: Vec<_> = (0..MAX_PER_IP).map(|_| IpSlot::take(&map, ip).unwrap()).collect();
    assert!(IpSlot::take(&map, ip).is_none());
    let o = IpSlot::take(&map, other).unwrap();
    held.pop();
    let again = IpSlot::take(&map, ip).unwrap();
    assert!(IpSlot::take(&map, ip).is_none());
    drop((held, again, o));
    assert!(map.lock().unwrap().is_empty(), "released slots leave nothing behind");
}

#[test]
fn ip_slots_fail_closed_when_poisoned() {
    let map = PerIp::default();
    let m2 = map.clone();
    let _ = std::thread::spawn(move || {
        let _g = m2.lock().unwrap();
        panic!("poison");
    })
    .join();
    assert!(IpSlot::take(&map, "192.0.2.1".parse().unwrap()).is_none());
}

// ---------- device names ----------

fn device_name_rule(cn: &str, ok: bool) {
    let leaf = pki().device_ca.device(cn, 99);
    assert_eq!(cert_device_name(leaf.der.as_ref()), ok.then(|| cn.to_string()), "{cn:?}");
}

cases! { device_name_rule;
    cn_simple: "laptop-01", true;
    cn_digits: "1234", true;
    cn_one_char: "a", true;
    cn_63_chars: &"a".repeat(63), true;
    cn_64_chars: &"a".repeat(64), false;
    cn_upper: "Laptop-01", false;
    cn_dot: "laptop.example.org", false;
    cn_underscore: "lap_top", false;
    cn_space: "lap top", false;
    cn_quote: "lap\"top", false;
    cn_unicode: "läptop", false;
    cn_empty: "", false;
}

#[test]
fn cert_without_cn_has_no_name() {
    let leaf = pki().device_ca.leaf(None, &["laptop-01"], 98, true);
    assert_eq!(cert_device_name(leaf.der.as_ref()), None);
}

#[test]
fn garbage_cert_has_no_name() {
    assert_eq!(cert_device_name(b""), None);
    assert_eq!(cert_device_name(&[0x30, 0x03, 0x02, 0x01, 0x01]), None);
}

#[test]
fn hostile_device_name_never_logged() {
    let h = h();
    for dev in ["Laptop", "a\"b", "x\ny", "", &"a".repeat(64)] {
        h.send_from(dev, &status_req());
        assert_eq!(h.last()["device"], "?");
    }
}

#[test]
fn now_secs_is_wall_clock() {
    let t = now_secs();
    assert!(t > 1_700_000_000 && t < 4_000_000_000);
}

// ---------- connection I/O: Deadline and handshake driven by a fake stream ----------

use std::io::ErrorKind;
use std::net::{TcpListener, TcpStream};

#[derive(Clone, Copy)]
enum WriteKind {
    Ok,
    Zero,
    Err,
}

/// A `DeadlineSock` whose reads, writes and deadline-setting are all scripted, so the error/timeout branches
/// of `Deadline` and `handshake` run without a real socket.
struct FakeSock {
    to_read: Vec<u8>,
    read_pos: usize,
    writes: WriteKind,
    deadline_err: bool,
}

impl FakeSock {
    fn feeding(to_read: Vec<u8>) -> FakeSock {
        FakeSock { to_read, read_pos: 0, writes: WriteKind::Ok, deadline_err: false }
    }
}

impl Read for FakeSock {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = buf.len().min(self.to_read.len() - self.read_pos);
        buf[..n].copy_from_slice(&self.to_read[self.read_pos..self.read_pos + n]);
        self.read_pos += n;
        Ok(n)
    }
}

impl Write for FakeSock {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self.writes {
            WriteKind::Ok => Ok(buf.len()),
            WriteKind::Zero => Ok(0),
            WriteKind::Err => Err(ErrorKind::BrokenPipe.into()),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl DeadlineSock for FakeSock {
    fn set_read_deadline(&mut self, _left: Duration) -> std::io::Result<()> {
        if self.deadline_err {
            Err(ErrorKind::InvalidInput.into())
        } else {
            Ok(())
        }
    }
}

#[test]
fn deadline_reads_through() {
    let mut sock = FakeSock::feeding(b"hello".to_vec());
    let mut d = Deadline { sock: &mut sock, until: Instant::now() + Duration::from_secs(5) };
    let mut buf = [0u8; 8];
    assert_eq!(d.read(&mut buf).unwrap(), 5);
    assert_eq!(&buf[..5], b"hello");
}

#[test]
fn deadline_already_passed_times_out() {
    let mut sock = FakeSock::feeding(b"hello".to_vec());
    let mut d = Deadline { sock: &mut sock, until: Instant::now() };
    assert_eq!(d.read(&mut [0u8; 8]).unwrap_err().kind(), ErrorKind::TimedOut);
}

#[test]
fn deadline_set_timeout_error_propagates() {
    let mut sock = FakeSock::feeding(b"hello".to_vec());
    sock.deadline_err = true;
    let mut d = Deadline { sock: &mut sock, until: Instant::now() + Duration::from_secs(5) };
    assert!(d.read(&mut [0u8; 8]).is_err());
}

fn server_cfg() -> std::sync::Arc<rustls::ServerConfig> {
    let dir = crate::tests::support::TempDir::new();
    let f = pki().files(&dir, &pki().crl());
    crate::tls::server_config(&f.cert, &f.key, &f.ca, &f.crl).unwrap()
}

fn client_hello() -> Vec<u8> {
    let cfg = crate::tests::support::client(Some(&pki().device), false);
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut c = rustls::ClientConnection::new(cfg, name).unwrap();
    let mut buf = Vec::new();
    c.write_tls(&mut buf).unwrap();
    buf
}

fn drive_handshake(sock: FakeSock, deadline_in: Duration) -> Result<(), ()> {
    let mut conn = rustls::ServerConnection::new(server_cfg()).unwrap();
    let mut sock = sock;
    handshake(&mut conn, &mut sock, Instant::now() + deadline_in)
}

#[test]
fn handshake_write_error_fails() {
    let mut sock = FakeSock::feeding(client_hello());
    sock.writes = WriteKind::Err;
    assert!(drive_handshake(sock, Duration::from_secs(5)).is_err());
}

#[test]
fn handshake_write_zero_fails() {
    let mut sock = FakeSock::feeding(client_hello());
    sock.writes = WriteKind::Zero;
    assert!(drive_handshake(sock, Duration::from_secs(5)).is_err());
}

#[test]
fn handshake_eof_fails() {
    assert!(drive_handshake(FakeSock::feeding(Vec::new()), Duration::from_secs(5)).is_err());
}

#[test]
fn handshake_deadline_already_passed_fails() {
    assert!(drive_handshake(FakeSock::feeding(client_hello()), Duration::ZERO).is_err());
}

#[test]
fn handshake_set_deadline_error_fails() {
    let mut sock = FakeSock::feeding(client_hello());
    sock.deadline_err = true;
    assert!(drive_handshake(sock, Duration::from_secs(5)).is_err());
}

#[test]
fn handshake_garbage_fails() {
    assert!(drive_handshake(FakeSock::feeding(vec![0xff; 300]), Duration::from_secs(5)).is_err());
}

// ---------- poisoned replay cache ----------

#[test]
fn seen_rids_poisoned_is_internal_error() {
    let h = h();
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _g = h.server.seen_rids.lock().unwrap();
        panic!("poison the replay cache");
    }));
    let r = h.send(&h.auth(ALICE, PW));
    assert_eq!(result(r), "error");
    assert_eq!(h.last()["reason"], "internal");
    assert!(h.calls().is_empty(), "a poisoned replay cache never reaches the directory");
}

// ---------- keepalive ----------

#[test]
fn keepalive_is_enabled_on_accepted_sockets() {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let s = TcpStream::connect(l.local_addr().unwrap()).unwrap();
    crate::hardening::enable_keepalive(&s);
    assert!(crate::hardening::keepalive_enabled(&s), "SO_KEEPALIVE should be set");
}

#[test]
fn cert_cn_with_invalid_utf8_is_rejected_not_panicked() {
    // A device CA could issue a certificate whose CN bytes are not valid UTF-8; the server must reject it
    // (return None -> handshake_refused), never panic. We patch a real cert's CN value to 0xFF bytes.
    let leaf = pki().device_ca.device("zzdevicezz", 4242);
    let mut der = leaf.der.as_ref().to_vec();
    let cn = b"zzdevicezz";
    let pos = der.windows(cn.len()).position(|w| w == cn).expect("CN is present in the DER");
    for b in &mut der[pos..pos + cn.len()] {
        *b = 0xff; // invalid UTF-8, same length so the DER stays structurally valid
    }
    assert_eq!(cert_device_name(&der), None);
}
