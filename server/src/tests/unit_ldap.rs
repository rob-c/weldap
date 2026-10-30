//! BER and the LDAP exchanges, on scripted byte streams.

use super::*;
use crate::cases;
use crate::tests::support::{
    ber_len, bind_response, msg, parse, result_op, search_done, search_entry, tlv as t, Mock, MockState,
};

fn secret(b: &[u8]) -> SecretBuf {
    let mut s = SecretBuf::with_capacity(b.len());
    s.extend_from_slice(b).unwrap();
    s
}

fn ldap(replies: &[Vec<u8>]) -> (Ldap<Mock>, Mock) {
    let m = Mock::replying(replies.concat());
    (Ldap::new(m.clone()), m)
}

// ---------- lengths ----------

fn length(n: usize, want: &[u8]) {
    assert_eq!(len_bytes(n), want);
    assert_eq!(ber_len(n), want, "independent encoder agrees");
    // And it reads back.
    let mut buf = vec![0x04];
    buf.extend_from_slice(want);
    buf.extend(vec![0u8; n]);
    let (tag, content, rest) = take(&buf).unwrap();
    assert_eq!((tag, content.len(), rest.len()), (0x04, n, 0));
}

cases! { length;
    len_0: 0, &[0];
    len_1: 1, &[1];
    len_127: 127, &[0x7f];
    len_128: 128, &[0x81, 0x80];
    len_255: 255, &[0x81, 0xff];
    len_256: 256, &[0x82, 0x01, 0x00];
    len_300: 300, &[0x82, 0x01, 0x2c];
    len_65535: 65535, &[0x82, 0xff, 0xff];
    len_65536: 65536, &[0x83, 0x01, 0x00, 0x00];
    len_max_message: MAX_MESSAGE, &[0x83, 0x04, 0x00, 0x00];
}

#[test]
fn len_four_bytes() {
    assert_eq!(len_bytes(0x0100_0000), vec![0x84, 1, 0, 0, 0]);
    assert_eq!(len_bytes(0xffff_ffff), vec![0x84, 0xff, 0xff, 0xff, 0xff]);
}

#[test]
fn tlv_and_int() {
    assert_eq!(tlv(0x04, b"hi"), vec![0x04, 2, b'h', b'i']);
    assert_eq!(tlv(0x30, b""), vec![0x30, 0]);
    assert_eq!(int(0x02, 3), vec![0x02, 1, 3]);
    assert_eq!(int(0x02, 127), vec![0x02, 1, 127]);
    assert_eq!(int(0x02, 0xff), vec![0x02, 1, 0x7f], "never a negative integer");
}

// ---------- take ----------

#[test]
fn take_splits() {
    let (tag, c, r) = take(&[0x04, 0x02, b'h', b'i', 0x01]).unwrap();
    assert_eq!((tag, c, r), (0x04, &b"hi"[..], &[0x01][..]));
}

#[test]
fn take_empty_content() {
    assert_eq!(take(&[0x05, 0x00]).unwrap(), (0x05, &[][..], &[][..]));
}

fn take_err(buf: &[u8]) {
    assert_eq!(take(buf), Err(LdapError::Protocol));
}

cases! { take_err;
    take_nothing: &[];
    take_tag_only: &[0x04];
    take_short_content: &[0x04, 0x05, 1, 2];
    take_long_form_zero_count: &[0x04, 0x80, 0x00];
    take_long_form_five_bytes: &[0x04, 0x85, 0, 0, 0, 0, 1, 0];
    take_long_form_missing_bytes: &[0x04, 0x82, 0x01];
    take_long_form_beyond_buffer: &[0x04, 0x82, 0x01, 0x00, 1, 2, 3];
    take_long_form_huge: &[0x04, 0x84, 0xff, 0xff, 0xff, 0xff, 0];
    take_long_form_indefinite_like: &[0x30, 0xff];
}

#[test]
fn take_long_form_non_minimal_accepted() {
    // 0x81 0x02 is a non-minimal encoding of 2: accepted, and bounded the same way.
    assert_eq!(take(&[0x04, 0x81, 0x02, b'o', b'k']).unwrap().1, b"ok");
    assert_eq!(take(&[0x04, 0x84, 0, 0, 0, 2, b'o', b'k']).unwrap().1, b"ok");
}

#[test]
fn take_every_truncation_of_a_valid_message() {
    let full = search_entry(1, "uid=alice,ou=people", &[("memberOf", &["cn=a", "cn=b"]), ("cn", &["Alice"])]);
    assert!(take(&full).is_ok());
    for n in 0..full.len() {
        assert_eq!(take(&full[..n]), Err(LdapError::Protocol), "prefix {n}");
    }
}

#[test]
fn small_uint_table() {
    assert_eq!(small_uint(&[0]), Ok(0));
    assert_eq!(small_uint(&[49]), Ok(49));
    assert_eq!(small_uint(&[1, 0]), Ok(256));
    assert_eq!(small_uint(&[0xff, 0xff, 0xff, 0xff]), Ok(u32::MAX));
    assert_eq!(small_uint(&[]), Err(LdapError::Protocol));
    assert_eq!(small_uint(&[1, 2, 3, 4, 5]), Err(LdapError::Protocol));
}

#[test]
fn message_ids_cycle_1_to_127() {
    let (mut l, _) = ldap(&[]);
    assert_eq!(l.next_id(), 1);
    assert_eq!(l.next_id(), 2);
    l.msgid = 126;
    assert_eq!(l.next_id(), 127);
    assert_eq!(l.next_id(), 1, "never 0 (unsolicited notifications), never above 127");
}

// ---------- bind ----------

#[test]
fn bind_request_exact_bytes() {
    let (mut l, m) = ldap(&[bind_response(1, 0)]);
    assert_eq!(l.bind("cn=x", secret(b"pw")), Ok(0));
    let want = [
        0x30, 0x12, 0x02, 0x01, 0x01, 0x60, 0x0d, 0x02, 0x01, 0x03, 0x04, 0x04, b'c', b'n', b'=', b'x', 0x80, 0x02,
        b'p', b'w',
    ];
    assert_eq!(m.output(), want);
}

fn count(hay: &[u8], needle: &[u8]) -> usize {
    hay.windows(needle.len()).filter(|w| *w == needle).count()
}

fn bind_layout(dn_len: usize, pw_len: usize) {
    let dn = format!("uid={},ou=people", "d".repeat(dn_len));
    let pw: Vec<u8> = (0..pw_len).map(|i| b'A' + u8::try_from(i % 26).unwrap()).collect();
    let (mut l, m) = ldap(&[bind_response(1, 0)]);
    assert_eq!(l.bind(&dn, secret(&pw)), Ok(0));
    let out = m.output();
    // Decode independently: SEQUENCE { INTEGER 1, [APPLICATION 0] { INTEGER 3, OCTET STRING dn, [0] pw } }
    let (tag, body, rest) = parse(&out).unwrap();
    assert_eq!((tag, rest.len()), (0x30, 0));
    let (tag, id, rest) = parse(body).unwrap();
    assert_eq!((tag, id), (0x02, &[1u8][..]));
    let (tag, bind, rest) = parse(rest).unwrap();
    assert_eq!((tag, rest.len()), (0x60, 0));
    let (tag, version, rest) = parse(bind).unwrap();
    assert_eq!((tag, version), (0x02, &[3u8][..]));
    let (tag, got_dn, rest) = parse(rest).unwrap();
    assert_eq!((tag, got_dn), (0x04, dn.as_bytes()));
    let (tag, got_pw, rest) = parse(rest).unwrap();
    assert_eq!((tag, got_pw, rest.len()), (0x80, pw.as_slice(), 0));
    assert_eq!(count(&out, &pw), 1, "the password is written exactly once");
    assert!(out.ends_with(&pw), "and last: nothing after it");
}

cases! { bind_layout;
    bind_short: 1, 1;
    bind_pw_127: 5, 127;
    bind_pw_128: 5, 128;
    bind_pw_max: 5, 256;
    bind_long_dn: 300, 20;
    bind_both_long: 70_000, 256;
}

fn bind_code(code: u8) {
    let (mut l, _) = ldap(&[bind_response(1, code)]);
    assert_eq!(l.bind("cn=x", secret(b"pw")), Ok(u32::from(code)));
}

cases! { bind_code;
    bind_success: 0; bind_invalid_credentials: 49; bind_unwilling: 53; bind_constraint: 19; bind_insufficient: 50;
    bind_busy: 51; bind_other: 80;
}

#[test]
fn bind_multi_byte_result_code() {
    let mut op = t(0x0a, &[0x01, 0x00]);
    op.extend(t(0x04, b""));
    op.extend(t(0x04, b""));
    let (mut l, _) = ldap(&[msg(1, &t(0x61, &op))]);
    assert_eq!(l.bind("cn=x", secret(b"pw")), Ok(256));
}

#[test]
fn bind_empty_password_is_never_sent() {
    let (mut l, m) = ldap(&[bind_response(1, 0)]);
    assert_eq!(l.bind("cn=x", secret(b"")), Err(LdapError::Protocol));
    assert!(m.output().is_empty(), "an empty simple bind would be an anonymous bind");
}

fn bind_reply(reply: Vec<u8>, want: LdapError) {
    let (mut l, _) = ldap(&[reply]);
    assert_eq!(l.bind("cn=x", secret(b"pw")), Err(want));
}

cases! { bind_reply;
    bind_eof: vec![], LdapError::Unreachable;
    bind_wrong_message_id: bind_response(2, 0), LdapError::Protocol;
    bind_message_id_zero: bind_response(0, 0), LdapError::Protocol;
    bind_wrong_op: msg(1, &result_op(0x65, 0)), LdapError::Protocol;
    bind_extended_response: msg(1, &result_op(0x78, 0)), LdapError::Protocol;
    bind_not_a_sequence: vec![0x31, 0x03, 0x02, 0x01, 0x01], LdapError::Protocol;
    bind_code_not_enumerated: msg(1, &t(0x61, &t(0x02, &[0]))), LdapError::Protocol;
    bind_code_empty: msg(1, &t(0x61, &t(0x0a, &[]))), LdapError::Protocol;
    bind_code_too_long: msg(1, &t(0x61, &t(0x0a, &[1, 2, 3, 4, 5]))), LdapError::Protocol;
    bind_empty_op: msg(1, &t(0x61, &[])), LdapError::Protocol;
    bind_no_op: msg(1, &[]), LdapError::Protocol;
    bind_id_not_integer: t(0x30, &[0x04, 0x01, 0x01, 0x61, 0x00]), LdapError::Protocol;
    bind_id_too_long: t(0x30, &[0x02, 0x05, 0, 0, 0, 0, 1, 0x61, 0x00]), LdapError::Protocol;
    bind_header_long_zero: vec![0x30, 0x80], LdapError::Protocol;
    bind_header_long_five: vec![0x30, 0x85, 0, 0, 0, 0, 5], LdapError::Protocol;
    bind_over_max_message: { let mut v = vec![0x30]; v.extend(ber_len(MAX_MESSAGE + 1)); v }, LdapError::Protocol;
    bind_huge_length: vec![0x30, 0x84, 0xff, 0xff, 0xff, 0xff], LdapError::Protocol;
    bind_long_header_truncated: vec![0x30, 0x83, 0x01], LdapError::Unreachable;
    bind_body_truncated: vec![0x30, 0x0c, 0x02, 0x01, 0x01], LdapError::Unreachable;
}

#[test]
fn bind_every_truncated_reply_is_unreachable() {
    let full = bind_response(1, 0);
    for n in 0..full.len() {
        let (mut l, _) = ldap(&[full[..n].to_vec()]);
        assert_eq!(l.bind("cn=x", secret(b"pw")), Err(LdapError::Unreachable), "prefix {n}");
    }
}

#[test]
fn bind_reply_at_max_message_accepted() {
    // Padding after the protocolOp (where controls would be) up to exactly MAX_MESSAGE.
    let mut body = t(0x02, &[1]);
    body.extend(result_op(0x61, 0));
    let pad = MAX_MESSAGE - body.len() - 1 - ber_len(MAX_MESSAGE).len();
    body.extend(t(0xa0, &vec![0u8; pad]));
    assert_eq!(body.len(), MAX_MESSAGE);
    let (mut l, _) = ldap(&[t(0x30, &body)]);
    assert_eq!(l.bind("cn=x", secret(b"pw")), Ok(0));
}

#[test]
fn bind_write_failure_is_unreachable() {
    let (mut l, m) = ldap(&[bind_response(1, 0)]);
    m.0.borrow_mut().fail_write = true;
    assert_eq!(l.bind("cn=x", secret(b"pw")), Err(LdapError::Unreachable));
}

#[test]
fn bind_flush_failure_is_unreachable() {
    let (mut l, m) = ldap(&[bind_response(1, 0)]);
    m.0.borrow_mut().fail_flush = true;
    assert_eq!(l.bind("cn=x", secret(b"pw")), Err(LdapError::Unreachable));
}

#[test]
fn second_bind_uses_next_message_id() {
    let (mut l, m) = ldap(&[bind_response(1, 49), bind_response(2, 0)]);
    assert_eq!(l.bind("cn=x", secret(b"bad")), Ok(49));
    assert_eq!(l.bind("cn=x", secret(b"good")), Ok(0));
    let out = m.output();
    let (_, first, rest) = parse(&out).unwrap();
    let (_, second, _) = parse(rest).unwrap();
    assert_eq!(parse(first).unwrap().1, [1]);
    assert_eq!(parse(second).unwrap().1, [2]);
}

// ---------- search ----------

const DN: &str = "uid=alice,ou=people,dc=example,dc=org";

fn read(replies: &[Vec<u8>]) -> Result<(u32, Option<Entry>), LdapError> {
    let (mut l, _) = ldap(replies);
    l.read_entry(DN, ("uid", "alice"), &["memberOf"])
}

#[test]
fn search_request_layout() {
    let (mut l, m) = ldap(&[search_done(1, 0)]);
    l.read_entry(DN, ("uid", "alice"), &["memberOf", "cn"]).unwrap();
    let out = m.output();
    let (tag, body, rest) = parse(&out).unwrap();
    assert_eq!((tag, rest.len()), (0x30, 0));
    let (_, id, rest) = parse(body).unwrap();
    assert_eq!(id, [1]);
    let (tag, search, _) = parse(rest).unwrap();
    assert_eq!(tag, 0x63);
    let mut fields = Vec::new();
    let mut s = search;
    while let Some((tag, c, rest)) = parse(s) {
        fields.push((tag, c.to_vec()));
        s = rest;
        if s.is_empty() {
            break;
        }
    }
    assert_eq!(fields[0], (0x04, DN.as_bytes().to_vec()), "base");
    assert_eq!(fields[1], (0x0a, vec![0]), "scope baseObject");
    assert_eq!(fields[2], (0x0a, vec![0]), "derefAliases never");
    assert_eq!(fields[3], (0x02, vec![1]), "sizeLimit 1");
    assert_eq!(fields[4], (0x02, vec![10]), "timeLimit");
    assert_eq!(fields[5], (0x01, vec![0]), "typesOnly false");
    let mut filter = t(0x04, b"uid");
    filter.extend(t(0x04, b"alice"));
    assert_eq!(fields[6], (0xa3, filter), "equalityMatch uid=alice");
    let mut attrs = t(0x04, b"memberOf");
    attrs.extend(t(0x04, b"cn"));
    assert_eq!(fields[7], (0x30, attrs));
    assert_eq!(fields.len(), 8);
}

#[test]
fn search_no_entry() {
    let (code, entry) = read(&[search_done(1, 0)]).unwrap();
    assert_eq!(code, 0);
    assert!(entry.is_none());
}

#[test]
fn search_entry_multiple_attrs_and_values() {
    let (code, entry) = read(&[
        search_entry(1, DN, &[("memberOf", &["cn=a", "cn=b"]), ("cn", &["Alice"]), ("MEMBEROF", &["cn=c"])]),
        search_done(1, 0),
    ])
    .unwrap();
    let e = entry.unwrap();
    assert_eq!(code, 0);
    assert_eq!(e.attrs.len(), 3);
    let groups: Vec<_> = e.values("memberof").collect();
    assert_eq!(groups, [&b"cn=a"[..], b"cn=b", b"cn=c"], "names match case-insensitively");
    assert_eq!(e.values("cn").collect::<Vec<_>>(), [&b"Alice"[..]]);
    assert_eq!(e.values("mail").count(), 0);
}

#[test]
fn search_entry_no_attrs_and_empty_values() {
    let (_, e) = read(&[search_entry(1, DN, &[]), search_done(1, 0)]).unwrap();
    assert!(e.unwrap().attrs.is_empty());
    let (_, e) = read(&[search_entry(1, DN, &[("memberOf", &[])]), search_done(1, 0)]).unwrap();
    assert_eq!(e.unwrap().values("memberOf").count(), 0);
}

#[test]
fn search_binary_values_kept() {
    let mut set = t(0x04, &[0, 0xff, 0x80]);
    set = t(0x31, &set);
    let mut one = t(0x04, b"memberOf");
    one.extend(set);
    let mut c = t(0x04, DN.as_bytes());
    c.extend(t(0x30, &t(0x30, &one)));
    let (_, e) = read(&[msg(1, &t(0x64, &c)), search_done(1, 0)]).unwrap();
    assert_eq!(e.unwrap().values("memberOf").next().unwrap(), [0, 0xff, 0x80]);
}

#[test]
fn search_two_entries_refused() {
    let e = search_entry(1, DN, &[("memberOf", &["cn=a"])]);
    assert_eq!(read(&[e.clone(), e, search_done(1, 0)]).err(), Some(LdapError::Protocol));
}

#[test]
fn search_references_ignored() {
    let reference = msg(1, &t(0x73, &t(0x04, b"ldap://elsewhere/")));
    let (code, e) =
        read(&[reference.clone(), search_entry(1, DN, &[("memberOf", &["cn=a"])]), reference, search_done(1, 0)])
            .unwrap();
    assert_eq!(code, 0);
    assert!(e.is_some());
}

fn search_code(code: u8) {
    let (got, e) = read(&[search_done(1, code)]).unwrap();
    assert_eq!(got, u32::from(code));
    assert!(e.is_none());
}

cases! { search_code;
    search_no_such_object: 32; search_insufficient_access: 50; search_size_limit: 4; search_busy: 51;
}

#[test]
fn search_entry_then_error_code_returns_both() {
    let (code, e) = read(&[search_entry(1, DN, &[]), search_done(1, 4)]).unwrap();
    assert_eq!(code, 4);
    assert!(e.is_some());
}

fn search_bad(replies: Vec<Vec<u8>>, want: LdapError) {
    let mut l = Ldap::new(Mock::replying(replies.into_iter().flatten().collect()));
    assert_eq!(l.read_entry(DN, ("uid", "alice"), &["memberOf"]).err(), Some(want));
}

fn entry_with(list: &[u8]) -> Vec<u8> {
    let mut c = t(0x04, DN.as_bytes());
    c.extend_from_slice(list);
    msg(1, &t(0x64, &c))
}

cases! { search_bad;
    search_eof_before_done: vec![search_entry(1, DN, &[])], LdapError::Unreachable;
    search_eof: vec![], LdapError::Unreachable;
    search_wrong_id: vec![search_done(2, 0)], LdapError::Protocol;
    search_wrong_id_on_entry: vec![search_entry(2, DN, &[]), search_done(1, 0)], LdapError::Protocol;
    search_unexpected_op: vec![bind_response(1, 0)], LdapError::Protocol;
    search_done_code_not_enumerated: vec![msg(1, &t(0x65, &t(0x02, &[0])))], LdapError::Protocol;
    search_done_empty: vec![msg(1, &t(0x65, &[]))], LdapError::Protocol;
    search_entry_empty: vec![msg(1, &t(0x64, &[])), search_done(1, 0)], LdapError::Protocol;
    search_entry_no_attr_list: vec![entry_with(&[]), search_done(1, 0)], LdapError::Protocol;
    search_entry_attr_list_not_sequence: vec![entry_with(&t(0x31, &[])), search_done(1, 0)], LdapError::Protocol;
    search_entry_attr_not_sequence: vec![entry_with(&t(0x30, &t(0x04, b"x"))), search_done(1, 0)], LdapError::Protocol;
    search_entry_values_not_set: vec![entry_with(&t(0x30, &t(0x30, &[t(0x04, b"memberOf"), t(0x30, &[])].concat()))), search_done(1, 0)], LdapError::Protocol;
    search_entry_attr_without_values: vec![entry_with(&t(0x30, &t(0x30, &t(0x04, b"memberOf")))), search_done(1, 0)], LdapError::Protocol;
    search_entry_truncated_value: vec![entry_with(&t(0x30, &t(0x30, &[t(0x04, b"memberOf"), t(0x31, &[0x04, 0x09, b'x'])].concat()))), search_done(1, 0)], LdapError::Protocol;
    search_over_max_message: vec![{ let mut v = vec![0x30]; v.extend(ber_len(MAX_MESSAGE + 1)); v }], LdapError::Protocol;
}

#[test]
fn search_every_truncation_is_an_error() {
    let full = [search_entry(1, DN, &[("memberOf", &["cn=a", "cn=b"])]), search_done(1, 0)].concat();
    for n in 0..full.len() {
        let (mut l, _) = ldap(&[full[..n].to_vec()]);
        assert!(l.read_entry(DN, ("uid", "alice"), &["memberOf"]).is_err(), "prefix {n}");
    }
}

#[test]
fn search_write_failure_is_unreachable() {
    let (mut l, m) = ldap(&[search_done(1, 0)]);
    m.0.borrow_mut().fail_write = true;
    assert_eq!(l.read_entry(DN, ("uid", "alice"), &[]).err(), Some(LdapError::Unreachable));
}

#[test]
fn bind_then_search_ids() {
    let (mut l, _) = ldap(&[bind_response(1, 0), search_entry(2, DN, &[]), search_done(2, 0)]);
    assert_eq!(l.bind(DN, secret(b"pw")), Ok(0));
    assert!(l.read_entry(DN, ("uid", "alice"), &["memberOf"]).unwrap().1.is_some());
}

#[test]
fn unbind_bytes() {
    let (mut l, m) = ldap(&[]);
    l.msgid = 6;
    l.unbind();
    assert_eq!(m.output(), [0x30, 0x05, 0x02, 0x01, 0x07, 0x42, 0x00]);
}

#[test]
fn unbind_ignores_write_failure() {
    let m = Mock(std::rc::Rc::new(std::cell::RefCell::new(MockState { fail_write: true, ..MockState::default() })));
    Ldap::new(m).unbind();
}

// ---------- fuzz: never panics ----------

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn byte(&mut self) -> u8 {
        self.next().to_be_bytes()[0]
    }
    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % n as u64).unwrap()
    }
}

#[test]
fn fuzz_random_replies() {
    let mut rng = Rng(0x5eed_1234_abcd_0001);
    for _ in 0..20_000 {
        let len = rng.below(64);
        let mut reply: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        if !reply.is_empty() && rng.below(2) == 0 {
            reply[0] = 0x30; // get past the first check more often
        }
        let (mut l, _) = ldap(&[reply.clone()]);
        let _ = l.bind("cn=x", secret(b"pw"));
        let (mut l, _) = ldap(&[reply.clone()]);
        let _ = l.read_entry(DN, ("uid", "alice"), &["memberOf"]);
        if let Ok((_, c, r)) = take(&reply) {
            assert!(c.len() + r.len() < reply.len());
        }
    }
}

#[test]
fn fuzz_mutated_valid_replies() {
    let mut rng = Rng(0x0dd_ba11_cafe_f00d);
    let seeds = [
        bind_response(1, 0),
        [search_entry(1, DN, &[("memberOf", &["cn=a,dc=x", "cn=b"]), ("cn", &["A"])]), search_done(1, 0)].concat(),
        [msg(1, &t(0x73, &t(0x04, b"ldap://x/"))), search_done(1, 32)].concat(),
    ];
    for _ in 0..20_000 {
        let mut reply = seeds[rng.below(seeds.len())].clone();
        for _ in 0..=rng.below(4) {
            let i = rng.below(reply.len());
            match rng.below(3) {
                0 => reply[i] = rng.byte(),
                1 => reply[i] ^= 1 << rng.below(8),
                _ => reply.truncate(i),
            }
            if reply.is_empty() {
                break;
            }
        }
        let (mut l, _) = ldap(&[reply.clone()]);
        let _ = l.bind("cn=x", secret(b"pw"));
        let (mut l, _) = ldap(&[reply]);
        let _ = l.read_entry(DN, ("uid", "alice"), &["memberOf"]);
    }
}

// ---------- connect() helpers (the real-socket parts not reached via Mock) ----------

#[test]
fn set_timeouts_rejects_zero_and_accepts_nonzero() {
    use std::net::{TcpListener, TcpStream};
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let s = TcpStream::connect(l.local_addr().unwrap()).unwrap();
    // std rejects a zero timeout ("cannot set a 0 duration timeout"): the error path is exercised here.
    assert!(set_timeouts(&s, Duration::ZERO).is_err());
    assert!(set_timeouts(&s, Duration::from_secs(1)).is_ok());
}

#[test]
fn connect_unresolvable_host_is_unreachable() {
    let cfg = crate::tls::directory_client(
        &crate::tests::support::TempDir::new().write("ca.crt", &crate::tests::support::pki().dir_ca.pem),
    )
    .unwrap();
    // A host string the resolver rejects: to_socket_addrs yields nothing, so connect never touches the network.
    let r = Ldap::connect("no such host", 636, "ldap.test", cfg, Duration::from_secs(1));
    assert_eq!(r.err(), Some(LdapError::Unreachable));
}
