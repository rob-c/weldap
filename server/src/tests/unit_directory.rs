//! Result mapping, DN comparison, and membership reads on scripted LDAP streams. `LdapDirectory` against a
//! fake LDAPS server is in `tests/e2e_directory.rs`.

use super::*;
use crate::cases;
use crate::tests::support::{msg, parse, search_done, search_entry, tlv, Mock};

pub fn cfg() -> config::Directory {
    config::Directory {
        host: "127.0.0.1".into(),
        port: 636,
        server_name: "ldap.test".into(),
        ca: "/nonexistent".into(),
        user_dn_template: "uid={0},ou=people,dc=example,dc=org".into(),
        users_group: "cn=weldap-users,ou=groups,dc=example,dc=org".into(),
        admins_group: "cn=weldap-admins,ou=groups,dc=example,dc=org".into(),
        service_dn: "cn=svc,dc=example,dc=org".into(),
        service_password_file: "/nonexistent".into(),
        timeout_seconds: 1,
    }
}

const DN: &str = "uid=alice,ou=people,dc=example,dc=org";

fn bind(r: Result<u32, LdapError>, want: Result<(), Failure>) {
    assert_eq!(bind_result(r), want);
}

cases! { bind;
    bind_0_ok: Ok(0), Ok(());
    bind_49_invalid: Ok(49), Err(Failure::Invalid);
    bind_19_denied: Ok(19), Err(Failure::Denied);
    bind_50_denied: Ok(50), Err(Failure::Denied);
    bind_53_denied: Ok(53), Err(Failure::Denied);
    bind_1_error: Ok(1), Err(Failure::Error("directory_result"));
    bind_32_error: Ok(32), Err(Failure::Error("directory_result"));
    bind_48_error: Ok(48), Err(Failure::Error("directory_result"));
    bind_51_busy_error: Ok(51), Err(Failure::Error("directory_result"));
    bind_huge_error: Ok(u32::MAX), Err(Failure::Error("directory_result"));
    bind_unreachable: Err(LdapError::Unreachable), Err(Failure::Unavailable);
    bind_protocol: Err(LdapError::Protocol), Err(Failure::Error("directory_protocol"));
}

fn norm(a: &str, b: &str) {
    assert_eq!(normalize_dn(a), b);
}

cases! { norm;
    norm_identity: "cn=a,dc=b", "cn=a,dc=b";
    norm_case: "CN=Weldap-Users,OU=Groups", "cn=weldap-users,ou=groups";
    norm_spaces_around_comma: "cn=a , dc=b", "cn=a,dc=b";
    norm_spaces_around_equals: "cn = a,dc =b", "cn=a,dc=b";
    norm_leading_trailing: "  cn=a,dc=b  ", "cn=a,dc=b";
    norm_inner_space_kept: "cn=weldap users,dc=b", "cn=weldap users,dc=b";
    norm_no_equals: "garbage", "garbage";
    norm_empty: "", "";
    norm_value_with_equals: "cn=a=b,dc=c", "cn=a=b,dc=c";
}

#[test]
fn user_dn_from_template() {
    assert_eq!(user_dn(&cfg(), "alice"), DN);
    let mut c = cfg();
    c.user_dn_template = "{0}@example.org/{0}".into();
    assert_eq!(user_dn(&c, "bob"), "bob@example.org/bob");
}

fn read_membership(replies: &[Vec<u8>]) -> (Result<Option<Membership>, Failure>, Vec<u8>) {
    let m = Mock::replying(replies.concat());
    let mut l = Ldap::new(m.clone());
    let r = membership(&mut l, &cfg(), "alice");
    (r, m.output())
}

fn groups(values: &[&str], want: Membership) {
    let (r, _) = read_membership(&[search_entry(1, DN, &[("memberOf", values)]), search_done(1, 0)]);
    assert_eq!(r, Ok(Some(want)), "{values:?}");
}

const U: Membership = Membership { user: true, admin: false };
const A: Membership = Membership { user: false, admin: true };
const UA: Membership = Membership { user: true, admin: true };
const NO: Membership = Membership { user: false, admin: false };

cases! { groups;
    member_user: &["cn=weldap-users,ou=groups,dc=example,dc=org"], U;
    member_admin: &["cn=weldap-admins,ou=groups,dc=example,dc=org"], A;
    member_both: &["cn=weldap-admins,ou=groups,dc=example,dc=org", "cn=weldap-users,ou=groups,dc=example,dc=org"], UA;
    member_none: &[], NO;
    member_other_groups: &["cn=staff,ou=groups,dc=example,dc=org", "cn=weldap-users,ou=other,dc=example,dc=org"], NO;
    member_upper_case: &["CN=WELDAP-USERS,OU=GROUPS,DC=EXAMPLE,DC=ORG"], U;
    member_spaced: &["cn = weldap-users , ou=groups,  dc=example ,dc=org"], U;
    member_prefix_is_not_member: &["cn=weldap-users,ou=groups,dc=example"], NO;
    member_suffix_is_not_member: &["cn=weldap-users,ou=groups,dc=example,dc=org,dc=evil"], NO;
    member_substring_is_not_member: &["cn=weldap-users-old,ou=groups,dc=example,dc=org"], NO;
}

#[test]
fn member_of_attribute_name_case_insensitive() {
    let (r, _) = read_membership(&[
        search_entry(1, DN, &[("MemberOf", &["cn=weldap-users,ou=groups,dc=example,dc=org"])]),
        search_done(1, 0),
    ]);
    assert_eq!(r, Ok(Some(U)));
}

#[test]
fn other_attributes_do_not_count() {
    let (r, _) = read_membership(&[
        search_entry(1, DN, &[("description", &["cn=weldap-admins,ou=groups,dc=example,dc=org"])]),
        search_done(1, 0),
    ]);
    assert_eq!(r, Ok(Some(NO)));
}

#[test]
fn configured_groups_are_normalised_too() {
    let mut c = cfg();
    c.users_group = "CN=Weldap-Users, OU=Groups, DC=Example, DC=Org".into();
    let m = Mock::replying(
        [search_entry(1, DN, &[("memberOf", &["cn=weldap-users,ou=groups,dc=example,dc=org"])]), search_done(1, 0)]
            .concat(),
    );
    assert_eq!(membership(&mut Ldap::new(m), &c, "alice"), Ok(Some(U)));
}

#[test]
fn non_utf8_group_values_do_not_match() {
    let mut c = tlv(0x04, b"\xffcn=weldap-users,ou=groups,dc=example,dc=org");
    c = tlv(0x31, &c);
    let mut one = tlv(0x04, b"memberOf");
    one.extend(c);
    let mut e = tlv(0x04, DN.as_bytes());
    e.extend(tlv(0x30, &tlv(0x30, &one)));
    let (r, _) = read_membership(&[msg(1, &tlv(0x64, &e)), search_done(1, 0)]);
    assert_eq!(r, Ok(Some(NO)));
}

#[test]
fn search_targets_user_entry() {
    let (_, out) = read_membership(&[search_done(1, 0)]);
    let (_, body, _) = parse(&out).unwrap();
    let (_, _, rest) = parse(body).unwrap();
    let (tag, search, _) = parse(rest).unwrap();
    assert_eq!(tag, 0x63);
    assert_eq!(parse(search).unwrap().1, DN.as_bytes());
    assert!(out.windows(8).any(|w| w == b"memberOf"));
}

fn code(c: u8, want: Result<Option<Membership>, Failure>) {
    let (r, _) = read_membership(&[search_done(1, c)]);
    assert_eq!(r, want);
}

cases! { code;
    no_entry_is_none: 0, Ok(None);
    no_such_object_is_none: 32, Ok(None);
    insufficient_access_is_error: 50, Err(Failure::Error("entry_read"));
    busy_is_error: 51, Err(Failure::Error("entry_read"));
    size_limit_is_error: 4, Err(Failure::Error("entry_read"));
}

#[test]
fn no_such_object_with_entry_is_none() {
    let (r, _) = read_membership(&[search_entry(1, DN, &[]), search_done(1, 32)]);
    assert_eq!(r, Ok(None));
}

#[test]
fn eof_is_unavailable() {
    let (r, _) = read_membership(&[]);
    assert_eq!(r, Err(Failure::Unavailable));
}

#[test]
fn protocol_error_is_error() {
    let (r, _) = read_membership(&[search_done(9, 0)]);
    assert_eq!(r, Err(Failure::Error("directory_protocol")));
}
