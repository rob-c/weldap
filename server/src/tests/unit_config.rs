//! Configuration: strict schema, required fields, defaults, sanity checks.

use super::*;
use crate::cases;
use crate::tests::support::TempDir;
use serde_json::{json, Value};

const EXAMPLE: &str = include_str!("../../server.example.json");

fn example() -> Value {
    serde_json::from_str(EXAMPLE).unwrap()
}

fn load(v: &Value) -> Result<Config, String> {
    let dir = TempDir::new();
    Config::load(&dir.write("server.json", serde_json::to_vec(v).unwrap()))
}

#[test]
fn example_loads() {
    let c = load(&example()).unwrap();
    assert_eq!(c.listen, "0.0.0.0:8636");
    assert_eq!(c.password_keys.len(), 2);
    assert_eq!(c.password_keys[0].kid, "k2");
    assert_eq!(c.directory.port, 636);
    assert_eq!(c.directory.timeout_seconds, 5);
    assert_eq!(c.max_connections, 64);
    assert_eq!(c.max_clock_skew_seconds, 120);
}

#[test]
fn defaults() {
    let mut v = example();
    v.as_object_mut().unwrap().remove("max_connections");
    v.as_object_mut().unwrap().remove("max_clock_skew_seconds");
    v["directory"].as_object_mut().unwrap().remove("timeout_seconds");
    let c = load(&v).unwrap();
    assert_eq!((c.max_connections, c.max_clock_skew_seconds, c.directory.timeout_seconds), (64, 120, 5));
}

#[test]
fn explicit_values_override_defaults() {
    let mut v = example();
    v["max_connections"] = json!(3);
    v["max_clock_skew_seconds"] = json!(0);
    v["directory"]["timeout_seconds"] = json!(30);
    let c = load(&v).unwrap();
    assert_eq!((c.max_connections, c.max_clock_skew_seconds, c.directory.timeout_seconds), (3, 0, 30));
}

fn missing(path: &[&str]) {
    let mut v = example();
    let (last, parents) = path.split_last().unwrap();
    let mut node = &mut v;
    for p in parents {
        node = if let Ok(i) = p.parse::<usize>() { &mut node[i] } else { &mut node[*p] };
    }
    node.as_object_mut().unwrap().remove(*last).unwrap();
    assert!(load(&v).is_err(), "{path:?}");
}

cases! { missing;
    missing_listen: &["listen"];
    missing_server_cert: &["server_cert"];
    missing_server_key: &["server_key"];
    missing_device_ca: &["device_ca"];
    missing_device_crl: &["device_crl"];
    missing_password_keys: &["password_keys"];
    missing_directory: &["directory"];
    missing_key_kid: &["password_keys", "0", "kid"];
    missing_key_path: &["password_keys", "0", "private_key"];
    missing_dir_host: &["directory", "host"];
    missing_dir_port: &["directory", "port"];
    missing_dir_server_name: &["directory", "server_name"];
    missing_dir_ca: &["directory", "ca"];
    missing_dir_template: &["directory", "user_dn_template"];
    missing_dir_users_group: &["directory", "users_group"];
    missing_dir_admins_group: &["directory", "admins_group"];
    missing_dir_service_dn: &["directory", "service_dn"];
    missing_dir_service_password_file: &["directory", "service_password_file"];
}

fn set(path: &[&str], value: Value) {
    let mut v = example();
    let (last, parents) = path.split_last().unwrap();
    let mut node = &mut v;
    for p in parents {
        node = if let Ok(i) = p.parse::<usize>() { &mut node[i] } else { &mut node[*p] };
    }
    node[*last] = value;
    assert!(load(&v).is_err(), "{path:?}");
}

cases! { set;
    unknown_top_level: &["debug"], json!(true);
    unknown_in_directory: &["directory", "bind_password"], json!("secret");
    unknown_in_key: &["password_keys", "0", "public_key"], json!("x");
    port_too_big: &["directory", "port"], json!(70_000);
    port_string: &["directory", "port"], json!("636");
    port_negative: &["directory", "port"], json!(-1);
    max_connections_negative: &["max_connections"], json!(-1);
    skew_string: &["max_clock_skew_seconds"], json!("120");
    keys_not_array: &["password_keys"], json!({"kid": "k1"});
    listen_number: &["listen"], json!(8636);
    template_without_placeholder: &["directory", "user_dn_template"], json!("uid=alice,ou=people");
    template_other_placeholder: &["directory", "user_dn_template"], json!("uid={1},ou=people");
    no_password_keys: &["password_keys"], json!([]);
}

#[test]
fn error_messages_name_the_problem() {
    let mut v = example();
    v["password_keys"] = json!([]);
    assert_eq!(load(&v).err().unwrap(), "password_keys is empty");
    let mut v = example();
    v["directory"]["user_dn_template"] = json!("uid=x");
    assert_eq!(load(&v).err().unwrap(), "directory.user_dn_template needs {0}");
}

#[test]
fn missing_file() {
    let e = Config::load(std::path::Path::new("/nonexistent/server.json")).err().unwrap();
    assert!(e.starts_with("/nonexistent/server.json: "), "{e}");
}

#[test]
fn not_json() {
    let dir = TempDir::new();
    for text in ["", "{", "[]", "null", "listen: x", "{\"listen\": \"a\",}"] {
        assert!(Config::load(&dir.write("c.json", text)).is_err(), "{text:?}");
    }
}

#[test]
fn not_utf8() {
    let dir = TempDir::new();
    assert!(Config::load(&dir.write("c.json", b"\xff\xfe{}")).is_err());
}
