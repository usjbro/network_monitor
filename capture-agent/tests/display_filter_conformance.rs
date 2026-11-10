//! JAM-18: runs the shared display-filter conformance corpus
//! (`testdata/display-filter-conformance.json`, also run by
//! `lib/__tests__/display-filter-conformance.test.ts`) against the Rust port,
//! so the agent counts IO-graph series with exactly the semantics the browser
//! filters with.

use capture_agent::display_filter::{compile, Error};
use capture_agent::fields::{ByteRegion, Field, FieldType, FieldValue};
use serde_json::Value;

const CORPUS: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../testdata/display-filter-conformance.json"));

fn field_from_json(v: &Value) -> Field {
    let path = v["path"].as_str().expect("field path").to_string();
    let field_type = match v["type"].as_str().expect("field type") {
        "group" => FieldType::Group,
        "bool" => FieldType::Bool,
        "uint" => FieldType::Uint,
        "str" => FieldType::Str,
        "addr" => FieldType::Addr,
        "bytes" => FieldType::Bytes,
        other => panic!("unknown field type {other}"),
    };
    // uint values above 2^53 - 1 are decimal strings, as on the wire.
    let value = match (&field_type, v.get("value")) {
        (_, None) => None,
        (FieldType::Uint, Some(Value::Number(n))) => Some(FieldValue::Uint(n.as_u64().expect("u64"))),
        (FieldType::Uint, Some(Value::String(s))) => Some(FieldValue::Uint(s.parse().expect("decimal u64"))),
        (_, Some(Value::Bool(b))) => Some(FieldValue::Bool(*b)),
        (_, Some(Value::String(s))) => Some(FieldValue::Str(s.clone())),
        (_, Some(other)) => panic!("unsupported field value {other}"),
    };
    Field { path: path.clone(), label: path, group: None, field_type, value, region: ByteRegion::Header, offset: 0, len: 0 }
}

#[test]
fn rust_port_matches_the_shared_corpus() {
    let corpus: Value = serde_json::from_str(CORPUS).expect("corpus is JSON");
    let frame_len = corpus["frameLen"].as_u64().expect("frameLen") as u32;
    let fields: Vec<Field> = corpus["fields"].as_array().expect("fields").iter().map(field_from_json).collect();
    let cases = corpus["cases"].as_array().expect("cases");
    assert!(cases.len() > 100, "corpus unexpectedly small");

    let mut failures = Vec::new();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let filter = case["filter"].as_str().unwrap();
        let result = compile(filter);
        match (&case["expect"], result) {
            (Value::Bool(expected), Ok(compiled)) => {
                let got = compiled.matches(&fields, frame_len);
                if got != *expected {
                    failures.push(format!("{name}: expected {expected}, got {got}"));
                }
            }
            (Value::Bool(_), Err(error)) => failures.push(format!("{name}: unexpected error {error:?}")),
            (Value::Object(o), result) => {
                let e = &o["error"];
                let expected = Error {
                    message: e["message"].as_str().unwrap().to_string(),
                    token: e["token"].as_str().unwrap().to_string(),
                    position: e["position"].as_u64().unwrap() as usize,
                };
                match result {
                    Err(error) if error == expected => {}
                    Err(error) => failures.push(format!("{name}: expected {expected:?}, got {error:?}")),
                    Ok(_) => failures.push(format!("{name}: expected {expected:?}, compiled instead")),
                }
            }
            (other, _) => panic!("{name}: bad expect {other}"),
        }
    }
    assert!(failures.is_empty(), "{} conformance failure(s):\n{}", failures.len(), failures.join("\n"));
}
