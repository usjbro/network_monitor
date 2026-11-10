#![no_main]
//! JAM-18: the display-filter tokenizer, parser and evaluator on arbitrary
//! input. IO-graph series filters are untrusted browser input that the agent
//! compiles and then evaluates on every frame.
//!
//! Properties under test: no panic anywhere (including unbounded recursion,
//! which would abort on stack overflow); a successful compile implies the
//! source is within the 2048 UTF-16-unit limit; evaluation always terminates;
//! and the series wrapper never accepts something plain `compile` rejects,
//! except an empty or whitespace-only source, which means "every frame"
//! for a series.
use capture_agent::display_filter::{compile, compile_for_series, MAX_SOURCE_LENGTH};
use capture_agent::fields::{ByteRegion, Field, FieldType, FieldValue};
use libfuzzer_sys::fuzz_target;

fn field(path: &str, field_type: FieldType, value: Option<FieldValue>) -> Field {
    Field { path: path.into(), label: path.into(), group: None, field_type, value, region: ByteRegion::Header, offset: 0, len: 0 }
}

fuzz_target!(|data: &[u8]| {
    let Ok(source) = std::str::from_utf8(data) else { return };
    let fields = [
        field("tcp", FieldType::Group, None),
        field("tcp.dst_port", FieldType::Uint, Some(FieldValue::Uint(443))),
        field("big", FieldType::Uint, Some(FieldValue::Uint(u64::MAX))),
        field("tcp.flags.syn", FieldType::Bool, Some(FieldValue::Bool(true))),
        field("dns.qry.name", FieldType::Str, Some(FieldValue::Str("Example.COM".into()))),
        field("ip.src", FieldType::Addr, Some(FieldValue::Str("2001:DB8::1".into()))),
        field("app.bytes", FieldType::Bytes, None),
    ];
    match compile(source) {
        Ok(compiled) => {
            let units: usize = source.chars().map(char::len_utf16).sum();
            assert!(units <= MAX_SOURCE_LENGTH, "compiled a {units}-unit source");
            let _ = compiled.matches(&fields, 1500);
            let _ = compiled.matches(&[], 0);
        }
        Err(error) => {
            if let Ok(all) = compile_for_series(source) {
                assert!(source.trim_matches(|c: char| c.is_whitespace() || c == '\u{FEFF}').is_empty(), "series wrapper accepted a rejected filter");
                assert!(all.matches(&fields, 0), "an empty series filter must match every frame");
            }
            assert!(!error.message.is_empty());
        }
    }
    if let Ok(series) = compile_for_series(source) {
        let _ = series.matches(&fields, 60);
    }
});
