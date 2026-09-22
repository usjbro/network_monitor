use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FieldType {
    Group,
    Bool,
    Uint,
    Str,
    Addr,
    Bytes,
}

/// Which of the two hex-dump panes a field's `offset`/`len` is relative to.
/// Header fields (eth/ip/tcp/udp/vlan) are offset into `headerHexDump`;
/// app-layer fields (http/dns/tls) are offset into the existing `hexDump`
/// — the two panes are never merged into one shared byte space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ByteRegion {
    Header,
    Payload,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum FieldValue {
    Bool(bool),
    Uint(u64),
    Str(String),
    #[allow(dead_code)] // no currently-decoded field uses this yet; kept for future dissector work per the spec's type enum
    Bytes(Vec<u8>),
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Field {
    pub path: String,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(rename = "type")]
    pub field_type: FieldType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<FieldValue>,
    pub region: ByteRegion,
    pub offset: u32,
    pub len: u32,
}

impl Field {
    pub fn group(path: &str, label: &str, group: Option<&str>, region: ByteRegion, offset: u32, len: u32) -> Field {
        Field {
            path: path.to_string(),
            label: label.to_string(),
            group: group.map(|g| g.to_string()),
            field_type: FieldType::Group,
            value: None,
            region,
            offset,
            len,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn leaf(
        path: &str,
        label: &str,
        group: &str,
        field_type: FieldType,
        value: FieldValue,
        region: ByteRegion,
        offset: u32,
        len: u32,
    ) -> Field {
        Field {
            path: path.to_string(),
            label: label.to_string(),
            group: Some(group.to_string()),
            field_type,
            value: Some(value),
            region,
            offset,
            len,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_group_omits_the_value_key_entirely() {
        let f = Field::group("tcp", "Transmission Control Protocol", None, ByteRegion::Header, 34, 20);
        let json = serde_json::to_string(&f).unwrap();
        assert!(!json.contains("\"value\""), "group entries must carry no value key at all, not null: {json}");
        assert!(!json.contains("\"group\":"), "a top-level group must omit the group key, not send null: {json}");
        assert!(json.contains("\"type\":\"group\""));
        assert!(json.contains("\"region\":\"header\""));
    }

    #[test]
    fn a_leaf_serializes_its_typed_value_untagged() {
        let f = Field::leaf(
            "tcp.flags.syn",
            "SYN",
            "tcp.flags",
            FieldType::Bool,
            FieldValue::Bool(true),
            ByteRegion::Header,
            47,
            1,
        );
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains("\"value\":true"), "bool value must serialize as a bare JSON bool, not {{\"Bool\":true}}: {json}");
        assert!(json.contains("\"group\":\"tcp.flags\""));
    }

    #[test]
    fn a_uint_leaf_serializes_as_a_bare_number() {
        let f = Field::leaf("tcp.src_port", "Source Port", "tcp", FieldType::Uint, FieldValue::Uint(51000), ByteRegion::Header, 34, 2);
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains("\"value\":51000"), "{json}");
    }

    #[test]
    fn field_uses_camel_case_keys() {
        let f = Field::leaf("ip.ttl", "Time to Live", "ip", FieldType::Uint, FieldValue::Uint(64), ByteRegion::Header, 22, 1);
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains("\"path\":\"ip.ttl\""));
        assert!(json.contains("\"offset\":22"));
        assert!(json.contains("\"len\":1"));
    }
}
