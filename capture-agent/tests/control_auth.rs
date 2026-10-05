use capture_agent::control_auth::{AgentToken, CredentialPath, PublishedCredential};
use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt},
    path::PathBuf,
};
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "agent-auth-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&p).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
        Self(p)
    }
    fn path(&self) -> CredentialPath {
        CredentialPath::new(self.0.join("token")).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
#[test]
fn token_is_fresh_lowercase_hex() {
    let a = AgentToken::generate().unwrap();
    let b = AgentToken::generate().unwrap();
    let text = a.to_hex();
    assert_eq!(text.len(), 64);
    assert!(text
        .bytes()
        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)));
    assert_ne!(text, b.to_hex());
    assert!(a.matches_hex(&text));
    assert!(!a.matches_hex(&b.to_hex()));
    assert!(!a.matches_hex(&text.to_uppercase()));
    assert!(!a.matches_hex("bad"));
}
#[test]
fn publication_rotates_and_cleanup_preserves_replacement() {
    let f = Fixture::new();
    let a = PublishedCredential::publish(&f.path(), AgentToken::generate().unwrap()).unwrap();
    let before = fs::read(f.0.join("token")).unwrap();
    assert_eq!(before.len(), 65);
    let b = PublishedCredential::publish(&f.path(), AgentToken::generate().unwrap()).unwrap();
    assert_ne!(before, fs::read(f.0.join("token")).unwrap());
    drop(a);
    assert!(f.0.join("token").exists());
    drop(b);
    assert!(!f.0.join("token").exists());
}
#[test]
fn publication_rejects_unsafe_entries() {
    for kind in ["mode", "link", "symlink", "directory", "parent"] {
        let f = Fixture::new();
        let p = f.0.join("token");
        match kind {
            "mode" => {
                fs::write(&p, b"secret").unwrap();
                fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
            }
            "link" => {
                fs::write(&p, b"secret").unwrap();
                fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
                fs::hard_link(&p, f.0.join("other")).unwrap();
            }
            "symlink" => symlink("missing", &p).unwrap(),
            "directory" => fs::create_dir(&p).unwrap(),
            "parent" => fs::set_permissions(&f.0, fs::Permissions::from_mode(0o755)).unwrap(),
            _ => unreachable!(),
        }
        assert!(
            PublishedCredential::publish(&f.path(), AgentToken::generate().unwrap()).is_err(),
            "{kind}"
        );
    }
}
#[test]
fn publication_survives_parent_path_rename() {
    let f = Fixture::new();
    let guard = PublishedCredential::publish(&f.path(), AgentToken::generate().unwrap()).unwrap();
    let moved = f.0.with_extension("moved");
    fs::rename(&f.0, &moved).unwrap();
    fs::create_dir(&f.0).unwrap();
    fs::write(f.0.join("token"), b"replacement").unwrap();
    drop(guard);
    assert!(!moved.join("token").exists());
    assert_eq!(fs::read(f.0.join("token")).unwrap(), b"replacement");
    fs::remove_dir(moved).unwrap();
}
#[test]
fn immediate_parent_symlink_is_rejected() {
    let f = Fixture::new();
    let alias = f.0.join("alias");
    symlink(&f.0, &alias).unwrap();
    assert!(CredentialPath::new(alias.join("token")).is_err());
}
#[test]
fn strict_auth_schema() {
    use capture_agent::wire::AuthenticateMessage;
    assert!(serde_json::from_str::<AuthenticateMessage>(&format!(
        r#"{{"type":"authenticate","token":"{}"}}"#,
        "a".repeat(64)
    ))
    .is_ok());
    for text in [
        r#"{"type":"pause"}"#,
        r#"{"type":"authenticate","token":"x","extra":true}"#,
        r#"{"type":"authenticate"}"#,
    ] {
        assert!(serde_json::from_str::<AuthenticateMessage>(text).is_err());
    }
    assert_eq!(
        serde_json::to_string(&capture_agent::wire::AuthenticatedMessage::Authenticated).unwrap(),
        r#"{"type":"authenticated"}"#
    );
}
