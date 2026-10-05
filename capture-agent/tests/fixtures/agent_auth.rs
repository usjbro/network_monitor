use std::{
    fs,
    io::{BufRead, BufReader, Write},
    net::TcpStream,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
pub struct AuthFixture(PathBuf);
impl AuthFixture {
    pub fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "agent-credential-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        Self(dir)
    }
    pub fn token_path(&self) -> PathBuf {
        self.0.join("token")
    }
    #[allow(dead_code)]
    pub fn authenticate(&self, mut stream: TcpStream) -> BufReader<TcpStream> {
        let token = read_token(&self.token_path());
        stream
            .write_all(
                format!(
                    "{{\"type\":\"authenticate\",\"token\":\"{}\"}}\n",
                    token.trim()
                )
                .as_bytes(),
            )
            .unwrap();
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert_eq!(
            line, "{\"type\":\"authenticated\"}\n",
            "authentication did not succeed"
        );
        reader
    }
}
#[allow(dead_code)]
pub fn read_token(path: &Path) -> String {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(token) = fs::read_to_string(path) {
            return token;
        }
        assert!(
            Instant::now() < deadline,
            "agent did not publish isolated credential"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}
impl Drop for AuthFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
