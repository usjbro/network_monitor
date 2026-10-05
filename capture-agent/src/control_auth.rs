//! Private per-launch credential handoff. No credential-bearing errors or Debug impls.
use ring::{
    hmac,
    rand::{SecureRandom, SystemRandom},
};
use std::{
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{DirBuilderExt, OpenOptionsExt},
        },
    },
    path::PathBuf,
};
use zeroize::Zeroizing;
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "unsafe agent credential")
}

pub struct AgentToken(Zeroizing<[u8; 32]>);
impl AgentToken {
    pub fn generate() -> io::Result<Self> {
        let mut bytes = Zeroizing::new([0; 32]);
        SystemRandom::new()
            .fill(bytes.as_mut())
            .map_err(|_| io::Error::other("credential generation failed"))?;
        Ok(Self(bytes))
    }
    pub fn to_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(hex::encode(self.0.as_ref()))
    }
    pub fn matches_hex(&self, text: &str) -> bool {
        if text.len() != 64
            || !text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return false;
        }
        let mut candidate = Zeroizing::new([0; 32]);
        if hex::decode_to_slice(text, candidate.as_mut()).is_err() {
            return false;
        }
        let domain = b"network-monitor-agent-auth-v1";
        let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, self.0.as_ref()), domain);
        hmac::verify(
            &hmac::Key::new(hmac::HMAC_SHA256, candidate.as_ref()),
            domain,
            tag.as_ref(),
        )
        .is_ok()
    }
}
pub struct CredentialPath {
    parent: PathBuf,
    name: CString,
}
impl CredentialPath {
    pub fn new(path: PathBuf) -> io::Result<Self> {
        if !path.is_absolute() {
            return Err(invalid());
        }
        let parent = path.parent().ok_or_else(invalid)?;
        let name = path.file_name().ok_or_else(invalid)?;
        // Resolve only ancestors; the immediate directory itself may not be a symlink.
        let ancestor = parent.parent().ok_or_else(invalid)?.canonicalize()?;
        let parent = ancestor.join(parent.file_name().ok_or_else(invalid)?);
        if fs::symlink_metadata(&parent)?.file_type().is_symlink() {
            return Err(invalid());
        }
        Ok(Self {
            parent,
            name: CString::new(name.as_bytes()).map_err(|_| invalid())?,
        })
    }
    pub fn from_env() -> io::Result<Self> {
        if let Some(path) = std::env::var_os("AGENT_TOKEN_FILE") {
            return Self::new(PathBuf::from(path));
        }
        let home = PathBuf::from(std::env::var_os("HOME").ok_or_else(invalid)?);
        if !home.is_absolute() {
            return Err(invalid());
        }
        let dir = home.join(".network-monitor");
        match fs::DirBuilder::new().mode(0o700).create(&dir) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
        Self::new(dir.join("agent-control-token"))
    }
}
fn stat_at(dir: &File, name: &CString) -> io::Result<libc::stat> {
    let mut stat = std::mem::MaybeUninit::uninit();
    // SAFETY: directory is an owned FD, name is NUL-terminated, stat has writable storage.
    if unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { stat.assume_init() })
}
fn safe_stat(stat: &libc::stat, dir: bool) -> bool {
    let mode = if dir { libc::S_IFDIR } else { libc::S_IFREG };
    stat.st_uid == unsafe { libc::geteuid() }
        && stat.st_mode & libc::S_IFMT == mode
        && stat.st_mode & 0o7777 == if dir { 0o700 } else { 0o600 }
        && (dir || stat.st_nlink == 1)
}
pub struct PublishedCredential {
    dir: File,
    name: CString,
    identity: (libc::dev_t, libc::ino_t),
    token: AgentToken,
}
impl PublishedCredential {
    pub fn token(&self) -> &AgentToken {
        &self.token
    }
    pub fn publish(path: &CredentialPath, token: AgentToken) -> io::Result<Self> {
        let dir = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path.parent)?;
        let mut stat = std::mem::MaybeUninit::uninit();
        if unsafe { libc::fstat(dir.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if !safe_stat(&unsafe { stat.assume_init() }, true) {
            return Err(invalid());
        }
        match stat_at(&dir, &path.name) {
            Ok(s) if !safe_stat(&s, false) => return Err(invalid()),
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let mut nonce = [0; 16];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| io::Error::other("credential generation failed"))?;
        let temp = CString::new(format!(".agent-token-{}", hex::encode(nonce))).unwrap();
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                temp.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let result = (|| {
            let mut file = unsafe { File::from_raw_fd(fd) };
            if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
                return Err(io::Error::last_os_error());
            }
            let text = token.to_hex();
            file.write_all(text.as_bytes())?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            let s = stat_at(&dir, &temp)?;
            // Recheck destination immediately before publishing; never replace an unsafe entry.
            match stat_at(&dir, &path.name) {
                Ok(s) if !safe_stat(&s, false) => return Err(invalid()),
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
            if unsafe {
                libc::renameat(
                    dir.as_raw_fd(),
                    temp.as_ptr(),
                    dir.as_raw_fd(),
                    path.name.as_ptr(),
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok((s.st_dev, s.st_ino))
        })();
        match result {
            Ok(identity) => Ok(Self {
                dir,
                name: path.name.clone(),
                identity,
                token,
            }),
            Err(e) => {
                unsafe { libc::unlinkat(dir.as_raw_fd(), temp.as_ptr(), 0) };
                Err(e)
            }
        }
    }
}
impl Drop for PublishedCredential {
    fn drop(&mut self) {
        if let Ok(stat) = stat_at(&self.dir, &self.name) {
            if (stat.st_dev, stat.st_ino) == self.identity {
                unsafe { libc::unlinkat(self.dir.as_raw_fd(), self.name.as_ptr(), 0) };
            }
        }
    }
}
