//! Self-update of the `dove` binary from signed GitHub Releases (`dove upgrade`), and the once-a-day "new version
//! available" notice ([`notice`]).
//!
//! CLI only: the `serve` process never calls into this module (checked by a test), so the service's outbound
//! allowlist (`gmail::gateway`, spec 7.5) is unaffected.
//!
//! Trust: the release's `SHA256SUMS` must carry a minisign signature by the key in `deploy/release/minisign.pub`
//! (embedded at build time) whose trusted comment is exactly `dove <tag>`, so an old signed list cannot be replayed
//! for another release. The archive must match its line in that list. Only the `dove` entry is taken from the
//! archive, and the running binary is replaced by an atomic rename in its own directory.

pub mod notice;

use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use semver::Version;
use sha2::{Digest, Sha256};

/// The project's repository URL (Cargo.toml `repository`): the one place owner and repo come from.
pub const REPOSITORY_URL: &str = env!("CARGO_PKG_REPOSITORY");
/// Release signing key (minisign), embedded at build time.
pub const RELEASE_PUBLIC_KEY: &str = include_str!("../../deploy/release/minisign.pub");
/// `dove upgrade --check` exit code when a newer release exists (0 means up to date, 1 an error).
pub const EXIT_UPDATE_AVAILABLE: u8 = 10;
/// Hint printed when the update would run inside a container image.
pub const CONTAINER_HINT: &str = "docker compose pull && docker compose up -d";

const USER_AGENT: &str = concat!("dove-cli/", env!("CARGO_PKG_VERSION"));
const MAX_API_BYTES: usize = 1024 * 1024;
const MAX_SUMS_BYTES: usize = 64 * 1024;
const MAX_SIG_BYTES: usize = 4 * 1024;
const MAX_ARCHIVE_BYTES: usize = 256 * 1024 * 1024;
const MAX_BINARY_BYTES: u64 = 256 * 1024 * 1024;
/// Bound on everything the gzip stream may expand to (protects against decompression bombs).
const MAX_UNPACKED_BYTES: u64 = 1024 * 1024 * 1024;

/// `owner/repo` from [`REPOSITORY_URL`].
pub fn repo_slug() -> &'static str {
    REPOSITORY_URL.strip_prefix("https://github.com/").unwrap_or(REPOSITORY_URL).trim_end_matches('/')
}

/// Release target triple of this build, when releases are published for it.
pub fn current_target() -> Option<&'static str> {
    if cfg!(all(target_os = "linux", target_env = "gnu", target_arch = "x86_64")) {
        Some("x86_64-unknown-linux-gnu")
    } else if cfg!(all(target_os = "linux", target_env = "gnu", target_arch = "aarch64")) {
        Some("aarch64-unknown-linux-gnu")
    } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        Some("x86_64-apple-darwin")
    } else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        Some("aarch64-apple-darwin")
    } else {
        None
    }
}

/// Where releases come from and what this binary is. Production uses [`Source::github`]; tests point the bases at
/// a local server and use their own key, version and target.
#[derive(Clone, Debug)]
pub struct Source {
    /// GitHub REST API base, e.g. `https://api.github.com`.
    pub api_base: String,
    /// Release download base, e.g. `https://github.com`.
    pub download_base: String,
    /// minisign public key file contents.
    pub public_key: String,
    /// Version of the installed binary.
    pub current: Version,
    /// Release target triple, `None` on platforms without release builds.
    pub target: Option<String>,
}

impl Source {
    pub fn github() -> Self {
        Self {
            api_base: "https://api.github.com".into(),
            download_base: "https://github.com".into(),
            public_key: RELEASE_PUBLIC_KEY.into(),
            current: Version::parse(env!("CARGO_PKG_VERSION")).expect("crate version is semver"),
            target: current_target().map(str::to_string),
        }
    }

    fn latest_url(&self) -> String {
        format!("{}/repos/{}/releases/latest", self.api_base.trim_end_matches('/'), repo_slug())
    }

    fn asset_url(&self, tag: &str, asset: &str) -> String {
        format!("{}/{}/releases/download/{tag}/{asset}", self.download_base.trim_end_matches('/'), repo_slug())
    }
}

/// HTTP client for release lookups and downloads. `timeout` bounds each whole request.
pub fn http_client(timeout: Duration) -> anyhow::Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .redirect(reqwest::redirect::Policy::limited(5))
        .connect_timeout(timeout.min(Duration::from_secs(10)))
        .timeout(timeout)
        .build()
        .context("cannot build HTTP client")
}

/// Release tag of a version (`v1.2.3`).
pub fn tag(v: &Version) -> String {
    format!("v{v}")
}

/// Parses a stable release tag `vX.Y.Z`.
pub fn parse_tag(tag: &str) -> anyhow::Result<Version> {
    let v = tag
        .strip_prefix('v')
        .and_then(|s| Version::parse(s).ok())
        .ok_or_else(|| anyhow!("release tag '{tag}' is not of the form vX.Y.Z"))?;
    if !v.pre.is_empty() || !v.build.is_empty() {
        bail!("release tag '{tag}' is not a stable release");
    }
    Ok(v)
}

/// Parses a version given on the command line (`1.2.3` or `v1.2.3`).
pub fn parse_requested(s: &str) -> anyhow::Result<Version> {
    parse_tag(&format!("v{}", s.strip_prefix('v').unwrap_or(s)))
        .map_err(|_| anyhow!("--version must be a release version like 0.2.0"))
}

/// Latest stable release (GitHub's `releases/latest` excludes prereleases and drafts).
pub async fn latest_release(src: &Source, http: &reqwest::Client) -> anyhow::Result<Version> {
    let resp = http
        .get(src.latest_url())
        .header("accept", "application/vnd.github+json")
        .send()
        .await
        .map_err(|e| anyhow!("cannot reach GitHub to look up the latest release ({})", e.without_url()))?;
    match resp.status().as_u16() {
        200 => {}
        404 => bail!("no Dove release has been published yet"),
        403 | 429 => bail!("GitHub refused the release lookup (rate limit); try again later"),
        s => bail!("unexpected HTTP status {s} from the GitHub release lookup"),
    }
    let body = read_capped(resp, MAX_API_BYTES).await?;
    let v: serde_json::Value = serde_json::from_slice(&body).context("GitHub returned invalid release JSON")?;
    let tag = v["tag_name"].as_str().ok_or_else(|| anyhow!("GitHub release JSON has no tag_name"))?;
    parse_tag(tag)
}

/// What `dove upgrade` should do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The latest release is not newer than the installed binary.
    UpToDate { latest: Version },
    /// The explicitly requested version is the installed one.
    AlreadyInstalled,
    /// Install this release (newer, or an explicitly requested older one).
    Install(Version),
}

/// Upgrades only to newer releases; a downgrade happens only when that version is requested explicitly.
pub fn decide(current: &Version, latest: Option<&Version>, requested: Option<&Version>) -> Decision {
    match (requested, latest) {
        (Some(r), _) if r == current => Decision::AlreadyInstalled,
        (Some(r), _) => Decision::Install(r.clone()),
        (None, Some(l)) if l > current => Decision::Install(l.clone()),
        (None, Some(l)) => Decision::UpToDate { latest: l.clone() },
        (None, None) => Decision::AlreadyInstalled,
    }
}

/// Archive file name of a release for a target.
pub fn archive_name(tag: &str, target: &str) -> String {
    format!("dove-{tag}-{target}.tar.gz")
}

/// Downloads a release for `src.target` and returns the verified `dove` binary.
pub async fn fetch_binary(src: &Source, http: &reqwest::Client, version: &Version) -> anyhow::Result<Vec<u8>> {
    let target = src.target.as_deref().ok_or_else(unsupported_target)?;
    let tag = tag(version);
    let archive = archive_name(&tag, target);
    // The small signed list first: a bad signature fails before the large download.
    let sums = download(http, &src.asset_url(&tag, "SHA256SUMS"), &tag, "SHA256SUMS", MAX_SUMS_BYTES).await?;
    let sig =
        download(http, &src.asset_url(&tag, "SHA256SUMS.minisig"), &tag, "SHA256SUMS.minisig", MAX_SIG_BYTES).await?;
    verify_sums(&src.public_key, &sums, &sig, &tag)?;
    let expected = expected_sha256(&sums, &archive)?
        .ok_or_else(|| anyhow!("release {tag} has no build for this platform ({target})"))?;
    let bytes = download(http, &src.asset_url(&tag, &archive), &tag, &archive, MAX_ARCHIVE_BYTES).await?;
    if crate::util::hex(&Sha256::digest(&bytes)) != expected {
        bail!("checksum mismatch for {archive}: the download does not match the signed SHA256SUMS");
    }
    extract_binary(&bytes, &tag, target)
}

fn unsupported_target() -> anyhow::Error {
    anyhow!(
        "no release builds exist for this platform ({}-{}); build Dove from source instead",
        std::env::consts::ARCH,
        std::env::consts::OS
    )
}

async fn download(http: &reqwest::Client, url: &str, tag: &str, asset: &str, cap: usize) -> anyhow::Result<Vec<u8>> {
    let resp = http
        .get(url)
        .send()
        .await
        .map_err(|e| anyhow!("cannot download {asset} of release {tag} ({})", e.without_url()))?;
    match resp.status().as_u16() {
        200 => {}
        404 => bail!("release {tag} has no asset {asset} (not published, or no build for this platform)"),
        s => bail!("unexpected HTTP status {s} downloading {asset} of release {tag}"),
    }
    read_capped(resp, cap).await.with_context(|| format!("cannot download {asset} of release {tag}"))
}

async fn read_capped(mut resp: reqwest::Response, cap: usize) -> anyhow::Result<Vec<u8>> {
    if resp.content_length().is_some_and(|n| n > cap as u64) {
        bail!("response is larger than {cap} bytes");
    }
    let mut out = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if out.len() + chunk.len() > cap {
            bail!("response is larger than {cap} bytes");
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

/// Checks the minisign signature of `SHA256SUMS` and that its trusted comment names exactly this release.
pub fn verify_sums(public_key: &str, sums: &[u8], sig: &[u8], tag: &str) -> anyhow::Result<()> {
    let pk = minisign_verify::PublicKey::decode(public_key).map_err(|_| anyhow!("invalid release public key"))?;
    let sig = std::str::from_utf8(sig)
        .ok()
        .and_then(|s| minisign_verify::Signature::decode(s).ok())
        .ok_or_else(|| anyhow!("SHA256SUMS.minisig of release {tag} is not a valid minisign signature"))?;
    pk.verify(sums, &sig, false)
        .map_err(|_| anyhow!("signature check failed for SHA256SUMS of release {tag}: refusing to install"))?;
    let want = format!("dove {tag}");
    if sig.trusted_comment() != want {
        bail!("the signed SHA256SUMS belongs to another release ('{}', expected '{want}')", sig.trusted_comment());
    }
    Ok(())
}

/// The lowercase hex SHA-256 listed for `name` in a `sha256sum`-style list. Conflicting lines are an error.
pub fn expected_sha256(sums: &[u8], name: &str) -> anyhow::Result<Option<String>> {
    let text = std::str::from_utf8(sums).context("SHA256SUMS is not UTF-8")?;
    let mut found: Option<String> = None;
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let (hash, file) = line.split_once(' ').ok_or_else(|| anyhow!("SHA256SUMS has a malformed line"))?;
        // Text mode (`hash  name`) or binary mode (`hash *name`).
        let file = file.strip_prefix(' ').or_else(|| file.strip_prefix('*')).unwrap_or(file);
        if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("SHA256SUMS has a malformed line");
        }
        if file == name {
            let hash = hash.to_ascii_lowercase();
            if found.as_ref().is_some_and(|f| *f != hash) {
                bail!("SHA256SUMS lists {name} twice with different checksums");
            }
            found = Some(hash);
        }
    }
    Ok(found)
}

/// Takes the `dove` binary out of a release archive. The archive may hold only directories and regular files
/// below `dove-<tag>-<target>/`; any other entry type, absolute path or `..` component rejects the whole archive.
/// Nothing is written to disk here.
pub fn extract_binary(archive: &[u8], tag: &str, target: &str) -> anyhow::Result<Vec<u8>> {
    let top = format!("dove-{tag}-{target}");
    let wanted = Path::new(&top).join("dove");
    let gz = flate2::read::GzDecoder::new(archive).take(MAX_UNPACKED_BYTES);
    let mut ar = tar::Archive::new(gz);
    let mut binary: Option<Vec<u8>> = None;
    for entry in ar.entries().context("release archive is not a valid tar.gz")? {
        let mut e = entry.context("release archive is damaged")?;
        let path = e.path().context("release archive has an unreadable entry name")?.into_owned();
        if path.components().any(|c| !matches!(c, Component::Normal(_) | Component::CurDir)) {
            bail!("release archive contains an unsafe path ({}): refusing to install", path.display());
        }
        let mut parts = path.components().filter(|c| !matches!(c, Component::CurDir));
        if parts.next() != Some(Component::Normal(top.as_ref())) {
            bail!("release archive contains an entry outside {top}/: refusing to install");
        }
        let kind = e.header().entry_type();
        if kind.is_dir() {
            continue;
        }
        if !kind.is_file() {
            bail!("release archive contains a link or special file ({}): refusing to install", path.display());
        }
        let normalized: PathBuf = path.components().filter(|c| !matches!(c, Component::CurDir)).collect();
        if normalized != wanted {
            continue;
        }
        if binary.is_some() {
            bail!("release archive contains {} twice", wanted.display());
        }
        if e.header().size().unwrap_or(u64::MAX) > MAX_BINARY_BYTES {
            bail!("the dove binary in the release archive is too large");
        }
        let mut data = Vec::new();
        (&mut e).take(MAX_BINARY_BYTES + 1).read_to_end(&mut data).context("release archive is damaged")?;
        if data.len() as u64 > MAX_BINARY_BYTES {
            bail!("the dove binary in the release archive is too large");
        }
        binary = Some(data);
    }
    let binary = binary.ok_or_else(|| anyhow!("release archive has no {}", wanted.display()))?;
    if binary.is_empty() {
        bail!("the dove binary in the release archive is empty");
    }
    Ok(binary)
}

fn sudo_hint(dir: &Path) -> String {
    format!("{} is not writable by this user; run `sudo dove upgrade`", dir.display())
}

fn parent_dir(path: &Path) -> anyhow::Result<&Path> {
    path.parent().filter(|p| !p.as_os_str().is_empty()).ok_or_else(|| anyhow!("{} has no directory", path.display()))
}

fn temp_path(dir: &Path) -> PathBuf {
    dir.join(format!(".dove.upgrade-{}", crate::util::new_id()))
}

/// Fails early, before any download, when the binary's directory does not accept new files.
pub fn check_writable(exe: &Path) -> anyhow::Result<()> {
    let dir = parent_dir(exe)?;
    let tmp = temp_path(dir);
    match std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp) {
        Ok(_) => {
            let _ = std::fs::remove_file(&tmp);
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => Err(anyhow!(sudo_hint(dir))),
        Err(e) => Err(anyhow!("cannot write in {}: {e}", dir.display())),
    }
}

/// Replaces the file at `path` with `binary`: a temporary file in the same directory (mode 0755, synced) is renamed
/// over it, so readers see either the old or the new file, never a partial one. On any error the temporary file is
/// removed and `path` is untouched.
pub fn replace_binary(path: &Path, binary: &[u8]) -> anyhow::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let dir = parent_dir(path)?;
    let tmp = temp_path(dir);
    let mut f = match std::fs::OpenOptions::new().write(true).create_new(true).mode(0o700).open(&tmp) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return Err(anyhow!(sudo_hint(dir))),
        Err(e) => return Err(anyhow!("cannot write in {}: {e}", dir.display())),
    };
    let result = (|| -> anyhow::Result<()> {
        f.write_all(binary)?;
        // Explicit chmod: the creation mode is subject to the umask.
        f.set_permissions(std::fs::Permissions::from_mode(0o755))?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path).map_err(|e| match e.kind() {
            std::io::ErrorKind::PermissionDenied => anyhow!(sudo_hint(dir)),
            _ => anyhow!("cannot replace {}: {e}", path.display()),
        })?;
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Downloads, verifies and installs `version` over the binary at `exe`.
pub async fn install(src: &Source, http: &reqwest::Client, version: &Version, exe: &Path) -> anyhow::Result<()> {
    check_writable(exe)?;
    let binary = fetch_binary(src, http, version).await?;
    replace_binary(exe, &binary)
}

/// A container marker below `root` (`/.dockerenv`, `/run/.containerenv`), if any.
pub fn container_marker(root: &Path) -> Option<PathBuf> {
    [".dockerenv", "run/.containerenv"].iter().map(|m| root.join(m)).find(|p| p.exists())
}

/// The running binary's path, with symlinks resolved (the link stays, its target is replaced).
pub fn current_exe() -> anyhow::Result<PathBuf> {
    let exe = std::env::current_exe().context("cannot find the path of the running dove binary")?;
    std::fs::canonicalize(&exe).with_context(|| format!("cannot resolve {}", exe.display()))
}

/// Options of `dove upgrade`.
#[derive(Debug, Clone, Default)]
pub struct UpgradeOpts {
    pub check: bool,
    pub version: Option<String>,
    pub socket: PathBuf,
}

/// `dove upgrade` / `dove update`. Returns the process exit code.
pub async fn run_upgrade(opts: UpgradeOpts) -> anyhow::Result<u8> {
    let src = Source::github();
    let requested = opts.version.as_deref().map(parse_requested).transpose()?;
    if !opts.check && container_marker(Path::new("/")).is_some() {
        bail!("Dove runs inside a container here; update the image instead: {CONTAINER_HINT}");
    }
    let http = http_client(Duration::from_secs(300))?;
    let latest = if requested.is_none() { Some(latest_release(&src, &http).await?) } else { None };
    let decision = decide(&src.current, latest.as_ref(), requested.as_ref());
    let installed = tag(&src.current);
    if opts.check {
        return Ok(match decision {
            Decision::Install(v) => {
                println!("{}", notice::notice_text(&v, &src.current));
                EXIT_UPDATE_AVAILABLE
            }
            Decision::UpToDate { latest } => {
                println!("Dove {installed} is up to date (latest release {}).", tag(&latest));
                0
            }
            Decision::AlreadyInstalled => 0,
        });
    }
    let version = match decision {
        Decision::UpToDate { latest } => {
            println!("Dove {installed} is up to date (latest release {}).", tag(&latest));
            return Ok(0);
        }
        Decision::AlreadyInstalled => {
            println!("Dove {installed} is already installed.");
            return Ok(0);
        }
        Decision::Install(v) => v,
    };
    if src.target.is_none() {
        return Err(unsupported_target());
    }
    let exe = current_exe()?;
    eprintln!("Downloading Dove {} (installed {installed}) ...", tag(&version));
    install(&src, &http, &version, &exe).await?;
    println!("Dove {} installed at {}.", tag(&version), exe.display());
    if let Some(line) = service_hint(&opts.socket, &version).await {
        println!("{line}");
    }
    Ok(0)
}

/// After an upgrade: a restart hint when a local service answers on the admin socket and runs another version.
/// Unreachable sockets (no service here, not the operator) are ignored quietly.
async fn service_hint(socket: &Path, installed: &Version) -> Option<String> {
    let req = crate::admin::AdminRequest::Version;
    let reply = tokio::time::timeout(Duration::from_secs(5), crate::admin::client::send(socket, &req)).await.ok()?;
    match reply {
        Ok(v) => restart_hint(Some(&v), installed),
        // Socket missing or not ours: no service to talk about.
        Err(e) if e.downcast_ref::<std::io::Error>().is_some() => None,
        // The service answered but not with a version (releases without the `version` verb).
        Err(_) => restart_hint(None, installed),
    }
}

/// The restart hint for an admin `version` reply (`None`: the service answered without a version).
pub fn restart_hint(reply: Option<&serde_json::Value>, installed: &Version) -> Option<String> {
    const RESTART: &str = "sudo systemctl restart dove";
    let new = tag(installed);
    match reply.and_then(|r| r["version"].as_str()) {
        Some(v) if v == installed.to_string() => None,
        Some(v) => Some(format!("The Dove service still runs v{v}; restart it to use {new}: {RESTART}")),
        None => Some(format!(
            "Could not read the version of the running Dove service (it may run an older release); restart it to \
             use {new}: {RESTART}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_comes_from_the_repository_url() {
        assert_eq!(repo_slug(), "dominik-lenhart/dove");
        let src = Source::github();
        assert_eq!(src.latest_url(), "https://api.github.com/repos/dominik-lenhart/dove/releases/latest");
        assert_eq!(
            src.asset_url("v1.2.3", "SHA256SUMS"),
            "https://github.com/dominik-lenhart/dove/releases/download/v1.2.3/SHA256SUMS"
        );
    }

    #[test]
    fn embedded_release_key_decodes() {
        minisign_verify::PublicKey::decode(RELEASE_PUBLIC_KEY).unwrap();
    }

    #[test]
    fn tags_and_requested_versions() {
        assert_eq!(parse_tag("v0.2.0").unwrap(), Version::new(0, 2, 0));
        for bad in ["0.2.0", "v0.2", "v0.2.0-rc.1", "v0.2.0+build", "vx", ""] {
            assert!(parse_tag(bad).is_err(), "{bad}");
        }
        assert_eq!(parse_requested("0.3.1").unwrap(), Version::new(0, 3, 1));
        assert_eq!(parse_requested("v0.3.1").unwrap(), Version::new(0, 3, 1));
        assert!(parse_requested("latest").is_err());
    }

    #[test]
    fn downgrades_only_when_requested() {
        let v = |s: &str| Version::parse(s).unwrap();
        let cur = v("0.3.0");
        assert_eq!(decide(&cur, Some(&v("0.2.0")), None), Decision::UpToDate { latest: v("0.2.0") });
        assert_eq!(decide(&cur, Some(&v("0.3.0")), None), Decision::UpToDate { latest: v("0.3.0") });
        assert_eq!(decide(&cur, Some(&v("0.3.1")), None), Decision::Install(v("0.3.1")));
        assert_eq!(decide(&cur, None, Some(&v("0.2.0"))), Decision::Install(v("0.2.0")));
        assert_eq!(decide(&cur, None, Some(&v("0.3.0"))), Decision::AlreadyInstalled);
    }

    #[test]
    fn checksum_list_parsing() {
        let a = "a".repeat(64);
        let b = "B".repeat(64);
        let sums = format!("{a}  dove-v1-x.tar.gz\n{b} *dove-v1-y.tar.gz\n\n");
        assert_eq!(expected_sha256(sums.as_bytes(), "dove-v1-x.tar.gz").unwrap(), Some(a.clone()));
        assert_eq!(expected_sha256(sums.as_bytes(), "dove-v1-y.tar.gz").unwrap(), Some("b".repeat(64)));
        assert_eq!(expected_sha256(sums.as_bytes(), "dove-v1-z.tar.gz").unwrap(), None);
        let twice = format!("{a}  n\n{}  n\n", "c".repeat(64));
        assert!(expected_sha256(twice.as_bytes(), "n").is_err());
        assert!(expected_sha256(b"xyz  n\n", "n").is_err());
    }

    #[test]
    fn restart_hint_wording() {
        let v = Version::new(0, 2, 0);
        assert_eq!(restart_hint(Some(&serde_json::json!({ "version": "0.2.0" })), &v), None);
        let h = restart_hint(Some(&serde_json::json!({ "version": "0.1.0" })), &v).unwrap();
        assert!(h.contains("still runs v0.1.0") && h.contains("sudo systemctl restart dove"), "{h}");
        assert!(restart_hint(None, &v).unwrap().contains("older release"));
    }

    /// Builds a tar.gz from (path, entry type, data). The signed fixtures in tests/ cover traversal and symlinks;
    /// these cover the archive shape rules that need no signature.
    fn tar_gz(entries: &[(&str, tar::EntryType, &[u8])]) -> Vec<u8> {
        let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        let mut b = tar::Builder::new(gz);
        for (path, kind, data) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(*kind);
            h.set_mode(0o755);
            h.set_size(data.len() as u64);
            if kind.is_hard_link() {
                h.set_size(0);
                b.append_link(&mut h, path, "dove-v1.0.0-t/README.md").unwrap();
            } else {
                b.append_data(&mut h, path, *data).unwrap();
            }
        }
        b.into_inner().unwrap().finish().unwrap()
    }

    #[test]
    fn archive_shape_rules() {
        use tar::EntryType::{Directory as D, Link as L, Regular as F};
        let ok = |e: &[(&str, tar::EntryType, &[u8])]| extract_binary(&tar_gz(e), "v1.0.0", "t");
        let bin: &[u8] = b"binary";
        assert_eq!(ok(&[("dove-v1.0.0-t/", D, b""), ("dove-v1.0.0-t/dove", F, bin)]).unwrap(), bin);
        assert_eq!(ok(&[("./dove-v1.0.0-t/README.md", F, b"r"), ("./dove-v1.0.0-t/dove", F, bin)]).unwrap(), bin);
        let refused = |e: &[(&str, tar::EntryType, &[u8])], why: &str| {
            let err = format!("{:#}", ok(e).unwrap_err());
            assert!(err.contains(why), "{err}");
        };
        refused(&[("dove-v1.0.0-t/dove", F, bin), ("other/dove", F, bin)], "outside dove-v1.0.0-t/");
        refused(&[("dove-v0.9.0-t/dove", F, bin)], "outside dove-v1.0.0-t/");
        refused(&[("dove-v1.0.0-t/dove", F, bin), ("dove-v1.0.0-t/dove", F, bin)], "twice");
        refused(&[("dove-v1.0.0-t/README.md", F, b"r")], "has no dove-v1.0.0-t/dove");
        refused(&[("dove-v1.0.0-t/dove", F, b"")], "empty");
        refused(&[("dove-v1.0.0-t/README.md", F, b"r"), ("dove-v1.0.0-t/dove", L, b"")], "link or special file");
        refused(&[("dove-v1.0.0-t/dove/x", F, bin)], "has no");
        assert!(extract_binary(b"not a gzip stream", "v1.0.0", "t").is_err());
    }

    #[test]
    fn container_markers() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(container_marker(d.path()), None);
        std::fs::create_dir_all(d.path().join("run")).unwrap();
        std::fs::write(d.path().join("run/.containerenv"), "").unwrap();
        assert_eq!(container_marker(d.path()), Some(d.path().join("run/.containerenv")));
        std::fs::write(d.path().join(".dockerenv"), "").unwrap();
        assert_eq!(container_marker(d.path()), Some(d.path().join(".dockerenv")));
    }
}
