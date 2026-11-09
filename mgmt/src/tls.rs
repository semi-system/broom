// tls.rs — HTTPS for the web admin. At first start Broom makes itself a self-signed certificate (the server's name and
// addresses); an owner can upload their own (System page: certificate + key, PEM) or make a new self-signed one —
// either takes effect at once, no restart. The admin pages are served on :443; on :80 a browser asking for them (or for
// the sign-in) is sent to https://, the admin API refused. Everything the machines use stays on plain HTTP — iPXE, the
// boot files, Windows PE, the agents and the scripts on the clients (`auth::is_public`): they cannot check a
// self-signed certificate, and they need no secret from this channel.
// The session cookie gets `Secure` on HTTPS, so a browser never sends it over plain HTTP.
// Why: the sign-in never sends the password (password-proof handshake), but the session cookie and everything an
// admin does (machines, keys, remote screens) went over the LAN in clear text. Self-signed by default so it works out of
// the box with no domain or internet; an owner who has a real certificate uploads it. Machine traffic stays on HTTP on
// purpose: iPXE, Windows PE and the agents cannot check a self-signed certificate, and what they fetch is public (boot
// files, scripts) or allowed by other checks (the agent's key, a machine's IP + MAC).
use axum::{
    Json, Router,
    body::Body,
    extract::State,
    http::{Request, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio_rustls::rustls;

use crate::SharedState;
use crate::api::{ApiError, bad, ise};
use crate::pwproof::hex;

pub fn routes() -> Router<SharedState> {
    Router::new()
        .route("/api/config/tls", get(status))
        .route("/api/config/tls", post(set))
        .route("/api/tls/cert", get(for_tools))
        .route("/api/config/tls/cert.pem", get(download))
}

/// GET /api/config/tls/cert.pem — the certificate in use, to install on the staff PCs.
async fn download() -> Result<impl IntoResponse, ApiError> {
    let pem = tokio::task::spawn_blocking(|| std::fs::read_to_string(files().0))
        .await
        .map_err(ise)?
        .map_err(ise)?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/x-pem-file"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"broom.crt\"",
            ),
        ],
        pem,
    ))
}

/// The HTTPS listener is up (redirects from :80 only then).
static LISTENING: AtomicBool = AtomicBool::new(false);

/// Config key: "off" = admin pages over plain HTTP too (default on).
const ON_KEY: &str = "https";
/// Config key: what the certificate is (JSON Meta).
const META_KEY: &str = "tls_meta";

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub(crate) struct Meta {
    /// "self-signed" | "uploaded"
    pub kind: String,
    /// Names it was made for (self-signed).
    #[serde(default)]
    pub names: Vec<String>,
    /// SHA-256 of the certificate (DER), hex — what a browser shows to compare.
    pub sha256: String,
    pub since: u64,
    /// When it stops being valid (unix seconds; 0 = not known).
    #[serde(default)]
    pub until: u64,
}

fn dir() -> PathBuf {
    crate::home().join("tls")
}

fn files() -> (PathBuf, PathBuf) {
    (dir().join("cert.pem"), dir().join("key.pem"))
}

pub(crate) fn enabled(st: &SharedState) -> bool {
    st.db.get_config(ON_KEY, "on") != "off"
}

/// The certificate in use, swapped in place by an upload.
struct Resolver(RwLock<Arc<rustls::sign::CertifiedKey>>);

impl std::fmt::Debug for Resolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Resolver")
    }
}

impl rustls::server::ResolvesServerCert for Resolver {
    fn resolve(
        &self,
        _: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.0.read().clone())
    }
}

static RESOLVER: std::sync::OnceLock<Arc<Resolver>> = std::sync::OnceLock::new();

/// PEM certificate chain + private key → what rustls serves, and the leaf's SHA-256.
pub(crate) fn certified(
    cert_pem: &str,
    key_pem: &str,
) -> Result<(rustls::sign::CertifiedKey, String), String> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .collect::<Result<_, _>>()
        .map_err(|e| format!("certificate: {e}"))?;
    let leaf = chain.first().ok_or("no certificate in the PEM text")?;
    let digest: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(leaf.as_ref()).into();
    let sha = hex(&digest);
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
        .map_err(|e| format!("private key: {e}"))?;
    let signer = rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|e| format!("private key: {e}"))?;
    let ck = rustls::sign::CertifiedKey::new(chain, signer);
    ck.keys_match()
        .map_err(|_| "the key does not belong to the certificate".to_string())?;
    Ok((ck, sha))
}

/// The server's own names: its host name, its IPv4 addresses (boot LAN and others), localhost.
fn own_names(st: &SharedState) -> Vec<String> {
    let mut v = vec!["localhost".to_string(), "127.0.0.1".to_string()];
    let host = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .unwrap_or_default()
        .trim()
        .to_string();
    if !host.is_empty() {
        v.push(host);
    }
    for ip in local_ipv4s()
        .into_iter()
        .chain([st.db.get_config("dhcp_server_ip", "")])
    {
        if !ip.is_empty() && !v.contains(&ip) {
            v.push(ip);
        }
    }
    v
}

/// The IPv4 addresses on this host's interfaces (getifaddrs).
pub(crate) fn local_ipv4s() -> Vec<String> {
    local_ipv4_nets()
        .into_iter()
        .map(|(ip, _)| ip.to_string())
        .collect()
}

/// The IPv4 addresses on this host's interfaces with their netmasks (getifaddrs), loopback left out.
pub(crate) fn local_ipv4_nets() -> Vec<(std::net::Ipv4Addr, std::net::Ipv4Addr)> {
    let mut out = Vec::new();
    // SAFETY: getifaddrs fills a list freed with freeifaddrs; each entry read only while the list lives.
    unsafe {
        let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut list) != 0 {
            return out;
        }
        let v4 = |a: *const libc::sockaddr| {
            (!a.is_null() && i32::from((*a).sa_family) == libc::AF_INET).then(|| {
                let sin = &*(a as *const libc::sockaddr_in);
                std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr))
            })
        };
        let mut p = list;
        while !p.is_null() {
            if let Some(ip) = v4((*p).ifa_addr).filter(|ip| !ip.is_loopback()) {
                let mask = v4((*p).ifa_netmask).unwrap_or(std::net::Ipv4Addr::BROADCAST);
                out.push((ip, mask));
            }
            p = (*p).ifa_next;
        }
        libc::freeifaddrs(list);
    }
    out
}

/// `other` is on the subnet of this host's address `local` (its interface's netmask). False when `local` is not one
/// of this host's addresses or either is not an IPv4 address.
pub(crate) fn on_subnet_of(local: &str, other: &str) -> bool {
    let (Ok(l), Ok(o)) = (
        local.trim().parse::<std::net::Ipv4Addr>(),
        other.trim().parse::<std::net::Ipv4Addr>(),
    ) else {
        return false;
    };
    local_ipv4_nets()
        .into_iter()
        .any(|(ip, mask)| ip == l && same_subnet(l, mask, o))
}

/// `a` and `b` are on one subnet with netmask `mask`.
pub(crate) fn same_subnet(
    a: std::net::Ipv4Addr,
    mask: std::net::Ipv4Addr,
    b: std::net::Ipv4Addr,
) -> bool {
    let m = u32::from(mask);
    u32::from(a) & m == u32::from(b) & m
}

/// How long a self-signed certificate is valid. Apple's systems refuse any TLS server certificate valid for more than
/// 825 days (support.apple.com/103769); Broom makes a new one by itself when this one has RENEW_S left.
const VALID_S: u64 = 820 * 86400;
const RENEW_S: u64 = 30 * 86400;

/// A new self-signed certificate for `names`, valid from a day ago (a client's clock a little behind) for VALID_S:
/// (cert PEM, key PEM, valid until). ECDSA P-256; Server Authentication usage (Apple requires it).
pub(crate) fn self_signed(names: &[String], now: u64) -> Result<(String, String, u64), String> {
    let mut params = rcgen::CertificateParams::new(names.to_vec()).map_err(|e| e.to_string())?;
    let who = names
        .iter()
        .find(|n| *n != "localhost" && *n != "127.0.0.1")
        .cloned()
        .unwrap_or_default();
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        format!("Broom {who}").trim().to_string(),
    );
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let from = now.saturating_sub(86400);
    let until = from + VALID_S;
    let at =
        |t: u64| time::OffsetDateTime::from_unix_timestamp(t as i64).map_err(|e| e.to_string());
    params.not_before = at(from)?;
    params.not_after = at(until)?;
    let key = rcgen::KeyPair::generate().map_err(|e| e.to_string())?;
    let cert = params.self_signed(&key).map_err(|e| e.to_string())?;
    Ok((cert.pem(), key.serialize_pem(), until))
}

/// Make and use a new self-signed certificate for this server's current names.
fn new_self_signed(st: &SharedState) -> Result<Meta, String> {
    let names = own_names(st);
    let now = crate::now_secs();
    let (cert, key, until) = self_signed(&names, now)?;
    let (_, sha) = certified(&cert, &key)?;
    let meta = Meta {
        kind: "self-signed".into(),
        names,
        sha256: sha,
        since: now,
        until,
    };
    install(st, &cert, &key, meta.clone())?;
    Ok(meta)
}

/// Write cert + key (key readable by root only), then use them.
fn install(st: &SharedState, cert: &str, key: &str, meta: Meta) -> Result<(), String> {
    let (ck, _) = certified(cert, key)?;
    std::fs::create_dir_all(dir()).map_err(|e| e.to_string())?;
    let (c, k) = files();
    crate::versions::write_durable(&k, key.as_bytes())
        .map_err(|e| format!("{}: {e}", k.display()))?;
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&k, std::fs::Permissions::from_mode(0o600));
    }
    crate::versions::write_durable(&c, cert.as_bytes())
        .map_err(|e| format!("{}: {e}", c.display()))?;
    st.db
        .set_config(META_KEY, &serde_json::to_string(&meta).unwrap())
        .map_err(|e| e.to_string())?;
    if let Some(r) = RESOLVER.get() {
        *r.0.write() = Arc::new(ck);
    }
    Ok(())
}

fn meta(st: &SharedState) -> Meta {
    serde_json::from_str(&st.db.get_config(META_KEY, "{}")).unwrap_or_default()
}

/// The certificate to serve: the saved one, else a new self-signed one (first start, or the files are gone).
fn load_or_make(st: &SharedState) -> Result<rustls::sign::CertifiedKey, String> {
    let (c, k) = files();
    if let (Ok(cert), Ok(key)) = (std::fs::read_to_string(&c), std::fs::read_to_string(&k)) {
        match certified(&cert, &key) {
            Ok((ck, _)) => return Ok(ck),
            Err(e) => tracing::warn!(
                "https: {} unusable ({e}) — making a new self-signed one",
                c.display()
            ),
        }
    }
    let m = new_self_signed(st)?;
    tracing::info!(
        "https: self-signed certificate made for {}",
        m.names.join(", ")
    );
    let (cert, key) = (
        std::fs::read_to_string(&c).map_err(|e| e.to_string())?,
        std::fs::read_to_string(&k).map_err(|e| e.to_string())?,
    );
    certified(&cert, &key).map(|(ck, _)| ck)
}

/// A self-signed certificate close to its end → a new one (checked at start and daily). An uploaded one is the
/// owner's to renew (the System page shows its end date).
fn renew_if_due(st: &SharedState) {
    let m = meta(st);
    if m.kind == "self-signed" && m.until > 0 && m.until <= crate::now_secs() + RENEW_S {
        match new_self_signed(st) {
            Ok(_) => tracing::warn!(
                "https: self-signed certificate renewed (browsers ask to accept it again)"
            ),
            Err(e) => tracing::warn!("https: self-signed certificate not renewed: {e}"),
        }
    }
}

/// The end date (unix seconds) of the leaf certificate in `cert_pem`, 0 if unreadable.
pub(crate) fn not_after(cert_pem: &str) -> u64 {
    use rustls::pki_types::{CertificateDer, pem::PemObject};
    let Some(Ok(der)) = CertificateDer::pem_slice_iter(cert_pem.as_bytes()).next() else {
        return 0;
    };
    der_not_after(der.as_ref()).unwrap_or(0)
}

/// One DER element at the start of `b`: (tag, contents, rest).
fn der(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, b) = b.split_first()?;
    let (&l0, mut b) = b.split_first()?;
    let len = if l0 < 0x80 {
        l0 as usize
    } else {
        let n = (l0 & 0x7f) as usize;
        if n == 0 || n > 4 || b.len() < n {
            return None;
        }
        let v = b[..n].iter().fold(0usize, |a, &x| (a << 8) | x as usize);
        b = &b[n..];
        v
    };
    (b.len() >= len).then(|| (tag, &b[..len], &b[len..]))
}

/// A certificate's notAfter (X.509: Certificate → tbsCertificate → [version] serial sigAlg issuer validity), unix seconds.
pub(crate) fn der_not_after(cert: &[u8]) -> Option<u64> {
    let (0x30, c, _) = der(cert)? else {
        return None;
    };
    let (0x30, mut t, _) = der(c)? else {
        return None;
    };
    if t.first() == Some(&0xa0) {
        t = der(t)?.2; // version
    }
    for _ in 0..3 {
        t = der(t)?.2; // serial, signature algorithm, issuer
    }
    let (0x30, v, _) = der(t)? else { return None };
    let (_, _, v) = der(v)?; // notBefore
    let (tag, s, _) = der(v)?;
    let s = std::str::from_utf8(s).ok()?;
    let (y, rest) = match tag {
        0x17 => {
            let yy: i32 = s.get(0..2)?.parse().ok()?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, s.get(2..)?)
        }
        0x18 => (s.get(0..4)?.parse().ok()?, s.get(4..)?),
        _ => return None,
    };
    let n = |i: usize| -> Option<u8> { rest.get(i..i + 2)?.parse().ok() };
    let date = time::Date::from_calendar_date(y, time::Month::try_from(n(0)?).ok()?, n(2)?).ok()?;
    let at = time::PrimitiveDateTime::new(date, time::Time::from_hms(n(4)?, n(6)?, n(8)?).ok()?);
    u64::try_from(at.assume_utc().unix_timestamp()).ok()
}

/// HTTPS connections, their TLS handshakes done concurrently (a slow client never holds the others up).
pub struct Listener {
    rx: tokio::sync::mpsc::Receiver<(
        tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
        SocketAddr,
    )>,
    local: SocketAddr,
}

impl axum::serve::Listener for Listener {
    type Io = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
    type Addr = SocketAddr;
    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.rx.recv().await {
            Some(x) => x,
            None => std::future::pending().await,
        }
    }
    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(self.local)
    }
}

/// Bind the HTTPS port with the saved (or a new self-signed) certificate. Err: HTTPS stays off (logged by the caller).
pub async fn listen(st: &SharedState, port: u16) -> Result<Listener, String> {
    let st2 = st.clone();
    let ck = tokio::task::spawn_blocking(move || {
        renew_if_due(&st2);
        load_or_make(&st2)
    })
    .await
    .map_err(|e| e.to_string())??;
    let st3 = st.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(86400)).await;
            let st = st3.clone();
            let _ = tokio::task::spawn_blocking(move || renew_if_due(&st)).await;
        }
    });
    let resolver = RESOLVER
        .get_or_init(|| Arc::new(Resolver(RwLock::new(Arc::new(ck.clone())))))
        .clone();
    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| e.to_string())?
    .with_no_client_auth()
    .with_cert_resolver(resolver);
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let tcp = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .map_err(|e| format!("bind https :{port}: {e}"))?;
    let local = tcp.local_addr().map_err(|e| e.to_string())?;
    let (tx, rx) = tokio::sync::mpsc::channel(64);
    tokio::spawn(async move {
        loop {
            let Ok((sock, peer)) = tcp.accept().await else {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                continue;
            };
            let (acceptor, tx) = (acceptor.clone(), tx.clone());
            tokio::spawn(async move {
                if let Ok(Ok(s)) =
                    tokio::time::timeout(std::time::Duration::from_secs(10), acceptor.accept(sock))
                        .await
                {
                    let _ = tx.send((s, peer)).await;
                }
            });
        }
    });
    LISTENING.store(true, Ordering::Relaxed);
    Ok(Listener { rx, local })
}

/// HTTPS side: the session cookie only ever travels encrypted.
pub async fn secure_cookies(req: Request<Body>, next: Next) -> Response {
    let mut res = next.run(req).await;
    let v: Vec<String> = res
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .map(|s| {
            if s.contains("; Secure") {
                s.to_string()
            } else {
                format!("{s}; Secure")
            }
        })
        .collect();
    if !v.is_empty() {
        res.headers_mut().remove(header::SET_COOKIE);
        for c in v {
            if let Ok(h) = header::HeaderValue::from_str(&c) {
                res.headers_mut().append(header::SET_COOKIE, h);
            }
        }
    }
    res
}

/// What plain HTTP does with a request while HTTPS is on: None = serve it (the machines' paths), Some(Ok(url)) =
/// send the browser there, Some(Err) = refuse (the admin API).
pub(crate) fn plain_http(
    method: &axum::http::Method,
    path_q: &str,
    host: &str,
    https_port: u16,
) -> Option<Result<String, ()>> {
    let path = path_q.split('?').next().unwrap_or(path_q);
    let admin = path == "/login"
        || path.starts_with("/api/auth/")
        || path == "/api/password"
        || !crate::auth::is_public(method, path);
    if !admin {
        return None;
    }
    let name = match host.strip_prefix('[') {
        Some(v6) => format!("[{}]", v6.split(']').next().unwrap_or("")),
        None => host.rsplit_once(':').map_or(host, |(h, _)| h).to_string(),
    };
    if !matches!(*method, axum::http::Method::GET | axum::http::Method::HEAD) || name.is_empty() {
        return Some(Err(()));
    }
    let port = if https_port == 443 {
        String::new()
    } else {
        format!(":{https_port}")
    };
    Some(Ok(format!("https://{name}{port}{path_q}")))
}

/// HTTP side (:80): while HTTPS is up and on, admin pages → https://, admin API → 403.
pub async fn http_side(State(st): State<SharedState>, req: Request<Body>, next: Next) -> Response {
    if !LISTENING.load(Ordering::Relaxed) || !enabled(&st) {
        return next.run(req).await;
    }
    // The capture tool (capture.rs) when it cannot check the certificate: it says so; a browser never sends this
    // header on its own (and its Secure cookie never travels on plain HTTP anyway).
    if req
        .headers()
        .get("x-broom-tool")
        .is_some_and(|v| v == "capture")
    {
        return next.run(req).await;
    }
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();
    let pq = req
        .uri()
        .path_and_query()
        .map_or("/", |p| p.as_str())
        .to_string();
    match plain_http(req.method(), &pq, &host, HTTPS_PORT.load(Ordering::Relaxed)) {
        None => next.run(req).await,
        Some(Ok(url)) => {
            (StatusCode::PERMANENT_REDIRECT, [(header::LOCATION, url)]).into_response()
        }
        Some(Err(())) => {
            (StatusCode::FORBIDDEN, "the web admin is on https:// only").into_response()
        }
    }
}

/// The HTTPS port (for redirects).
pub static HTTPS_PORT: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(443);

/// GET /api/config/tls — {https, listening, kind, names, sha256, since}.
async fn status(State(st): State<SharedState>) -> Json<serde_json::Value> {
    let m = meta(&st);
    Json(serde_json::json!({
        "https": enabled(&st),
        "listening": LISTENING.load(Ordering::Relaxed),
        "port": HTTPS_PORT.load(Ordering::Relaxed),
        "kind": m.kind, "names": m.names, "sha256": m.sha256, "since": m.since, "until": m.until,
    }))
}

/// GET /api/tls/cert (public, plain HTTP) — for the capture tool: the HTTPS port (0 = none) and, while the server's own
/// self-signed certificate is in use, that certificate (PEM) to trust exactly.
async fn for_tools(State(st): State<SharedState>) -> Json<serde_json::Value> {
    let on = LISTENING.load(Ordering::Relaxed) && enabled(&st);
    let m = meta(&st);
    let self_signed = m.kind == "self-signed";
    let cert = if on && self_signed {
        tokio::task::spawn_blocking(|| std::fs::read_to_string(files().0).unwrap_or_default())
            .await
            .unwrap_or_default()
    } else {
        String::new()
    };
    Json(serde_json::json!({
        "port": if on { HTTPS_PORT.load(Ordering::Relaxed) } else { 0 },
        "self_signed": self_signed,
        "cert": cert,
    }))
}

#[derive(Deserialize)]
struct SetBody {
    /// Admin pages on HTTPS only (true) or on plain HTTP too.
    #[serde(default)]
    https: Option<bool>,
    /// Your own certificate (chain, PEM) + its private key (PEM).
    #[serde(default)]
    cert: Option<String>,
    #[serde(default)]
    key: Option<String>,
    /// Make a new self-signed certificate (e.g. the server's address changed).
    #[serde(default)]
    self_signed: bool,
}

/// POST /api/config/tls {https?} | {cert, key} | {self_signed: true} (owner).
async fn set(
    State(st): State<SharedState>,
    Json(b): Json<SetBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if let Some(on) = b.https {
        st.db
            .set_config(ON_KEY, if on { "on" } else { "off" })
            .map_err(ise)?;
        tracing::warn!(
            "https: admin pages {}",
            if on {
                "on HTTPS only"
            } else {
                "on plain HTTP too"
            }
        );
    }
    if let (Some(cert), Some(key)) = (b.cert.as_deref(), b.key.as_deref()) {
        let (_, sha) = certified(cert, key).map_err(bad)?;
        let st2 = st.clone();
        let (c, k) = (cert.to_string(), key.to_string());
        let meta = Meta {
            kind: "uploaded".into(),
            names: vec![],
            sha256: sha.clone(),
            since: crate::now_secs(),
            until: not_after(cert),
        };
        tokio::task::spawn_blocking(move || install(&st2, &c, &k, meta))
            .await
            .map_err(ise)?
            .map_err(ise)?;
        tracing::warn!("https: uploaded certificate in use (sha256 {sha})");
    } else if b.cert.is_some() || b.key.is_some() {
        return Err(bad("both the certificate and its key, PEM"));
    }
    if b.self_signed {
        let st2 = st.clone();
        tokio::task::spawn_blocking(move || new_self_signed(&st2))
            .await
            .map_err(ise)?
            .map_err(ise)?;
        tracing::warn!("https: new self-signed certificate in use");
    }
    Ok(status(State(st)).await)
}

#[cfg(test)]
#[path = "../tests/unit/tls.rs"]
mod tests;
