use super::*;
use axum::http::Method;

fn names() -> Vec<String> {
    ["localhost", "127.0.0.1", "broom", "10.20.0.1"]
        .map(String::from)
        .to_vec()
}

/// The self-signed certificate: loads as what rustls serves, its key matches, it lasts VALID_S (Apple: ≤ 825 days)
/// from a day before now, its fingerprint is a SHA-256.
#[test]
fn self_signed_certificate() {
    let now = 1_790_000_000;
    let (cert, key, until) = self_signed(&names(), now).unwrap();
    assert!(cert.starts_with("-----BEGIN CERTIFICATE-----"));
    assert!(key.contains("PRIVATE KEY"));
    let (_, sha) = certified(&cert, &key).unwrap();
    assert_eq!(sha.len(), 64);
    assert!(sha.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(until, now - 86400 + VALID_S);
    const {
        assert!(
            VALID_S <= 825 * 86400,
            "Apple refuses longer TLS server certificates"
        )
    };
    assert_eq!(
        not_after(&cert),
        until,
        "the end date read back from the certificate"
    );
    // Two certificates never share a key (nor a fingerprint).
    let (cert2, key2, _) = self_signed(&names(), now).unwrap();
    assert_ne!(certified(&cert2, &key2).unwrap().1, sha);
}

/// An upload whose key belongs to another certificate, or that is not PEM, is refused.
#[test]
fn upload_checked() {
    let (cert, _, _) = self_signed(&names(), 1_790_000_000).unwrap();
    let (_, other_key, _) = self_signed(&names(), 1_790_000_000).unwrap();
    let e = certified(&cert, &other_key).err().unwrap();
    assert!(e.contains("does not belong"), "{e}");
    assert!(certified("hello", &other_key).is_err());
    assert!(certified(&cert, "hello").is_err());
    assert_eq!(not_after("not a certificate"), 0);
}

/// X.509 dates both ways: UTCTime (YYMMDD…, 1950–2049) and GeneralizedTime (YYYYMMDD…).
#[test]
fn certificate_end_dates() {
    // 2049-12-31 23:59:59 = UTCTime; 2050-01-01 = GeneralizedTime (RFC 5280: from 2050 on).
    for (end, kind) in [
        (2_524_607_999, "UTCTime"),
        (2_524_608_000, "GeneralizedTime"),
    ] {
        let (cert, _, until) = self_signed(&names(), end + 86400 - VALID_S).unwrap();
        assert_eq!(until, end);
        assert_eq!(not_after(&cert), end, "{kind}");
    }
}

/// While HTTPS is on, plain HTTP: the machines' paths are served; a browser asking for an admin page (or the
/// sign-in) is sent to the same path on https://; the admin API is refused.
#[test]
fn plain_http_rules() {
    let get = Method::GET;
    let post = Method::POST;
    // Machines (iPXE, scripts, agents, boot files): served.
    for p in [
        "/boot.ipxe",
        "/tftp/broom-stage/vmlinuz",
        "/api/vnc/agent",
        "/broom-diskless.ps1",
        "/api/tls/cert",
    ] {
        assert_eq!(plain_http(&get, p, "10.20.0.1", 443), None, "{p}");
    }
    assert_eq!(
        plain_http(&post, "/api/diskless/client/base-done", "10.20.0.1", 443),
        None
    );
    // The login page's stylesheet etc.: harmless either way.
    assert_eq!(plain_http(&get, "/app.css", "10.20.0.1", 443), None);
    // Admin pages → https, same host (without the HTTP port) and path + query.
    assert_eq!(
        plain_http(&get, "/", "10.20.0.1", 443),
        Some(Ok("https://10.20.0.1/".into()))
    );
    assert_eq!(
        plain_http(&get, "/machines?x=1", "broom:8080", 443),
        Some(Ok("https://broom/machines?x=1".into()))
    );
    assert_eq!(
        plain_http(&get, "/login", "10.20.0.1", 8443),
        Some(Ok("https://10.20.0.1:8443/login".into()))
    );
    assert_eq!(
        plain_http(&Method::HEAD, "/app.js", "[fe80::1]:80", 443),
        Some(Ok("https://[fe80::1]/app.js".into()))
    );
    // The admin API and the sign-in over plain HTTP: refused.
    assert_eq!(
        plain_http(&post, "/api/auth/login", "10.20.0.1", 443),
        Some(Err(()))
    );
    assert_eq!(
        plain_http(&get, "/api/auth/status", "10.20.0.1", 443),
        Some(Ok("https://10.20.0.1/api/auth/status".into()))
    );
    assert_eq!(
        plain_http(&post, "/api/power", "10.20.0.1", 443),
        Some(Err(()))
    );
    assert_eq!(
        plain_http(&Method::PUT, "/api/images/upload-chunk", "10.20.0.1", 443),
        Some(Err(()))
    );
    // No Host: nowhere to send it.
    assert_eq!(plain_http(&get, "/", "", 443), Some(Err(())));
}

/// The capture tool's way in: a TLS client that trusts exactly the server's self-signed certificate (as ureq does with
/// RootCerts::Specific) completes the handshake when it connects by one of the server's addresses, and not by another
/// address or against another certificate.
#[test]
fn pinned_self_signed_handshake() {
    use rustls::pki_types::{CertificateDer, ServerName, pem::PemObject};
    let (cert, key, _) = self_signed(&names(), crate::now_secs()).unwrap();
    let (ck, _) = certified(&cert, &key).unwrap();
    let resolver = Arc::new(Resolver(RwLock::new(Arc::new(ck))));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server = Arc::new(
        rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(resolver),
    );
    let handshake = |trust: &str, name: &str| -> Result<(), rustls::Error> {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from_pem_slice(trust.as_bytes()).unwrap())
            .unwrap();
        let client = Arc::new(
            rustls::ClientConfig::builder_with_provider(provider.clone())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let mut c =
            rustls::ClientConnection::new(client, ServerName::try_from(name.to_string()).unwrap())
                .unwrap();
        let mut s = rustls::ServerConnection::new(server.clone()).unwrap();
        for _ in 0..10 {
            let mut buf = Vec::new();
            c.write_tls(&mut buf).unwrap();
            s.read_tls(&mut buf.as_slice()).unwrap();
            s.process_new_packets()?;
            let mut buf = Vec::new();
            s.write_tls(&mut buf).unwrap();
            c.read_tls(&mut buf.as_slice()).unwrap();
            c.process_new_packets()?;
            if !c.is_handshaking() && !s.is_handshaking() {
                return Ok(());
            }
        }
        Err(rustls::Error::General("handshake did not finish".into()))
    };
    handshake(&cert, "10.20.0.1").expect("trusted, by its address");
    handshake(&cert, "broom").expect("trusted, by its host name");
    assert!(
        handshake(&cert, "10.20.0.9").is_err(),
        "an address it was not made for"
    );
    let (other, _, _) = self_signed(&names(), crate::now_secs()).unwrap();
    assert!(
        handshake(&other, "10.20.0.1").is_err(),
        "another certificate"
    );
}

#[test]
fn subnets() {
    let ip = |s: &str| s.parse::<std::net::Ipv4Addr>().unwrap();
    let m24 = ip("255.255.255.0");
    assert!(same_subnet(ip("192.168.1.111"), m24, ip("192.168.1.121")));
    assert!(!same_subnet(ip("192.168.1.111"), m24, ip("192.168.2.121")));
    assert!(!same_subnet(ip("192.168.1.111"), m24, ip("10.20.0.21")));
    assert!(same_subnet(
        ip("10.0.0.1"),
        ip("255.0.0.0"),
        ip("10.20.0.21")
    ));
    assert!(!same_subnet(
        ip("10.0.0.1"),
        ip("255.255.255.255"),
        ip("10.0.0.2")
    ));
    // Against this host's own interfaces: an address of its own is on its own subnet; a foreign "local" never is.
    if let Some((own, _)) = local_ipv4_nets().into_iter().next() {
        assert!(on_subnet_of(&own.to_string(), &own.to_string()));
    }
    assert!(
        !on_subnet_of("203.0.113.77", "203.0.113.78"),
        "not one of this host's addresses"
    );
    assert!(!on_subnet_of("", "192.168.1.121"));
    assert!(!on_subnet_of("192.168.1.111", "not an ip"));
}
