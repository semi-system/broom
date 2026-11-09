// The web admin's HTTP contract: first-run setup, sessions and the login throttle, the Host check, security headers,
// and the input checks of the main forms (network, images, machines).
mod common;

use common::clients::Http;
use common::*;
use serde_json::json;

#[test]
fn api_contract() {
    sandbox("api_contract", || {
        let home = Home::new("api");
        let _srv = Server::start(&home);
        let anon = Http::new();

        // First run: no password yet; setting it needs the token from the server log.
        let st = anon.get("/api/auth/status").json();
        assert_eq!(
            (st["configured"].as_bool(), st["authed"].as_bool()),
            (Some(false), Some(false))
        );
        assert_eq!(
            anon.post(
                "/api/auth/setup",
                &json!({"user": "admin", "cred": pw::seal(&pw::setup_key("nope"), "admin", PASSWORD)})
            )
            .status,
            403
        );
        assert_eq!(
            anon.post(
                "/api/auth/hello",
                &json!({"user": "admin", "cnonce": "00112233445566778899aabbccddeeff"})
            )
            .status,
            409,
            "nothing to log in to"
        );
        let h = admin(&home);
        assert_eq!(
            anon.post(
                "/api/auth/setup",
                &json!({"user": "admin", "cred": pw::seal(&pw::setup_key("x"), "admin", PASSWORD)})
            )
            .status,
            409
        );
        assert_eq!(h.get("/api/auth/status").json()["authed"], true);

        // Sessions: data needs one, boot endpoints don't; a page navigation is sent to /login.
        assert_eq!(anon.get("/api/status").status, 401);
        assert_eq!(h.get("/api/status").status, 200);
        assert_eq!(anon.get("/boot.ipxe").status, 200);
        let nav = anon.request("GET", "/machines", &[("Accept", "text/html")], b"");
        assert_eq!((nav.status, nav.header("location")), (303, Some("/login")));
        let forged = Http {
            cookie: Some("broom_session=99999999999.00ff".into()),
            ..Http::new()
        };
        assert_eq!(
            forged.get("/api/status").status,
            401,
            "unknown session refused"
        );

        // DNS rebinding: a foreign Host name is refused even with a session; IP literals and localhost pass.
        assert_eq!(
            h.request("GET", "/api/status", &[("Host", "evil.example")], b"")
                .status,
            421
        );
        assert_eq!(
            h.request("GET", "/api/status", &[("Host", "localhost:80")], b"")
                .status,
            200
        );

        let r = anon.get("/login");
        assert!(
            r.header("content-security-policy")
                .is_some_and(|c| c.contains("script-src 'self'"))
        );
        assert_eq!(r.header("x-frame-options"), Some("DENY"));

        // Network: refused unless complete and real; nothing saved on a refusal.
        let net = |v: serde_json::Value| h.post("/api/dhcp", &v).status;
        assert_eq!(
            net(json!({"mode": "full", "iface": "nope0"})),
            400,
            "unknown interface"
        );
        assert_eq!(
            net(json!({"mode": "full", "iface": SRV_IF, "server_ip": SRV})),
            400,
            "no gateway/DNS"
        );
        assert_eq!(net(json!({"server_ip": "10.0.0.1\nx"})), 400, "injection");
        assert_eq!(
            net(json!({"mode": "off", "server_ip": "192.0.2.7"})),
            400,
            "not our address"
        );
        assert_eq!(
            h.get("/api/dhcp").json()["server_ip"]
                .as_str()
                .unwrap_or(""),
            "",
            "nothing saved"
        );
        configure_network(&h);
        assert_eq!(h.get("/api/dhcp").json()["server_ip"], SRV);

        // Images: name + os checked, listed, deleted.
        let img = |v: serde_json::Value| h.post("/api/images", &v);
        assert_eq!(img(json!({"name": "../x", "os": "linux"})).status, 400);
        assert_eq!(img(json!({"name": "a", "os": "dos"})).status, 400);
        let id = img(json!({"name": "web1", "os": "windows"})).json()["id"]
            .as_i64()
            .unwrap();
        assert_eq!(
            img(json!({"name": "web1", "os": "windows"})).status,
            400,
            "duplicate name"
        );
        assert!(h.get("/api/images").text().contains("\"web1\""));
        assert_eq!(
            h.post("/api/images/upload-done", &json!({"name": "web1"}))
                .status,
            400,
            "no upload started"
        );
        assert_eq!(h.post("/api/images/delete", &json!({"id": id})).status, 200);
        assert!(!h.get("/api/images").text().contains("\"web1\""));

        // Machines: MAC normalized, duplicates and bad hostnames refused, CSV export.
        let add = |v: serde_json::Value| h.post("/api/machines", &v).status;
        assert_eq!(
            add(json!({"mac": "52-54-00-AA-BB-CC", "hostname": "pc-a"})),
            200
        );
        assert_eq!(add(json!({"mac": "52:54:00:aa:bb:cc"})), 400, "same MAC");
        assert_eq!(add(json!({"mac": "zz:54:00:aa:bb:cd"})), 400, "bad MAC");
        assert_eq!(
            add(json!({"mac": "52:54:00:aa:bb:cd", "hostname": "<b>"})),
            400,
            "bad hostname"
        );
        let csv = h.get("/api/machines/export.csv").text();
        assert!(
            csv.contains("52:54:00:aa:bb:cc") && csv.contains("pc-a"),
            "{csv}"
        );

        // Accounts (users.rs) and sessions (auth.rs): staff rights, an owner always left, a session ends on logout (a
        // copy of its cookie too), on a password reset and with its account; a role change applies at once. Passwords
        // never cross the network: a new one comes sealed with the owner's session key, signing in is the handshake.
        let as_user =
            |u: &str, p: &str| pw::sign_in(u, p).unwrap_or_else(|s| panic!("login {u}: {s}"));
        let sk = h.sk.unwrap();
        let set = |v: serde_json::Value| h.post("/api/users", &v).status;
        let cred = |name: &str, p: &str| pw::seal(&sk, name, p);
        assert_eq!(
            set(json!({"name": "staff1", "role": "staff"})),
            400,
            "a new account needs a password"
        );
        assert_eq!(
            set(
                json!({"name": "staff1", "role": "staff", "cred": pw::seal(&[9u8; 32], "staff1", "x-x-x-x-x")})
            ),
            400,
            "sealed with another key"
        );
        assert_eq!(
            set(json!({"name": "staff1", "role": "staff", "cred": cred("staff2", "staff-pass-1")})),
            400,
            "sealed for another account"
        );
        assert_eq!(
            set(
                json!({"name": "Bad Name", "role": "staff", "cred": cred("bad name", "long-enough")})
            ),
            400
        );
        assert_eq!(
            set(json!({"name": "staff1", "role": "staff", "cred": cred("staff1", "staff-pass-1")})),
            200
        );
        assert_eq!(
            pw::sign_in("staff1", "wrong-pass").err(),
            Some(401),
            "wrong password"
        );
        let s = as_user("staff1", "staff-pass-1");
        assert_eq!(s.get("/api/status").status, 200, "staff can look");
        assert_eq!(s.get("/api/users").status, 403, "not at the accounts");
        assert_eq!(
            s.post("/api/users", &json!({"name": "x", "role": "owner"}))
                .status,
            403
        );
        assert_eq!(
            s.post("/api/images", &json!({"name": "s", "os": "linux"}))
                .status,
            403
        );
        let copy = Http {
            cookie: s.cookie.clone(),
            ..Http::new()
        };
        assert_eq!(s.post("/api/auth/logout", &json!({})).status, 200);
        assert_eq!(copy.get("/api/status").status, 401, "ended on the server");
        let s = as_user("staff1", "staff-pass-1");
        // Their own password: a fresh handshake with the current one, the new one sealed with its key.
        let a = s
            .post(
                "/api/auth/hello",
                &json!({"user": "staff1", "cnonce": "0123456789abcdef0123456789abcdef"}),
            )
            .json();
        let (c, st, _) = pw::keys(
            "staff-pass-1",
            &pw::unhex(a["salt"].as_str().unwrap()),
            a["iter"].as_u64().unwrap() as u32,
        );
        let t = format!(
            "broom-login|staff1|0123456789abcdef0123456789abcdef|{}",
            a["snonce"].as_str().unwrap()
        );
        let proof = pw::hex(&std::array::from_fn::<u8, 32, _>(|i| {
            c[i] ^ pw::mac(&st, t.as_bytes())[i]
        }));
        let hsk = pw::mac(&c, format!("session|{t}").as_bytes());
        assert_eq!(
            s.post(
                "/api/password",
                &json!({"hs": a["hs"], "proof": proof, "cred": pw::seal(&hsk, "staff1", "staff-pass-own")})
            )
            .status,
            200
        );
        let s = as_user("staff1", "staff-pass-own");
        assert_eq!(
            set(json!({"name": "staff1", "role": "staff", "cred": cred("staff1", "staff-pass-2")})),
            200
        );
        assert_eq!(s.get("/api/status").status, 401, "password reset");
        let s = as_user("staff1", "staff-pass-2");
        assert_eq!(
            set(json!({"name": "admin", "role": "staff"})),
            400,
            "an owner must be left"
        );
        assert_eq!(
            h.post("/api/users/delete", &json!({"name": "admin"}))
                .status,
            400,
            "not yourself"
        );
        assert_eq!(
            set(json!({"name": "admin", "role": "owner", "cred": cred("admin", "new-admin-pass")})),
            400,
            "your own password: Change password, not a reset that ends your session"
        );
        assert_eq!(h.get("/api/status").status, 200, "still signed in");
        assert_eq!(set(json!({"name": "staff1", "role": "owner"})), 200);
        assert_eq!(s.get("/api/users").status, 200, "now an owner");
        assert_eq!(
            h.post("/api/users/delete", &json!({"name": "staff1"}))
                .status,
            200
        );
        assert_eq!(s.get("/api/status").status, 401, "account deleted");
        assert_eq!(h.get("/api/status").status, 200);

        // Login throttle: 5 free wrong proofs, then this IP is locked out (1 s, doubling) → 429.
        let wrong = || pw::sign_in("admin", "wrong-pass").err();
        for _ in 0..4 {
            assert_eq!(wrong(), Some(401));
        }
        assert!(
            (0..4).any(|_| wrong() == Some(429)),
            "locked out after 5 wrong passwords"
        );
    });
}

/// HTTPS for the web admin (tls.rs): a self-signed certificate made at first start; on plain HTTP the admin pages are
/// sent to https://, the admin API refused, the machines' paths served; the session cookie is Secure; an uploaded
/// certificate takes over at once (no restart), a bad one is refused; a new self-signed one on request; HTTPS can be
/// turned off for the admin pages.
#[test]
fn https_admin() {
    sandbox("https_admin", || {
        let home = Home::new("https");
        let _srv = Server::start_with(&home, &["--https-port", "443"]);
        let anon = Http::new();

        // What the capture tool reads first (public, plain HTTP): the port and the certificate to trust.
        let t = anon.get("/api/tls/cert").json();
        assert_eq!(
            (t["port"].as_u64(), t["self_signed"].as_bool()),
            (Some(443), Some(true))
        );
        let cert = t["cert"].as_str().unwrap().to_string();
        assert!(cert.starts_with("-----BEGIN CERTIFICATE-----"), "{t}");

        // Plain HTTP: pages → https://, the sign-in API refused, the machines' paths served.
        let nav = anon.request("GET", "/machines?x=1", &[("Accept", "text/html")], b"");
        assert_eq!(
            (nav.status, nav.header("location")),
            (308, Some(format!("https://{SRV}/machines?x=1").as_str()))
        );
        assert_eq!(
            anon.get("/login").header("location"),
            Some(format!("https://{SRV}/login").as_str())
        );
        let hello = json!({"user": "admin", "cnonce": "00112233445566778899aabbccddeeff"});
        assert_eq!(anon.post("/api/auth/hello", &hello).status, 403);
        assert_eq!(anon.get("/boot.ipxe").status, 200);
        assert_eq!(anon.get("/broom-diskless.ps1").status, 200);

        // HTTPS, trusting exactly that certificate (by the server's IP): sign in there; the cookie is Secure.
        let tls = Http::tls(&cert);
        let h = admin_via(&home, &tls);
        assert_eq!(h.get("/api/auth/status").json()["authed"], true);
        let r = tls.post("/api/auth/hello", &hello);
        assert_eq!(r.status, 200, "{}", r.text());
        let r = h.get("/login");
        assert!(
            r.header("content-security-policy").is_some(),
            "security headers on HTTPS too"
        );

        // That session on plain HTTP: not served (a browser would not even send it: Secure).
        let leaked = Http {
            cookie: h.cookie.clone(),
            ..Http::new()
        };
        assert_eq!(leaked.get("/api/status").status, 308);
        assert_eq!(
            leaked
                .post("/api/power", &json!({"action": "restart", "ids": []}))
                .status,
            403
        );
        // …except for the capture tool when it says it cannot check the certificate.
        let tool = leaked.request("GET", "/api/status", &[("X-Broom-Tool", "capture")], b"");
        assert_eq!(tool.status, 200);

        // The System page's view: a self-signed certificate, its fingerprint, its end (≤ 825 days away).
        let c = h.get("/api/config/tls").json();
        assert_eq!(
            (
                c["kind"].as_str(),
                c["https"].as_bool(),
                c["listening"].as_bool()
            ),
            (Some("self-signed"), Some(true), Some(true))
        );
        let fp = |pem: &str| {
            use sha2::Digest;
            use tokio_rustls::rustls::pki_types::{CertificateDer, pem::PemObject};
            let der = CertificateDer::from_pem_slice(pem.as_bytes()).unwrap();
            sha2::Sha256::digest(der.as_ref())
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        };
        assert_eq!(c["sha256"].as_str(), Some(fp(&cert).as_str()));
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let until = c["until"].as_u64().unwrap();
        assert!(
            until > now + 800 * 86400 && until <= now + 825 * 86400,
            "{c}"
        );
        assert!(
            c["names"].as_array().unwrap().iter().any(|n| n == SRV),
            "made for the server's address: {c}"
        );

        // Your own certificate (made here for the server's address): in use at once, the old one no longer served.
        let mut p = rcgen::CertificateParams::new(vec![SRV.to_string()]).unwrap();
        p.distinguished_name
            .push(rcgen::DnType::CommonName, "venue test");
        let k = rcgen::KeyPair::generate().unwrap();
        let mine = p.self_signed(&k).unwrap();
        let (mine_pem, mine_key) = (mine.pem(), k.serialize_pem());
        let other_key = rcgen::KeyPair::generate().unwrap().serialize_pem();
        let r = h.post(
            "/api/config/tls",
            &json!({"cert": mine_pem, "key": other_key}),
        );
        assert_eq!(r.status, 400, "a key of another certificate: {}", r.text());
        assert_eq!(
            h.post("/api/config/tls", &json!({"cert": mine_pem})).status,
            400,
            "the key too"
        );
        let r = h.post(
            "/api/config/tls",
            &json!({"cert": mine_pem, "key": mine_key}),
        );
        assert_eq!(r.status, 200, "{}", r.text());
        assert_eq!(r.json()["kind"], "uploaded");
        assert_eq!(r.json()["sha256"].as_str(), Some(fp(&mine_pem).as_str()));
        let h2 = Http {
            cookie: h.cookie.clone(),
            ..Http::tls(&mine_pem)
        };
        assert_eq!(
            h2.get("/api/status").status,
            200,
            "the new one serves, same session"
        );
        let old = tls.handshake();
        assert!(old.is_err(), "the old certificate is gone: {old:?}");
        let t = anon.get("/api/tls/cert").json();
        assert_eq!(
            (t["self_signed"].as_bool(), t["cert"].as_str()),
            (Some(false), Some("")),
            "nothing to pin"
        );
        assert!(std::fs::read_to_string(home.0.join("tls/cert.pem")).unwrap() == mine_pem);
        let mode = {
            use std::os::unix::fs::PermissionsExt;
            std::fs::metadata(home.0.join("tls/key.pem"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777
        };
        assert_eq!(mode, 0o600, "the key: root only");

        // A new self-signed certificate on request: a new fingerprint, pinned again by the tool.
        let r = h2.post("/api/config/tls", &json!({"self_signed": true}));
        assert_eq!(r.status, 200, "{}", r.text());
        let t = anon.get("/api/tls/cert").json();
        let again = t["cert"].as_str().unwrap().to_string();
        assert_ne!(fp(&again), fp(&cert));
        let h3 = Http {
            cookie: h.cookie.clone(),
            ..Http::tls(&again)
        };
        assert_eq!(h3.get("/api/status").status, 200);

        // HTTPS off for the admin pages: plain HTTP serves them again (the tool is told port 0); back on.
        assert_eq!(
            h3.post("/api/config/tls", &json!({"https": false})).status,
            200
        );
        assert_eq!(leaked.get("/api/status").status, 200);
        assert_eq!(anon.get("/api/tls/cert").json()["port"], 0);
        assert_eq!(
            leaked
                .post("/api/config/tls", &json!({"https": true}))
                .status,
            200
        );
        assert_eq!(leaked.get("/api/status").status, 308);

        // Signing out over HTTPS clears a Secure cookie.
        let out = h3.post("/api/auth/logout", &json!({}));
        let sc = out.header("set-cookie").unwrap_or("");
        assert!(sc.contains("; Secure") && sc.contains("HttpOnly"), "{sc}");
    });
}
