use super::*;
use crate::iscsid::{Entry, export, games};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};

/// A client: the server's greeting read, "fixed newstyle + no zeroes" answered.
async fn connect() -> DuplexStream {
    let (mut a, b) = duplex(1 << 20);
    tokio::spawn(serve(b));
    let mut hello = [0u8; 18];
    a.read_exact(&mut hello).await.unwrap();
    assert_eq!(&hello[..8], b"NBDMAGIC");
    assert_eq!(
        u64::from_be_bytes(hello[8..16].try_into().unwrap()),
        IHAVEOPT
    );
    assert_eq!(u16::from_be_bytes(hello[16..18].try_into().unwrap()), 3);
    a.write_all(&3u32.to_be_bytes()).await.unwrap();
    a
}

/// One option sent; the server's one reply: (type, data).
async fn option(a: &mut DuplexStream, opt: u32, data: &[u8]) -> (u32, Vec<u8>) {
    let mut b = Vec::new();
    b.extend(IHAVEOPT.to_be_bytes());
    b.extend(opt.to_be_bytes());
    b.extend((data.len() as u32).to_be_bytes());
    b.extend(data);
    a.write_all(&b).await.unwrap();
    let mut h = [0u8; 20];
    a.read_exact(&mut h).await.unwrap();
    assert_eq!(u64::from_be_bytes(h[..8].try_into().unwrap()), REP_MAGIC);
    assert_eq!(u32::from_be_bytes(h[8..12].try_into().unwrap()), opt);
    let len = u32::from_be_bytes(h[16..20].try_into().unwrap()) as usize;
    let mut d = vec![0u8; len];
    a.read_exact(&mut d).await.unwrap();
    (u32::from_be_bytes(h[12..16].try_into().unwrap()), d)
}

/// NBD_OPT_GO for `name`: Ok((size, transmission flags)) once the export is chosen, Err((type, text)) when refused.
async fn go(a: &mut DuplexStream, name: &str) -> Result<(u64, u16), (u32, String)> {
    let mut d = Vec::new();
    d.extend((name.len() as u32).to_be_bytes());
    d.extend(name.as_bytes());
    d.extend(0u16.to_be_bytes());
    let (kind, data) = option(a, OPT_GO, &d).await;
    if kind != REP_INFO {
        return Err((kind, String::from_utf8_lossy(&data).into_owned()));
    }
    assert_eq!(
        u16::from_be_bytes(data[..2].try_into().unwrap()),
        INFO_EXPORT
    );
    let size = u64::from_be_bytes(data[2..10].try_into().unwrap());
    let flags = u16::from_be_bytes(data[10..12].try_into().unwrap());
    let mut ack = [0u8; 20];
    a.read_exact(&mut ack).await.unwrap();
    assert_eq!(u32::from_be_bytes(ack[12..16].try_into().unwrap()), REP_ACK);
    Ok((size, flags))
}

async fn request(
    a: &mut DuplexStream,
    kind: u16,
    flags: u16,
    handle: u64,
    off: u64,
    len: u32,
    data: &[u8],
) {
    let mut b = Vec::new();
    b.extend(REQ_MAGIC.to_be_bytes());
    b.extend(flags.to_be_bytes());
    b.extend(kind.to_be_bytes());
    b.extend(handle.to_be_bytes());
    b.extend(off.to_be_bytes());
    b.extend(len.to_be_bytes());
    b.extend(data);
    a.write_all(&b).await.unwrap();
}

/// A reply: (error, handle, `n` bytes of data).
async fn reply(a: &mut DuplexStream, n: usize) -> (u32, u64, Vec<u8>) {
    let mut h = [0u8; 16];
    a.read_exact(&mut h).await.unwrap();
    assert_eq!(u32::from_be_bytes(h[..4].try_into().unwrap()), REPLY_MAGIC);
    let mut d = vec![0u8; n];
    a.read_exact(&mut d).await.unwrap();
    (
        u32::from_be_bytes(h[4..8].try_into().unwrap()),
        u64::from_be_bytes(h[8..16].try_into().unwrap()),
        d,
    )
}

fn patterned(len: u32) -> Vec<u8> {
    (0..len)
        .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
        .collect()
}

#[test]
fn request_arithmetic() {
    assert!(in_range(0, 512, 512));
    assert!(!in_range(1, 512, 512));
    assert!(!in_range(u64::MAX, 2, u64::MAX), "no wrap-around");
    assert_eq!(units(0), 1);
    assert_eq!(units(1), 1);
    assert_eq!(units(UNIT), 1);
    assert_eq!(units(UNIT + 1), 2);
    assert_eq!(
        units(MAX_LEN),
        BUDGET as u32,
        "the biggest request takes the whole budget"
    );
    assert_eq!(errno_of("overlay write: x"), EIO);
    assert_eq!(errno_of(&format!("{NO_ROOM}full")), ENOSPC);
    assert_eq!(transmission_flags(false), FLAG_HAS_FLAGS | FLAG_READ_ONLY);
    assert_eq!(
        transmission_flags(true),
        FLAG_HAS_FLAGS | FLAG_SEND_FLUSH | FLAG_SEND_FUA
    );
}

/// NBD_OPT_GO's data: length, name, the list of requested information whole — anything else is not served.
#[test]
fn go_data_is_parsed_strictly() {
    let mk = |name: &[u8], reqs: u16, extra: usize| {
        let mut d = Vec::new();
        d.extend((name.len() as u32).to_be_bytes());
        d.extend(name);
        d.extend(reqs.to_be_bytes());
        d.extend(vec![0u8; 2 * reqs as usize + extra]);
        d
    };
    assert_eq!(go_name(&mk(b"iqn.x:d.g1", 0, 0)), Some("iqn.x:d.g1"));
    assert_eq!(go_name(&mk(b"iqn.x:d.g1", 2, 0)), Some("iqn.x:d.g1"));
    assert_eq!(go_name(&mk(b"iqn.x:d.g1", 2, 1)), None, "trailing bytes");
    assert_eq!(go_name(&mk(b"", 0, 0)), None, "no default export");
    assert_eq!(
        go_name(&[0, 0, 0, 9, b'a']),
        None,
        "name longer than the data"
    );
    assert_eq!(go_name(&[0, 0]), None);
    assert_eq!(go_name(&mk(&[0xff, 0xfe], 0, 0)), None, "not text");
    assert_eq!(go_name(&[0xff, 0xff, 0xff, 0xff]), None, "no overflow");
}

/// A plain target is served read-only: the size and flags say so, reads come back byte for byte, a write is refused
/// (EPERM) and the data that came with it is consumed (the next request still parses), an unknown or malformed
/// request does not end the session, and a request past the end is EINVAL.
#[tokio::test]
async fn plain_target_is_read_only() {
    let p = std::env::temp_dir().join("broom_test_nbd_plain.img");
    let file = patterned(1 << 20);
    std::fs::write(&p, &file).unwrap();
    let iqn = "iqn.test:nbdplain.g1";
    export(Entry {
        iqn: iqn.into(),
        path: p.to_string_lossy().into(),
        ram: false,
        reserve: 0,
        stamp: String::new(),
        cd: false,
    })
    .unwrap();
    let mut a = connect().await;
    assert_eq!(
        go(&mut a, "iqn.test:nope").await.unwrap_err().0,
        REP_ERR_POLICY,
        "no such disk"
    );
    let (size, flags) = go(&mut a, iqn).await.unwrap();
    assert_eq!(size, 1 << 20);
    assert_eq!(flags, transmission_flags(false));

    request(&mut a, CMD_READ, 0, 7, 4096, 8192, &[]).await;
    let (err, handle, data) = reply(&mut a, 8192).await;
    assert_eq!((err, handle), (0, 7));
    assert_eq!(data, file[4096..4096 + 8192]);

    request(&mut a, CMD_WRITE, 0, 8, 0, 4, &[1, 2, 3, 4]).await;
    assert_eq!(reply(&mut a, 0).await.0, EPERM);
    request(&mut a, CMD_READ, 0, 9, (1 << 20) - 4, 8, &[]).await;
    assert_eq!(reply(&mut a, 0).await.0, EINVAL, "past the end");
    request(&mut a, 99, 0, 10, 0, 0, &[]).await;
    assert_eq!(
        reply(&mut a, 0).await,
        (EINVAL, 10, vec![]),
        "unknown command"
    );
    request(&mut a, CMD_FLUSH, 0, 11, 0, 0, &[]).await;
    assert_eq!(reply(&mut a, 0).await.0, 0);
    request(&mut a, CMD_READ, 0, 12, 0, 512, &[]).await;
    assert_eq!(reply(&mut a, 512).await.2, file[..512], "still in step");

    request(&mut a, CMD_DISC, 0, 13, 0, 0, &[]).await;
    let mut rest = Vec::new();
    a.read_to_end(&mut rest).await.unwrap();
    assert!(rest.is_empty(), "the server closes after DISC");
    let _ = std::fs::remove_file(&p);
}

/// A VM's session: the keyed name gets the update overlay — writable, flush and FUA offered, what was written reads
/// back and is kept for Save. The plain name from the same address and a wrong key are not writers (the keyed name
/// with a wrong key is refused outright: the VM must not start on a disk it cannot write); the session ends with the
/// connection.
#[tokio::test]
async fn keyed_session_writes() {
    let _one = crate::iscsid::golden::TEST_LOCK.lock().await;
    let d = std::env::temp_dir().join("broom_test_nbd_key");
    let _ = std::fs::remove_dir_all(&d);
    let img = d.join("k/games.img");
    std::fs::create_dir_all(img.parent().unwrap()).unwrap();
    let base = patterned(1 << 20);
    std::fs::write(&img, &base).unwrap();
    let key = "0123456789abcdef0123456789abcdef";
    games::set(vec![games::Config {
        name: "k".into(),
        iqn: "iqn.test:nbdkey".into(),
        path: img.to_string_lossy().into(),
        update_ip: Some("127.0.0.1".into()),
        update_key: Some(key.into()),
        ..Default::default()
    }])
    .unwrap();

    // The plain name: read-only, though from the update machine's address.
    let mut a = connect().await;
    let (_, flags) = go(&mut a, "iqn.test:nbdkey.g0").await.unwrap();
    assert_eq!(flags, transmission_flags(false));
    request(&mut a, CMD_WRITE, 0, 1, 0, 512, &[7u8; 512]).await;
    assert_eq!(reply(&mut a, 0).await.0, EPERM);
    request(&mut a, CMD_DISC, 0, 2, 0, 0, &[]).await;
    drop(a);

    // A keyed name with another key: refused, with the reason.
    let mut a = connect().await;
    let (kind, why) = go(&mut a, &format!("iqn.test:nbdkey.g0.u{}", "f".repeat(32)))
        .await
        .unwrap_err();
    assert_eq!(kind, REP_ERR_POLICY);
    assert!(why.contains("not writable"), "{why}");
    assert_eq!(option(&mut a, OPT_ABORT, &[]).await.0, REP_ACK);
    drop(a);

    // The right key: writable.
    let mut a = connect().await;
    let (size, flags) = go(&mut a, &format!("iqn.test:nbdkey.g0.u{key}"))
        .await
        .unwrap();
    assert_eq!(size, 1 << 20);
    assert_eq!(flags, transmission_flags(true));
    let info = games::info().into_iter().find(|i| i.name == "k").unwrap();
    assert!(info.update_connected, "the daemon sees the update session");
    let new = vec![0xA5u8; 8192];
    // Two writes in flight, the second with FUA, a flush; each answered by its handle.
    request(&mut a, CMD_WRITE, 0, 21, 4096, 8192, &new).await;
    request(&mut a, CMD_WRITE, CMD_FLAG_FUA, 22, 100_000, 8192, &new).await;
    request(&mut a, CMD_FLUSH, 0, 23, 0, 0, &[]).await;
    let mut got = std::collections::HashMap::new();
    for _ in 0..3 {
        let (err, handle, _) = reply(&mut a, 0).await;
        got.insert(handle, err);
    }
    assert_eq!(got, [(21, 0), (22, 0), (23, 0)].into());
    request(&mut a, CMD_READ, 0, 24, 4096, 8192, &[]).await;
    assert_eq!(reply(&mut a, 8192).await.2, new, "reads its own writes");
    request(&mut a, CMD_READ, 0, 25, 0, 4096, &[]).await;
    assert_eq!(
        reply(&mut a, 4096).await.2,
        base[..4096],
        "the rest is the disk"
    );
    request(&mut a, CMD_WRITE, 0, 26, (1 << 20) - 4, 8, &[0u8; 8]).await;
    assert_eq!(reply(&mut a, 0).await.0, ENOSPC, "past the end");
    let info = games::info().into_iter().find(|i| i.name == "k").unwrap();
    assert!(info.update_bytes > 0, "the writes are kept for Save");

    // The session ends with the connection.
    request(&mut a, CMD_DISC, 0, 27, 0, 0, &[]).await;
    drop(a);
    for _ in 0..50 {
        if !games::info()
            .into_iter()
            .find(|i| i.name == "k")
            .unwrap()
            .update_connected
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let info = games::info().into_iter().find(|i| i.name == "k").unwrap();
    assert!(!info.update_connected, "detached once the client is gone");
    games::set(Vec::new()).unwrap();
    let _ = std::fs::remove_dir_all(&d);
}

/// The older option the first NBD clients use (EXPORT_NAME) and options this server does not know.
#[tokio::test]
async fn legacy_export_name_and_unknown_options() {
    let p = std::env::temp_dir().join("broom_test_nbd_legacy.img");
    std::fs::write(&p, patterned(1 << 16)).unwrap();
    let iqn = "iqn.test:nbdlegacy.g1";
    export(Entry {
        iqn: iqn.into(),
        path: p.to_string_lossy().into(),
        ram: false,
        reserve: 0,
        stamp: String::new(),
        cd: false,
    })
    .unwrap();
    let mut a = connect().await;
    assert_eq!(
        option(&mut a, 8, &[]).await.0,
        REP_ERR_UNSUP,
        "structured replies: not offered"
    );
    assert_eq!(
        option(&mut a, 10, &[0; 8]).await.0,
        REP_ERR_UNSUP,
        "meta contexts: not offered"
    );
    // EXPORT_NAME has no reply header: size, flags, and (no zeroes agreed) nothing more.
    let mut b = Vec::new();
    b.extend(IHAVEOPT.to_be_bytes());
    b.extend(OPT_EXPORT_NAME.to_be_bytes());
    b.extend((iqn.len() as u32).to_be_bytes());
    b.extend(iqn.as_bytes());
    a.write_all(&b).await.unwrap();
    let mut r = [0u8; 10];
    a.read_exact(&mut r).await.unwrap();
    assert_eq!(u64::from_be_bytes(r[..8].try_into().unwrap()), 1 << 16);
    assert_eq!(
        u16::from_be_bytes(r[8..].try_into().unwrap()),
        transmission_flags(false)
    );
    request(&mut a, CMD_READ, 0, 1, 0, 16, &[]).await;
    assert_eq!(reply(&mut a, 16).await.0, 0);
    drop(a);

    // A name that is not there: the connection simply ends (this option has no way to say why).
    let mut a = connect().await;
    let mut b = Vec::new();
    b.extend(IHAVEOPT.to_be_bytes());
    b.extend(OPT_EXPORT_NAME.to_be_bytes());
    b.extend(4u32.to_be_bytes());
    b.extend(b"nope");
    a.write_all(&b).await.unwrap();
    let mut rest = Vec::new();
    a.read_to_end(&mut rest).await.unwrap();
    assert!(rest.is_empty());

    // A client that does not speak fixed newstyle, and one that sends garbage, are dropped.
    let (mut c, s) = duplex(4096);
    tokio::spawn(serve(s));
    let mut hello = [0u8; 18];
    c.read_exact(&mut hello).await.unwrap();
    c.write_all(&0u32.to_be_bytes()).await.unwrap();
    let mut rest = Vec::new();
    c.read_to_end(&mut rest).await.unwrap();
    assert!(rest.is_empty());
    let _ = std::fs::remove_file(&p);
}
