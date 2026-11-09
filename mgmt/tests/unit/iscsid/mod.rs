use super::*;
use tokio::io::AsyncWriteExt;

fn pdu(op: u8, flags: u8, itt: u32, cmdsn: u32, data: &[u8]) -> Vec<u8> {
    let mut b = vec![0u8; 48];
    b[0] = op;
    b[1] = flags;
    b[5..8].copy_from_slice(&(data.len() as u32).to_be_bytes()[1..]);
    b[8..14].copy_from_slice(&[0x80, 0, 0, 0x12, 0x34, 0x56]);
    b[16..20].copy_from_slice(&itt.to_be_bytes());
    b[24..28].copy_from_slice(&cmdsn.to_be_bytes());
    b.extend(data);
    b.resize(b.len().div_ceil(4) * 4, 0);
    b
}

async fn login(s: &mut tokio::net::TcpStream, target: &str) -> conn::Pdu {
    let keys = format!(
        "InitiatorName=iqn.test:pc-{target}\0TargetName={target}\0SessionType=Normal\0MaxRecvDataSegmentLength=4096\0MaxBurstLength=65536\0"
    );
    s.write_all(&pdu(0x43, 0x80 | 1 << 2 | 3, 1, 0, keys.as_bytes()))
        .await
        .unwrap();
    conn::read_pdu(s).await.unwrap()
}

/// Login + three READs sent back to back on one connection (answered concurrently), checked byte for byte; the
/// session is counted while connected; an unknown target is refused.
#[tokio::test]
async fn serves_pipelined_reads() {
    let p = std::env::temp_dir().join("broom_test_iscsid.img");
    let file: Vec<u8> = (0..1u32 << 20)
        .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
        .collect();
    std::fs::write(&p, &file).unwrap();
    let iqn = "iqn.test:img.g1";
    export(Entry {
        iqn: iqn.into(),
        path: p.to_string_lossy().into(),
        ram: false,
        reserve: 0,
        stamp: String::new(),
        cd: false,
    })
    .unwrap();
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            tokio::spawn(conn::serve(s, "127.0.0.1".into()));
        }
    });

    let mut bad = tokio::net::TcpStream::connect(addr).await.unwrap();
    let r = login(&mut bad, "iqn.test:nope").await;
    assert_eq!(
        (r.bhs[0], r.bhs[36], r.bhs[37]),
        (0x23, 0x02, 0x03),
        "target not found"
    );

    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    let r = login(&mut s, iqn).await;
    assert_eq!(
        (r.bhs[0], r.bhs[1] & 0x83, r.bhs[36]),
        (0x23, 0x83, 0),
        "login → full feature"
    );
    assert_ne!(&r.bhs[14..16], &[0, 0], "TSIH given");
    assert!(String::from_utf8_lossy(&r.data).contains("TargetPortalGroupTag=1"));
    assert_eq!(list().iter().find(|t| t.iqn == iqn).unwrap().sessions, 1);

    let reads = [(10u32, 0u32, 8u16), (11, 100, 16), (12, 2040, 8)]; // (itt, lba, blocks)
    for (i, (itt, lba, blocks)) in reads.iter().enumerate() {
        let mut cmd = pdu(0x01, 0xc0, *itt, i as u32 + 1, &[]);
        cmd[8..16].fill(0); // LUN 0 (the helper puts an ISID there, for logins)
        cmd[20..24].copy_from_slice(&(*blocks as u32 * 512).to_be_bytes());
        cmd[32] = 0x28;
        cmd[34..38].copy_from_slice(&lba.to_be_bytes());
        cmd[39..41].copy_from_slice(&blocks.to_be_bytes());
        s.write_all(&cmd).await.unwrap();
    }
    let mut got: HashMap<u32, Vec<u8>> = HashMap::new();
    let mut done = 0;
    while done < reads.len() {
        let r = conn::read_pdu(&mut s).await.unwrap();
        assert_eq!(r.bhs[0], 0x25, "Data-In");
        assert!(
            r.data.len() <= 4096,
            "split to the initiator's segment size"
        );
        let itt = u32::from_be_bytes(r.bhs[16..20].try_into().unwrap());
        let at = u32::from_be_bytes(r.bhs[40..44].try_into().unwrap()) as usize;
        let buf = got.entry(itt).or_default();
        buf.resize(buf.len().max(at + r.data.len()), 0);
        buf[at..at + r.data.len()].copy_from_slice(&r.data);
        if r.bhs[1] & 0x01 != 0 {
            assert_eq!(r.bhs[3], 0, "GOOD");
            done += 1;
        }
    }
    for (itt, lba, blocks) in reads {
        let off = lba as usize * 512;
        assert_eq!(
            got[&itt],
            &file[off..off + blocks as usize * 512],
            "ITT {itt}"
        );
    }
    drop(s);
    for _ in 0..50 {
        if list().iter().find(|t| t.iqn == iqn).unwrap().sessions == 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(
        list().iter().find(|t| t.iqn == iqn).unwrap().sessions,
        0,
        "session freed on disconnect"
    );
    TARGETS.lock().remove(iqn);
    let _ = std::fs::remove_file(p);
}

fn scsi_cmd(itt: u32, cmdsn: u32, flags: u8, op: u8, lba: u32, blocks: u16) -> Vec<u8> {
    let mut c = pdu(0x01, flags, itt, cmdsn, &[]);
    c[8..16].fill(0);
    c[20..24].copy_from_slice(&(blocks as u32 * 512).to_be_bytes());
    c[32] = op;
    c[34..38].copy_from_slice(&lba.to_be_bytes());
    c[39..41].copy_from_slice(&blocks.to_be_bytes());
    c
}

async fn read_blocks(
    s: &mut tokio::net::TcpStream,
    itt: u32,
    cmdsn: u32,
    lba: u32,
    blocks: u16,
) -> Vec<u8> {
    s.write_all(&scsi_cmd(itt, cmdsn, 0xc0, 0x28, lba, blocks))
        .await
        .unwrap();
    let mut buf = vec![0u8; blocks as usize * 512];
    loop {
        let r = conn::read_pdu(s).await.unwrap();
        assert_eq!(r.bhs[0], 0x25, "Data-In");
        let at = u32::from_be_bytes(r.bhs[40..44].try_into().unwrap()) as usize;
        buf[at..at + r.data.len()].copy_from_slice(&r.data);
        if r.bhs[1] & 0x01 != 0 {
            return buf;
        }
    }
}

fn info_of(name: &str) -> games::Info {
    games::info().into_iter().find(|i| i.name == name).unwrap()
}

async fn wait_games(f: impl Fn(&games::Info) -> bool) {
    for _ in 0..100 {
        if f(&info_of("t")) {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("games disk state not reached: {:?}", games::info());
}

/// Games disk: the update machine's WRITE comes in over two R2T bursts, lands in the update overlay and reads back;
/// a read-only session is refused writes. "save" makes version g1 at once: a new session of g1 reads the update while
/// a session still on g0 keeps reading the old content; once g0 is unused the layer is merged into games.img and
/// g0 is no longer served.
#[tokio::test]
async fn games_disk_versions() {
    // The games list is the daemon's (one per process): not while golden.rs's games-copy test sets it.
    let _one = crate::iscsid::golden::TEST_LOCK.lock().await;
    let d = std::env::temp_dir().join("broom_test_games");
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    let (img, img2) = (d.join("t/games.img"), d.join("b/games.img"));
    std::fs::create_dir_all(img.parent().unwrap()).unwrap();
    std::fs::create_dir_all(img2.parent().unwrap()).unwrap();
    std::fs::write(&img, vec![0x11u8; 1 << 20]).unwrap();
    let (iqn, g0, g1) = ("iqn.test:games", "iqn.test:games.g0", "iqn.test:games.g1");
    std::fs::write(&img2, vec![0x22u8; 1 << 20]).unwrap();
    let other = games::Config {
        name: "b".into(),
        iqn: "iqn.test:games-b".into(),
        path: img2.to_string_lossy().into(),
        update_ip: None,
        ..Default::default()
    };
    let cfg = |ip: Option<&str>, ram: bool| {
        vec![
            games::Config {
                name: "t".into(),
                iqn: iqn.into(),
                path: img.to_string_lossy().into(),
                update_ip: ip.map(Into::into),
                ram,
                ..Default::default()
            },
            other.clone(),
        ]
    };
    games::set(cfg(Some("127.0.0.1"), false)).unwrap();
    let mut all = games::iqns();
    all.sort();
    assert_eq!(
        all,
        ["iqn.test:games-b.g0", g0],
        "every disk served, each with its own versions"
    );
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            tokio::spawn(conn::serve(s, "127.0.0.1".into()));
        }
    });

    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    assert_eq!(
        login(&mut s, g0).await.bhs[36],
        0,
        "update machine logged in"
    );
    let data: Vec<u8> = (0..128 << 10).map(|i: u32| (i % 253) as u8).collect();
    s.write_all(&scsi_cmd(20, 1, 0xa0, 0x2a, 8, 256))
        .await
        .unwrap(); // WRITE(10), F + W
    for burst in 0..2u32 {
        let r = conn::read_pdu(&mut s).await.unwrap();
        assert_eq!(r.bhs[0], 0x31, "R2T");
        let g = |at: usize| u32::from_be_bytes(r.bhs[at..at + 4].try_into().unwrap());
        assert_eq!(
            (g(36), g(40), g(44)),
            (burst, burst * 65536, 65536),
            "R2TSN, offset, length"
        );
        for (i, chunk) in data[g(40) as usize..(g(40) + g(44)) as usize]
            .chunks(32768)
            .enumerate()
        {
            let mut p = pdu(0x05, if i == 1 { 0x80 } else { 0 }, 20, 0, chunk);
            p[8..16].fill(0);
            p[20..24].copy_from_slice(&r.bhs[20..24]); // TTT
            p[36..40].copy_from_slice(&(i as u32).to_be_bytes());
            p[40..44].copy_from_slice(&(g(40) + i as u32 * 32768).to_be_bytes());
            s.write_all(&p).await.unwrap();
        }
    }
    let r = conn::read_pdu(&mut s).await.unwrap();
    assert_eq!(
        (r.bhs[0], r.bhs[1] & 0x06, r.bhs[3]),
        (0x21, 0, 0),
        "GOOD, no residual"
    );
    assert!(
        read_blocks(&mut s, 21, 2, 8, 256).await == data,
        "reads its own write"
    );
    assert!(
        read_blocks(&mut s, 22, 3, 0, 8)
            .await
            .iter()
            .all(|&b| b == 0x11),
        "rest from the disk"
    );
    assert!(games::save("t").is_err(), "update machine still connected");
    drop(s);

    games::set(cfg(None, false)).unwrap(); // update mode off: every session read-only
    let mut old = tokio::net::TcpStream::connect(addr).await.unwrap();
    login(&mut old, g0).await;
    assert!(
        read_blocks(&mut old, 30, 1, 8, 8)
            .await
            .iter()
            .all(|&b| b == 0x11),
        "g0 unchanged"
    );
    old.write_all(&scsi_cmd(31, 2, 0xa0, 0x2a, 8, 1))
        .await
        .unwrap();
    let r = conn::read_pdu(&mut old).await.unwrap();
    assert_eq!((r.bhs[0], r.bhs[3]), (0x21, 0x02), "write refused, no R2T");

    wait_games(|i| !i.update_connected).await;
    assert!(games::save("t").unwrap().starts_with("version g1 ready"));
    assert!(games::iqns().iter().any(|i| i == g1), "new boots get g1");
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    assert_eq!(login(&mut s, g1).await.bhs[36], 0);
    assert!(
        read_blocks(&mut s, 40, 1, 8, 256).await == data,
        "g1 = the update"
    );
    assert!(
        read_blocks(&mut old, 32, 3, 8, 8)
            .await
            .iter()
            .all(|&b| b == 0x11),
        "a client on g0 keeps g0"
    );

    games::merge_if_idle("t", std::time::Duration::ZERO);
    assert_eq!(info_of("t").layers, 1, "not merged while g0 is in use");
    drop(old);
    wait_games(|i| i.old_sessions == 0).await;
    // RAM option on: the copy is loaded under the layer (games.img still holds the old bytes there).
    games::set(cfg(None, true)).unwrap();
    wait_games(|i| i.ram).await;
    games::merge_if_idle("t", std::time::Duration::ZERO);
    let i = info_of("t");
    assert_eq!((i.ver, i.layers, i.merging), (1, 0, false), "merged");
    let disk = std::fs::read(&img).unwrap();
    assert!(
        disk[8 * 512..8 * 512 + data.len()] == data[..]
            && disk[..8 * 512].iter().all(|&b| b == 0x11)
    );
    assert!(
        read_blocks(&mut s, 41, 2, 8, 256).await == data,
        "g1 session unaffected by the merge"
    );
    drop(s); // (a new login below from the same test initiator would replace it)
    // (Loaded again on a thread already: a 1 MB copy may be back before this line, so only the bytes are checked.)
    let mut fresh = tokio::net::TcpStream::connect(addr).await.unwrap();
    login(&mut fresh, g1).await;
    assert!(
        read_blocks(&mut fresh, 50, 1, 8, 256).await == data,
        "a new session right after the merge reads the merged bytes"
    );
    wait_games(|i| i.ram).await;
    let mut fresh2 = tokio::net::TcpStream::connect(addr).await.unwrap();
    login(&mut fresh2, g1).await;
    assert!(
        read_blocks(&mut fresh2, 60, 1, 8, 256).await == data,
        "and from the RAM copy loaded again"
    );
    drop((fresh, fresh2));
    games::set(cfg(None, false)).unwrap();
    assert!(!info_of("t").ram, "RAM option off → the file");
    let mut late = tokio::net::TcpStream::connect(addr).await.unwrap();
    assert_eq!(
        login(&mut late, g0).await.bhs[36],
        0x02,
        "g0 no longer served"
    );
    games::set(Vec::new()).unwrap();
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn requests_roundtrip() {
    let e = Entry {
        iqn: "iqn.x:a.g1".into(),
        path: "/i/a/image.img".into(),
        ram: true,
        reserve: 2 << 30,
        stamp: String::new(),
        cd: false,
    };
    let s = serde_json::to_string(&Req::Export(e.clone())).unwrap();
    assert!(s.contains("\"op\":\"export\""));
    assert!(matches!(serde_json::from_str::<Req>(&s).unwrap(), Req::Export(x) if x == e));
    assert!(matches!(
        serde_json::from_str::<Req>("{\"op\":\"list\"}").unwrap(),
        Req::List
    ));
    // An older daemon's answer without the newer fields still parses.
    let r: Resp =
        serde_json::from_str("{\"targets\":[{\"iqn\":\"a\",\"sessions\":2,\"ram\":false}]}")
            .unwrap();
    assert_eq!(
        (r.targets[0].sessions, r.err, r.version.as_str()),
        (2, None, "")
    );
}

/// The update session needs the update machine's IP and, when the disk names it, its MAC as ARP sees it.
#[test]
fn games_update_needs_ip_and_mac() {
    let c = |mac: Option<&str>| games::Config {
        name: "t".into(),
        update_ip: Some("10.0.0.20".into()),
        update_mac: mac.map(Into::into),
        ..Default::default()
    };
    let arp = |m: Option<&'static str>| move || m.map(String::from);
    let mac = Some("aa:bb:cc:dd:ee:01");
    assert!(games::update_allowed(
        &c(mac),
        "10.0.0.20",
        arp(Some("AA:BB:CC:DD:EE:01")),
        "t"
    ));
    assert!(
        !games::update_allowed(&c(mac), "10.0.0.20", arp(Some("aa:bb:cc:dd:ee:99")), "t"),
        "same IP, other MAC"
    );
    assert!(
        !games::update_allowed(&c(mac), "10.0.0.20", arp(None), "t"),
        "no ARP entry"
    );
    assert!(
        !games::update_allowed(&c(mac), "10.0.0.21", arp(Some("aa:bb:cc:dd:ee:01")), "t"),
        "other IP"
    );
    assert!(
        games::update_allowed(&c(None), "10.0.0.20", arp(None), "t"),
        "no MAC named: IP only"
    );
}

/// Whole sessions from the LAN, mangled: a login + a READ, a WRITE, an INQUIRY, a Data-Out and a logout in one stream,
/// random bytes changed / cut / repeated. Each connection must end once the client closes (no hang) and its task
/// must never panic; the target keeps serving.
#[tokio::test]
async fn fuzz_sessions() {
    let p = std::env::temp_dir().join("broom_test_iscsid_fuzz.img");
    std::fs::write(&p, vec![7u8; 1 << 20]).unwrap();
    let iqn = "iqn.test:fuzz.g1";
    export(Entry {
        iqn: iqn.into(),
        path: p.to_string_lossy().into(),
        ram: false,
        reserve: 0,
        stamp: String::new(),
        cd: false,
    })
    .unwrap();
    let keys = format!(
        "InitiatorName=iqn.test:pc-fuzz\0TargetName={iqn}\0SessionType=Normal\0MaxRecvDataSegmentLength=4096\0MaxBurstLength=65536\0"
    );
    let mut stream = pdu(0x43, 0x80 | 1 << 2 | 3, 1, 0, keys.as_bytes());
    let mut cmd = |itt: u32, sn: u32, flags: u8, cdb: &[u8], edtl: u32, data: &[u8]| {
        let mut c = pdu(0x01, flags, itt, sn, data);
        c[8..16].fill(0);
        c[20..24].copy_from_slice(&edtl.to_be_bytes());
        c[32..32 + cdb.len()].copy_from_slice(cdb);
        stream.extend(c);
    };
    cmd(2, 1, 0xc0, &[0x28, 0, 0, 0, 0, 10, 0, 0, 8], 4096, &[]);
    cmd(3, 2, 0xa0, &[0x2a, 0, 0, 0, 0, 20, 0, 0, 1], 512, &[]);
    cmd(4, 3, 0xc0, &[0x12, 0, 0, 0, 96], 96, &[]);
    let mut data_out = pdu(0x05, 0x80, 3, 0, &[1u8; 512]);
    data_out[20..24].copy_from_slice(&1u32.to_be_bytes());
    stream.extend(data_out);
    stream.extend(pdu(0x06, 0x80, 5, 4, &[]));

    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    for (i, input) in crate::fuzz::inputs(&[stream], 400).enumerate() {
        let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (s, _) = l.accept().await.unwrap();
        let task = tokio::spawn(conn::serve(s, "127.0.0.1".into()));
        let _ = c.write_all(&input).await;
        let _ = c.shutdown().await;
        let mut sink = Vec::new();
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tokio::io::AsyncReadExt::read_to_end(&mut c, &mut sink),
        )
        .await;
        drop(c);
        match tokio::time::timeout(std::time::Duration::from_secs(5), task).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => panic!("case {i}: the session task panicked: {e}"),
            Err(_) => panic!("case {i}: the session did not end after the client closed"),
        }
    }
    TARGETS.lock().remove(iqn);
    let _ = std::fs::remove_file(p);
}

/// A diskless machine over the wire: it logs in to its own target, its WRITE lands in its session layer and reads
/// back; the golden is untouched; another IP or a machine that was not prepared is refused.
#[tokio::test]
async fn diskless_machine_session() {
    let _one = golden::TEST_LOCK.lock().await;
    let d = std::env::temp_dir().join("broom_test_diskless_tcp");
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("img")).unwrap();
    let img = d.join("img/golden.img");
    std::fs::write(&img, vec![0x22u8; 1 << 20]).unwrap();
    let mac = "02:00:00:00:00:31";
    TEST_ARP.lock().insert("127.0.0.1".into(), mac.into());
    let cfg = golden::Config {
        disk: games::Config {
            name: "w11tcp".into(),
            iqn: "iqn.test:golden-w11tcp".into(),
            path: img.to_string_lossy().into(),
            ..Default::default()
        },
        dir: d.join("wb").to_string_lossy().into(),
        machines: vec![
            golden::Machine {
                mac: mac.into(),
                ip: "127.0.0.1".into(),
            },
            golden::Machine {
                mac: "02:00:00:00:00:32".into(),
                ip: "127.0.0.2".into(),
            },
        ],
        games: false,
    };
    golden::set(vec![cfg]).unwrap();
    let mine = golden::machine_iqn("iqn.test:golden-w11tcp", mac).unwrap();
    let other = golden::machine_iqn("iqn.test:golden-w11tcp", "02:00:00:00:00:32").unwrap();
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            tokio::spawn(conn::serve(s, "127.0.0.1".into()));
        }
    });

    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    assert_eq!(
        login(&mut s, &mine).await.bhs[36],
        0x03,
        "not prepared for a boot: refused"
    );
    golden::prepare("w11tcp", mac, false, false, false, None).unwrap();
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    assert_eq!(login(&mut s, &mine).await.bhs[36], 0, "its own disk");
    let data: Vec<u8> = (0..64 << 10).map(|i: u32| (i % 251) as u8).collect();
    s.write_all(&scsi_cmd(40, 1, 0xa0, 0x2a, 16, 128))
        .await
        .unwrap();
    let r = conn::read_pdu(&mut s).await.unwrap();
    assert_eq!(r.bhs[0], 0x31, "R2T");
    for (i, chunk) in data.chunks(32768).enumerate() {
        let mut p = pdu(0x05, if i == 1 { 0x80 } else { 0 }, 40, 0, chunk);
        p[8..16].fill(0);
        p[20..24].copy_from_slice(&r.bhs[20..24]);
        p[36..40].copy_from_slice(&(i as u32).to_be_bytes());
        p[40..44].copy_from_slice(&(i as u32 * 32768).to_be_bytes());
        s.write_all(&p).await.unwrap();
    }
    let r = conn::read_pdu(&mut s).await.unwrap();
    assert_eq!((r.bhs[0], r.bhs[3]), (0x21, 0), "GOOD");
    assert!(
        read_blocks(&mut s, 41, 2, 16, 128).await == data,
        "reads its own write"
    );
    assert!(
        read_blocks(&mut s, 42, 3, 0, 8)
            .await
            .iter()
            .all(|&b| b == 0x22),
        "rest from the golden"
    );
    assert!(
        std::fs::read(&img).unwrap().iter().all(|&b| b == 0x22),
        "golden file untouched"
    );
    // The other machine's disk, from this IP: refused.
    golden::prepare("w11tcp", "02:00:00:00:00:32", false, false, false, None).unwrap();
    let mut x = tokio::net::TcpStream::connect(addr).await.unwrap();
    assert_eq!(
        login(&mut x, &other).await.bhs[36],
        0x03,
        "not that machine"
    );
    drop(s);
    for _ in 0..100 {
        if golden::prepare("w11tcp", mac, false, false, false, None).is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let i = golden::info();
    assert_eq!(
        i[0].machines[0].session_bytes, 0,
        "next boot: session dropped"
    );
    golden::set(Vec::new()).unwrap();
    TEST_ARP.lock().remove("127.0.0.1");
    let _ = std::fs::remove_dir_all(&d);
}

/// One initiator (same name, same ISID) logged in to two targets at once — a Windows machine booted from iSCSI that
/// also mounts a games disk: two sessions side by side. Only a new login to the SAME target replaces the old session.
#[tokio::test]
async fn same_initiator_two_targets() {
    let dir = std::env::temp_dir().join("broom_test_twin");
    std::fs::create_dir_all(&dir).unwrap();
    let (ta, tb) = ("iqn.test:twin-a.g1", "iqn.test:twin-b.g1");
    for (t, b) in [(ta, 0x0au8), (tb, 0x0bu8)] {
        let p = dir.join(format!("{b}.img"));
        std::fs::write(&p, vec![b; 1 << 20]).unwrap();
        export(Entry {
            iqn: t.into(),
            path: p.to_string_lossy().into(),
            ram: false,
            reserve: 0,
            stamp: String::new(),
            cd: false,
        })
        .unwrap();
    }
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            tokio::spawn(conn::serve(s, "127.0.0.1".into()));
        }
    });
    async fn login_as(s: &mut tokio::net::TcpStream, target: &str) -> conn::Pdu {
        let keys = format!(
            "InitiatorName=iqn.test:pc-boot\0TargetName={target}\0SessionType=Normal\0MaxRecvDataSegmentLength=4096\0MaxBurstLength=65536\0"
        );
        s.write_all(&pdu(0x43, 0x80 | 1 << 2 | 3, 1, 0, keys.as_bytes()))
            .await
            .unwrap();
        conn::read_pdu(s).await.unwrap()
    }
    let mut a = tokio::net::TcpStream::connect(addr).await.unwrap();
    assert_eq!(login_as(&mut a, ta).await.bhs[36], 0);
    let mut b = tokio::net::TcpStream::connect(addr).await.unwrap();
    assert_eq!(login_as(&mut b, tb).await.bhs[36], 0);
    // The first session is still there (it was closed at once when sessions were keyed without the target).
    assert!(
        read_blocks(&mut a, 10, 1, 0, 8)
            .await
            .iter()
            .all(|&x| x == 0x0a)
    );
    assert!(
        read_blocks(&mut b, 10, 1, 0, 8)
            .await
            .iter()
            .all(|&x| x == 0x0b)
    );
    // A second login to target a with the same initiator + ISID replaces the first session there.
    let mut a2 = tokio::net::TcpStream::connect(addr).await.unwrap();
    assert_eq!(login_as(&mut a2, ta).await.bhs[36], 0);
    assert!(
        read_blocks(&mut a2, 11, 1, 0, 8)
            .await
            .iter()
            .all(|&x| x == 0x0a)
    );
    let mut buf = [0u8; 48];
    let gone = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::io::AsyncReadExt::read(&mut a, &mut buf),
    )
    .await;
    assert!(
        matches!(gone, Ok(Ok(0)) | Ok(Err(_))),
        "the replaced session is closed"
    );
    TARGETS.lock().remove(ta);
    TARGETS.lock().remove(tb);
    let _ = std::fs::remove_dir_all(&dir);
}

/// WRITE `data` at `lba` on an update session (R2T bursts answered as they come).
async fn write_blocks(s: &mut tokio::net::TcpStream, itt: u32, cmdsn: u32, lba: u32, data: &[u8]) {
    s.write_all(&scsi_cmd(
        itt,
        cmdsn,
        0xa0,
        0x2a,
        lba,
        (data.len() / 512) as u16,
    ))
    .await
    .unwrap();
    let mut sent = 0;
    while sent < data.len() {
        let r = conn::read_pdu(s).await.unwrap();
        assert_eq!(r.bhs[0], 0x31, "R2T");
        let g = |at: usize| u32::from_be_bytes(r.bhs[at..at + 4].try_into().unwrap()) as usize;
        let (off, len) = (g(40), g(44));
        let chunks: Vec<&[u8]> = data[off..off + len].chunks(32768).collect();
        for (i, chunk) in chunks.iter().enumerate() {
            let mut p = pdu(
                0x05,
                if i + 1 == chunks.len() { 0x80 } else { 0 },
                itt,
                0,
                chunk,
            );
            p[8..16].fill(0);
            p[20..24].copy_from_slice(&r.bhs[20..24]); // TTT
            p[36..40].copy_from_slice(&(i as u32).to_be_bytes());
            p[40..44].copy_from_slice(&((off + i * 32768) as u32).to_be_bytes());
            s.write_all(&p).await.unwrap();
        }
        sent += len;
    }
    let r = conn::read_pdu(s).await.unwrap();
    assert_eq!((r.bhs[0], r.bhs[3]), (0x21, 0), "write GOOD");
}

/// Keeping versions (Config.retain): saved versions stay served (nothing merged while space is fine), each reads its
/// own bytes; dropping the oldest merges only its next layer, so every newer version reads as before; a version a
/// group is held on (keep_from) or a machine uses is never dropped, nor the last one; a drop cut off by a restart is
/// finished up to its target only.
#[tokio::test]
async fn games_disk_keeps_versions() {
    let _one = crate::iscsid::golden::TEST_LOCK.lock().await;
    let d = std::env::temp_dir().join("broom_test_keep");
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("k")).unwrap();
    let img = d.join("k/games.img");
    std::fs::write(&img, vec![0x11u8; 1 << 20]).unwrap();
    let iqn = "iqn.test:keep";
    let cfg = |keep_from: Option<u64>| games::Config {
        name: "k".into(),
        iqn: iqn.into(),
        path: img.to_string_lossy().into(),
        update_ip: Some("127.0.0.1".into()),
        retain: true,
        min_free_pct: 0, // never short of space here
        keep_from,
        ..Default::default()
    };
    games::set(vec![cfg(None)]).unwrap();
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            tokio::spawn(conn::serve(s, "127.0.0.1".into()));
        }
    });
    let info = || games::info().into_iter().find(|i| i.name == "k").unwrap();
    let wait_off = || async {
        for _ in 0..100 {
            if !info().update_connected {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("update still connected");
    };
    // g1 writes 0xA1 at blocks 8..16 and 64..72; g2 writes 0xB2 at 8..16 (over g1) and 128..136.
    let fill = |b: u8| vec![b; 8 * 512];
    for (ver, b, at) in [(0u64, 0xa1u8, [8u32, 64]), (1, 0xb2, [8, 128])] {
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        assert_eq!(login(&mut s, &format!("{iqn}.g{ver}")).await.bhs[36], 0);
        write_blocks(&mut s, 10, 1, at[0], &fill(b)).await;
        write_blocks(&mut s, 11, 2, at[1], &fill(b)).await;
        drop(s);
        wait_off().await;
        games::save("k").unwrap();
    }
    games::tick();
    let i = info();
    assert_eq!(i.ver, 2);
    assert_eq!(
        i.versions.iter().map(|v| v.ver).collect::<Vec<_>>(),
        [0, 1, 2],
        "every version kept"
    );
    assert!(i.versions[1].bytes > 0 && i.versions[1].saved > 0);
    let read = |ver: u64, lba: u32| async move {
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        let ok = login(&mut s, &format!("{iqn}.g{ver}")).await.bhs[36] == 0;
        if !ok {
            return None;
        }
        Some(read_blocks(&mut s, 20, 1, lba, 8).await[0])
    };
    assert_eq!(read(0, 8).await, Some(0x11), "g0 still served as it was");
    assert_eq!(
        (read(1, 8).await, read(1, 64).await, read(1, 128).await),
        (Some(0xa1), Some(0xa1), Some(0x11))
    );
    assert_eq!(
        (read(2, 8).await, read(2, 64).await, read(2, 128).await),
        (Some(0xb2), Some(0xa1), Some(0xb2))
    );

    // A machine still on g0: not dropped.
    let mut on0 = tokio::net::TcpStream::connect(addr).await.unwrap();
    login(&mut on0, &format!("{iqn}.g0")).await;
    assert!(games::drop_oldest("k").unwrap_err().contains("in use"));
    drop(on0);
    for _ in 0..100 {
        if info().versions[0].sessions == 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    // g0 dropped: g1 is now inside the file; g1 and g2 read exactly as before.
    assert_eq!(games::drop_oldest("k").unwrap(), 0);
    let i = info();
    assert_eq!(i.versions.iter().map(|v| v.ver).collect::<Vec<_>>(), [1, 2]);
    assert_eq!(read(0, 8).await, None, "g0 no longer served");
    assert_eq!(
        (read(1, 8).await, read(1, 64).await, read(1, 128).await),
        (Some(0xa1), Some(0xa1), Some(0x11))
    );
    assert_eq!(
        (read(2, 8).await, read(2, 64).await, read(2, 128).await),
        (Some(0xb2), Some(0xa1), Some(0xb2))
    );
    // A group held on g1: g1 stays.
    games::set(vec![cfg(Some(1))]).unwrap();
    assert!(games::drop_oldest("k").unwrap_err().contains("held"));
    games::set(vec![cfg(None)]).unwrap();

    // A drop of g1 cut off by a restart (marker written, nothing merged yet): finished up to its target at the next
    // start — g2 kept and right.
    games::set(Vec::new()).unwrap();
    std::fs::write(d.join("k/merging"), "2").unwrap();
    games::set(vec![cfg(None)]).unwrap();
    let i = info();
    assert_eq!(
        i.versions.iter().map(|v| v.ver).collect::<Vec<_>>(),
        [2],
        "finished up to g2"
    );
    assert!(!d.join("k/merging").exists());
    assert_eq!(
        (read(2, 8).await, read(2, 64).await, read(2, 128).await),
        (Some(0xb2), Some(0xa1), Some(0xb2))
    );
    assert!(
        games::drop_oldest("k")
            .unwrap_err()
            .contains("only one version")
    );
    games::set(Vec::new()).unwrap();
    let _ = std::fs::remove_dir_all(&d);
}
