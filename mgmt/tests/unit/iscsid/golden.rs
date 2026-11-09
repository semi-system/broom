use super::*;
use crate::iscsid::games::read_chain;

#[test]
fn mac_spellings() {
    assert_eq!(mac12("AA:BB:CC:DD:EE:0f").as_deref(), Some("aabbccddee0f"));
    assert_eq!(mac12("aa-bb-cc-dd-ee-0f").as_deref(), Some("aabbccddee0f"));
    assert_eq!(mac12("aabb.ccdd.ee0f").as_deref(), Some("aabbccddee0f"));
    assert_eq!(mac12("aabbccddee0"), None, "too short");
    assert_eq!(mac12("aabbccddee0g"), None, "not hex");
    assert_eq!(
        machine_iqn("iqn.x:golden-w11", "AA:BB:CC:DD:EE:0F").as_deref(),
        Some("iqn.x:golden-w11.maabbccddee0f")
    );
}

/// A machine's disk answers only its own IP with its own MAC behind it.
#[test]
fn machine_needs_ip_and_mac() {
    let m = Machine {
        mac: "aa:bb:cc:dd:ee:01".into(),
        ip: "10.0.0.20".into(),
    };
    let arp = |x: Option<&'static str>| move || x.map(String::from);
    let mac = "aabbccddee01";
    assert!(machine_allowed(
        &m,
        mac,
        "10.0.0.20",
        arp(Some("AA:BB:CC:DD:EE:01"))
    ));
    assert!(
        !machine_allowed(&m, mac, "10.0.0.20", arp(Some("aa:bb:cc:dd:ee:02"))),
        "other MAC"
    );
    assert!(
        !machine_allowed(&m, mac, "10.0.0.20", arp(None)),
        "no ARP entry"
    );
    assert!(
        !machine_allowed(&m, mac, "10.0.0.21", arp(Some("aa:bb:cc:dd:ee:01"))),
        "other IP"
    );
}

/// Read `len` bytes at `off` the way a session does: its own writes over the chain below.
fn read(v: &View, lun: &Lun, off: u64, len: usize) -> Vec<u8> {
    let mut b = vec![0u8; len];
    match &v.ov {
        Some(ov) => ov.read_at(&|o, x| read_chain(&v.layers, lun, o, x), off, &mut b),
        None => read_chain(&v.layers, lun, off, &mut b),
    }
    .unwrap();
    b
}

fn write(v: &View, lun: &Lun, off: u64, data: &[u8]) {
    v.ov.as_ref()
        .unwrap()
        .write_at(&|o, x| read_chain(&v.layers, lun, o, x), off, data)
        .unwrap();
}

/// The whole life of a diskless machine on a golden: first boot (setup) → kept as its base; a normal boot's writes
/// are gone at the next boot, the base stays; a new golden version (maintenance Save) drops the base; another machine
/// or another IP can't use the disk; forget deletes its layers.
#[test]
fn machine_layers_lifecycle() {
    let _one = TEST_LOCK.blocking_lock();
    let d = std::env::temp_dir().join("broom_test_golden");
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("img")).unwrap();
    let img = d.join("img/golden.img");
    std::fs::write(&img, vec![1u8; 1 << 20]).unwrap();
    let (pc, maint) = ("10.9.0.11", "10.9.0.99");
    let mac = "02:00:00:00:00:11";
    crate::iscsid::TEST_ARP
        .lock()
        .insert(pc.into(), mac.to_uppercase());
    crate::iscsid::TEST_ARP
        .lock()
        .insert(maint.into(), "02:00:00:00:00:99".into());
    let cfg = Config {
        disk: games::Config {
            name: "w11".into(),
            iqn: "iqn.test:golden-w11".into(),
            path: img.to_string_lossy().into(),
            update_ip: Some(maint.into()),
            update_mac: Some("02:00:00:00:00:99".into()),
            ..Default::default()
        },
        dir: d.join("wb").to_string_lossy().into(),
        machines: vec![Machine {
            mac: mac.into(),
            ip: pc.into(),
        }],
        games: false,
    };
    set(vec![cfg.clone()]).unwrap();
    let t = machine_iqn("iqn.test:golden-w11", mac).unwrap();
    assert!(owns(&t));
    assert!(
        !owns("iqn.test:golden-w11.m020000000022"),
        "machine not listed"
    );
    let lun = lun(&t).unwrap();
    assert_eq!(lun.size, 1 << 20);

    // Not prepared yet → refused; wrong IP → refused.
    assert!(attach(&t, pc).is_err(), "not prepared");
    let p = prepare("w11", mac, false, false, false, None).unwrap();
    assert_eq!(
        p,
        Prepared {
            ver: 0,
            first: true
        }
    );
    assert!(attach(&t, "10.9.0.12").is_err(), "other IP");

    // First boot: its setup writes.
    let v = attach(&t, pc).unwrap();
    assert_eq!(read(&v, &lun, 0, 4), [1, 1, 1, 1]);
    write(&v, &lun, 4096, b"name=PC11");
    assert!(
        prepare("w11", mac, true, false, false, None).is_err(),
        "still connected"
    );
    detach(&v);

    // Promoted: the setup is the base now; a normal boot's writes land in the session.
    let p = prepare("w11", mac, true, false, false, None).unwrap();
    assert_eq!(
        p,
        Prepared {
            ver: 0,
            first: false
        }
    );
    let v = attach(&t, pc).unwrap();
    assert_eq!(&read(&v, &lun, 4096, 9), b"name=PC11");
    write(&v, &lun, 8192, b"savegame");
    write(&v, &lun, 4096, b"name=XXXX");
    assert_eq!(&read(&v, &lun, 8192, 8), b"savegame");
    detach(&v);
    let i = info();
    assert_eq!(i[0].machines[0].base_ver, Some(0));
    assert!(i[0].machines[0].session_bytes > 0);

    // Next boot: the session is gone, the base stays.
    assert!(
        !prepare("w11", mac, false, false, false, None)
            .unwrap()
            .first
    );
    let v = attach(&t, pc).unwrap();
    assert_eq!(&read(&v, &lun, 4096, 9), b"name=PC11");
    assert_eq!(read(&v, &lun, 8192, 8), [1u8; 8]);
    detach(&v);

    // Maintenance: the maintenance machine writes into the golden's update; Save → g1.
    let g = GOLDENS.attach("iqn.test:golden-w11.g0", maint).unwrap();
    assert!(g.ov.is_some(), "maintenance machine writes");
    write(&g, &lun, 0, b"DRIVERS");
    let ro = GOLDENS.attach("iqn.test:golden-w11.g0", pc).unwrap();
    assert!(ro.ov.is_none(), "anyone else reads only");
    GOLDENS.detach(&ro);
    assert!(
        GOLDENS.save("w11").is_err(),
        "maintenance machine still connected"
    );
    GOLDENS.detach(&g);
    assert!(GOLDENS.save("w11").unwrap().starts_with("version g1 ready"));

    // Its group held on g0 (pins): it boots g0 still, its base kept; a version no longer kept → the newest.
    assert_eq!(
        prepare("w11", mac, false, false, false, Some(0)).unwrap(),
        Prepared {
            ver: 0,
            first: false
        }
    );
    let v = attach(&t, pc).unwrap();
    assert_eq!(read(&v, &lun, 0, 7), [1u8; 7], "g0's bytes");
    detach(&v);
    assert_eq!(
        prepare("w11", mac, false, false, false, Some(9))
            .unwrap()
            .ver,
        1
    );
    assert_eq!(
        prepare("w11", mac, false, false, false, Some(0))
            .unwrap()
            .ver,
        0
    );

    // A new version: the base (built on g0) is dropped, the machine sets itself up again on g1.
    let p = prepare("w11", mac, true, false, false, None).unwrap();
    assert_eq!(
        p,
        Prepared {
            ver: 1,
            first: true
        }
    );
    let v = attach(&t, pc).unwrap();
    assert_eq!(&read(&v, &lun, 0, 7), b"DRIVERS");
    assert_eq!(read(&v, &lun, 4096, 4), [1u8; 4], "old base gone");
    write(&v, &lun, 4096, b"name=PC11");
    detach(&v);
    assert!(!prepare("w11", mac, true, false, false, None).unwrap().first);
    // drop_base (renamed / new licence): set up again.
    assert!(prepare("w11", mac, false, true, false, None).unwrap().first);

    // Forget: its folder is gone; it is no longer served once unlisted.
    forget("w11", mac, false).unwrap();
    assert!(!d.join("wb/020000000011").exists());
    set(vec![Config {
        machines: vec![],
        ..cfg
    }])
    .unwrap();
    assert!(!owns(&t));
    set(Vec::new()).unwrap();
    let _ = std::fs::remove_dir_all(&d);
}

/// A games disk for diskless machines (Config.games): each machine its own writable copy of the disk's newest version,
/// no base layer (even when asked to promote), its writes gone at its next boot; an update saved by the disk's update
/// machine reaches the copy at the machine's next boot. A golden of the same name is another disk.
#[test]
fn games_disk_copy_per_machine() {
    let _one = TEST_LOCK.blocking_lock();
    let d = std::env::temp_dir().join("broom_test_golden_games");
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("g")).unwrap();
    let img = d.join("g/games.img");
    std::fs::write(&img, vec![5u8; 1 << 20]).unwrap();
    let (pc, upd) = ("10.9.1.11", "10.9.1.99");
    let mac = "02:00:00:00:01:11";
    crate::iscsid::TEST_ARP.lock().insert(pc.into(), mac.into());
    crate::iscsid::TEST_ARP
        .lock()
        .insert(upd.into(), "02:00:00:00:01:99".into());
    let disk = games::Config {
        name: "g1".into(),
        iqn: "iqn.test:games-g1".into(),
        path: img.to_string_lossy().into(),
        update_ip: Some(upd.into()),
        update_mac: Some("02:00:00:00:01:99".into()),
        ..Default::default()
    };
    games::set(vec![disk.clone()]).unwrap();
    set(vec![Config {
        disk,
        dir: d.join("wb").to_string_lossy().into(),
        machines: vec![Machine {
            mac: mac.into(),
            ip: pc.into(),
        }],
        games: true,
    }])
    .unwrap();
    let t = machine_iqn("iqn.test:games-g1", mac).unwrap();
    assert!(owns(&t));
    assert!(!games::GAMES.owns(&t), "the disk's own targets are .g<k>");
    assert_eq!(
        games_iqns_for(pc),
        vec![t.clone()],
        "discovery lists its copy to it"
    );
    assert!(games_iqns_for("10.9.1.12").is_empty(), "and to no one else");
    assert!(
        prepare("g1", mac, false, false, false, None).is_err(),
        "no golden of that name"
    );
    assert_eq!(
        prepare("g1", mac, true, false, true, None).unwrap(),
        Prepared {
            ver: 0,
            first: true
        }
    );
    let lun = lun(&t).unwrap();
    let v = attach(&t, pc).unwrap();
    assert!(v.ov.is_some(), "its own copy is writable");
    assert_eq!(read(&v, &lun, 0, 4), [5u8; 4]);
    write(&v, &lun, 4096, b"settings");
    assert_eq!(&read(&v, &lun, 4096, 8), b"settings");
    assert!(attach(&t, "10.9.1.12").is_err(), "another IP");
    detach(&v);

    // Next boot, even asked to promote: its writes are gone, no base.
    assert!(prepare("g1", mac, true, false, true, None).unwrap().first);
    let v = attach(&t, pc).unwrap();
    assert_eq!(read(&v, &lun, 4096, 8), [5u8; 8]);
    detach(&v);
    assert!(info()[0].games);
    assert_eq!(info()[0].machines[0].base_ver, None);

    // The update machine saves a new version: the copy reads it after the next boot.
    let u = games::GAMES.attach("iqn.test:games-g1.g0", upd).unwrap();
    assert!(u.ov.is_some());
    write(&u, &lun, 0, b"PATCH");
    games::GAMES.detach(&u);
    assert!(
        games::GAMES
            .save("g1")
            .unwrap()
            .starts_with("version g1 ready")
    );
    assert_eq!(prepare("g1", mac, false, false, true, None).unwrap().ver, 1);
    let v = attach(&t, pc).unwrap();
    assert_eq!(&read(&v, &lun, 0, 5), b"PATCH");
    detach(&v);

    forget("g1", mac, true).unwrap();
    assert!(!d.join("wb/020000000111").exists());
    set(Vec::new()).unwrap();
    games::set(Vec::new()).unwrap();
    let _ = std::fs::remove_dir_all(&d);
}
