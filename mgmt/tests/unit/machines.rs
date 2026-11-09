use super::*;

#[test]
fn hostname_rule() {
    for ok in ["PC01", "FPS-43", "a", "ABCDEFGHIJKLMNO"] {
        assert!(hostname_ok(ok), "{ok}");
    }
    for bad in [
        "",
        "ABCDEFGHIJKLMNOP",
        "PC 01",
        "PC_01",
        "-PC",
        "PC-",
        "123",
        "Zoë1",
    ] {
        assert!(!hostname_ok(bad), "{bad}");
    }
}

fn row(id: i64, mac: &str, ip: Option<&str>, host: Option<&str>, grp: Option<&str>) -> Machine {
    Machine {
        id,
        mac: mac.into(),
        ip: ip.map(Into::into),
        hostname: host.map(Into::into),
        grp: grp.map(Into::into),
        ..Default::default()
    }
}

/// An unknown PC at the boot menu joins the new-machines group: NEW-<end of MAC>, its IP, the group, a note.
#[test]
fn new_machine_joins_the_group() {
    let all = [row(
        1,
        "52:54:00:6a:35:eb",
        Some("10.20.0.21"),
        Some("PC21"),
        Some("Lounge"),
    )];
    let m = new_machine(
        "AA:BB:CC:01:02:0F",
        "192.168.1.50",
        Some("aa:bb:cc:01:02:0f"),
        "New",
        &all,
        &[],
        1000,
    )
    .unwrap();
    assert_eq!(m.mac, "aa:bb:cc:01:02:0f");
    assert_eq!(m.ip.as_deref(), Some("192.168.1.50"));
    assert_eq!(m.hostname.as_deref(), Some("NEW-01020F"));
    assert_eq!(m.grp.as_deref(), Some("New"));
    assert_eq!(m.notes.as_deref(), Some(NEW_NOTE));
    assert!(waiting(&m, Some("new")) && !waiting(&m, Some("Lounge")) && !waiting(&m, None));
    assert!(!waiting(&all[0], Some("New")));
}

/// Only a PC booting for itself on the server's LAN: the MAC behind its IP (ARP) must be the one it gives.
#[test]
fn new_machine_needs_its_own_mac_behind_its_ip() {
    let e = new_machine(
        "aa:bb:cc:01:02:0f",
        "192.168.1.50",
        Some("aa:bb:cc:01:02:10"),
        "New",
        &[],
        &[],
        0,
    )
    .unwrap_err();
    assert!(e.contains("aa:bb:cc:01:02:10"), "{e}");
    let e = new_machine("aa:bb:cc:01:02:0f", "10.1.2.3", None, "New", &[], &[], 0).unwrap_err();
    assert!(e.contains("no ARP entry"), "{e}");
    assert!(new_machine("nonsense", "10.1.2.3", Some("nonsense"), "New", &[], &[], 0).is_err());
}

/// Names / IPs already used are not taken; the group has a ceiling (the boot menu is open to the LAN).
#[test]
fn new_machine_avoids_taken_names_and_ips_and_has_a_ceiling() {
    let mac = "aa:bb:cc:01:02:0f";
    let all = [
        row(
            1,
            "11:22:33:44:55:66",
            Some("192.168.1.50"),
            Some("new-01020f"),
            None,
        ),
        row(2, "11:22:33:44:55:67", None, Some("NEW-CC01020F"), None),
    ];
    let m = new_machine(mac, "192.168.1.50", Some(mac), "New", &all, &[], 0).unwrap();
    assert_eq!(m.hostname.as_deref(), Some("NAABBCC01020F"));
    assert_eq!(m.ip, None, "another machine's fixed IP");
    // A live lease of another MAC on that IP → no fixed IP either; an expired one doesn't count.
    let lease = |exp| crate::db::Lease {
        mac: "11:22:33:44:55:99".into(),
        ip: Some("192.168.1.60".into()),
        hostname: None,
        expires: exp,
    };
    let m = new_machine(
        mac,
        "192.168.1.60",
        Some(mac),
        "New",
        &[],
        &[lease(500)],
        100,
    )
    .unwrap();
    assert_eq!(m.ip, None);
    let m = new_machine(
        mac,
        "192.168.1.60",
        Some(mac),
        "New",
        &[],
        &[lease(50)],
        100,
    )
    .unwrap();
    assert_eq!(m.ip.as_deref(), Some("192.168.1.60"));
    // Ceiling: NEW_MAX machines already wait in the group (any case) → not added.
    let full: Vec<Machine> = (0..NEW_MAX)
        .map(|i| {
            row(
                i as i64 + 10,
                &format!("02:00:00:00:{:02x}:{:02x}", i / 256, i % 256),
                None,
                None,
                Some("NEW"),
            )
        })
        .collect();
    assert!(new_machine(mac, "192.168.1.70", Some(mac), "New", &full, &[], 0).is_err());
    assert!(new_machine(mac, "192.168.1.70", Some(mac), "New", &full[1..], &[], 0).is_ok());
}
