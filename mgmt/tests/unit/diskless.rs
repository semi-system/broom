use super::*;

#[test]
fn names() {
    assert!(valid_name("w11-lounge") && valid_name("a") && valid_name("ubuntu2604"));
    assert!(!valid_name(""), "empty");
    assert!(!valid_name("W11"), "upper case");
    assert!(!valid_name("w11_x"), "underscore");
    assert!(!valid_name("-w11"), "leading dash");
    assert!(!valid_name(&"a".repeat(25)), "too long");
    assert!(valid_iso("Win11_25H2_English_x64.iso"));
    assert!(valid_iso("ubuntu-26.04-desktop-amd64.ISO"));
    assert!(!valid_iso("win11.img"), "not .iso");
    assert!(!valid_iso("../x.iso"), "path");
    assert!(!valid_iso("a b.iso"), "space");
    assert!(!valid_iso(".iso"), "hidden / empty name");
}

#[test]
fn os_defaults_to_windows() {
    let g: Golden = serde_json::from_str(r#"{"name":"w11","size_gb":256}"#).unwrap();
    assert_eq!((g.os.as_str(), g.iso, g.maint), ("windows", None, None));
    let i: Iso = serde_json::from_str(r#"{"name":"x.iso","size":1}"#).unwrap();
    assert_eq!(i.os, "windows");
    assert!(os_ok(" Linux ").is_ok_and(|o| o == "linux"));
    assert!(os_ok("macos").is_err());
}

/// A golden's machines: in one of its groups (none = no machine: diskless is never the default) and with a fixed IP.
#[test]
fn machines_of_a_golden() {
    let m = |id: i64, grp: Option<&str>, ip: Option<&str>| Machine {
        id,
        mac: format!("02:00:00:00:00:{id:02x}"),
        ip: ip.map(Into::into),
        grp: grp.map(Into::into),
        ..Default::default()
    };
    let all = vec![
        m(1, Some("Lounge"), Some("10.0.0.1")),
        m(2, Some("lounge"), None),
        m(3, Some("VIP"), Some("10.0.0.3")),
        m(4, None, Some("10.0.0.4")),
        m(5, Some("lounge"), Some("")),
    ];
    let g = |groups: &[&str]| Golden {
        name: "w11".into(),
        os: "windows".into(),
        size_gb: 256,
        iso: None,
        groups: groups.iter().map(|s| s.to_string()).collect(),
        maint: None,
        ram: false,
        pins: Default::default(),
    };
    let ids = |g: &Golden| {
        machines_of(g, &all)
            .iter()
            .map(|m| m.id)
            .collect::<Vec<_>>()
    };
    assert_eq!(ids(&g(&["LOUNGE"])), [1], "group (any case), fixed IP only");
    assert_eq!(ids(&g(&["lounge", "VIP"])), [1, 3]);
    assert!(ids(&g(&[])).is_empty(), "no group: no machine");
}

#[test]
fn places_are_known() {
    assert_eq!(sub_of("golden"), Some("goldens"));
    assert_eq!(sub_of("writeback"), Some("diskless"));
    assert_eq!(sub_of("iso"), Some("isos"));
    assert_eq!(sub_of("games"), None);
}

/// The open boot URLs act for a machine only when the request comes from it: its IP, its MAC behind it.
#[test]
fn boot_requests_only_from_the_machine_itself() {
    let m = Machine {
        id: 7,
        mac: "02:00:00:00:00:07".into(),
        ip: Some("10.20.0.21".into()),
        hostname: Some("PC07".into()),
        ..Default::default()
    };
    let arp = |x: Option<&'static str>| move || x.map(String::from);
    let ip = m.ip.as_deref();
    assert!(allowed_peer(&m, ip, "10.20.0.21", arp(Some("02-00-00-00-00-07"))).is_ok());
    assert!(
        allowed_peer(&m, ip, "10.20.0.22", arp(Some("02:00:00:00:00:07"))).is_err(),
        "other IP"
    );
    assert!(
        allowed_peer(&m, ip, "10.20.0.21", arp(Some("02:00:00:00:00:08"))).is_err(),
        "other card"
    );
    assert!(
        allowed_peer(&m, ip, "10.20.0.21", arp(None)).is_err(),
        "no ARP entry"
    );
    assert!(
        allowed_peer(&m, None, "10.20.0.21", arp(Some("02:00:00:00:00:07"))).is_err(),
        "no IP"
    );
}

/// A machine that maintains a golden and is also in a diskless group boots the maintenance entry by default.
#[test]
fn maintenance_entry_wins_the_default() {
    let e = |t: &str, d: bool| MenuEntry {
        text: t.into(),
        chain: String::new(),
        default: d,
    };
    let out = ordered(
        vec![e("Install cdtest", true), e("Maintain cdtest", false)],
        vec![e("w11 (diskless)", true), e("w10 (diskless)", true)],
    );
    let got: Vec<(&str, bool)> = out.iter().map(|x| (x.text.as_str(), x.default)).collect();
    assert_eq!(
        got,
        [
            ("Install cdtest", true),
            ("Maintain cdtest", false),
            ("w11 (diskless)", false),
            ("w10 (diskless)", false)
        ]
    );
    let only = ordered(
        vec![],
        vec![e("w11 (diskless)", true), e("w10 (diskless)", true)],
    );
    assert_eq!(
        (only[0].default, only[1].default),
        (true, false),
        "first diskless one"
    );
}

/// A machine's base: its first boot is kept once Windows reported its setup done on that same version; a new name
/// or licence drops it; nothing reported = nothing kept (that boot's writes are wiped like any other).
#[test]
fn base_layer_plan() {
    let st = |pending: Option<u64>, host: &str, lic: i64| BaseState {
        pending,
        host: Some(host.into()),
        lic,
        akey: "k1".into(),
    };
    // First boot on g2 reported → promote at the next boot.
    assert_eq!(
        base_plan(
            &st(Some(2), "PC01", 0),
            Some(2),
            false,
            Some("PC01"),
            0,
            "k1"
        ),
        (true, false)
    );
    // Reported on g1 but the machine's session is on g2 (a Save in between): not kept.
    assert_eq!(
        base_plan(
            &st(Some(1), "PC01", 0),
            Some(2),
            false,
            Some("PC01"),
            0,
            "k1"
        ),
        (false, false)
    );
    // Nothing reported: nothing kept, base untouched.
    assert_eq!(
        base_plan(&st(None, "PC01", 0), Some(2), true, Some("PC01"), 0, "k1"),
        (false, false)
    );
    // Renamed on the Devices page, or a new licence: set up again.
    assert_eq!(
        base_plan(&st(None, "PC01", 0), Some(2), true, Some("PC09"), 0, "k1"),
        (false, true)
    );
    assert_eq!(
        base_plan(&st(None, "PC01", 0), Some(2), true, Some("PC01"), 1, "k1"),
        (false, true)
    );
    // A new agent key (Re-issue), or a base built before agents came to diskless machines: set up again.
    assert_eq!(
        base_plan(&st(None, "PC01", 0), Some(2), true, Some("PC01"), 0, "k2"),
        (false, true)
    );
    let old = BaseState {
        akey: String::new(),
        ..st(None, "PC01", 0)
    };
    assert_eq!(
        base_plan(&old, Some(2), true, Some("PC01"), 0, "k1"),
        (false, true)
    );
    // The first boot's report wins over a key change seen at the same boot: kept, the key compared next time.
    assert_eq!(
        base_plan(
            &st(Some(2), "PC01", 0),
            Some(2),
            true,
            Some("PC01"),
            0,
            "k2"
        ),
        (true, false)
    );
    // No base to drop.
    assert_eq!(
        base_plan(&st(None, "PC01", 0), Some(2), false, Some("PC09"), 0, "k2"),
        (false, false)
    );
    // A stored state from before the key field still reads (no key = "").
    assert_eq!(
        serde_json::from_str::<BaseState>(r#"{"pending":3,"host":"PC01","lic":0}"#)
            .unwrap()
            .akey,
        ""
    );
    // An empty state (never set up) parses from "{}".
    assert_eq!(
        serde_json::from_str::<BaseState>("{}").unwrap(),
        BaseState::default()
    );
}

/// Windows boots its disk's default loader; Linux its distribution's shim first (the default \EFI\BOOT\BOOTX64.EFI
/// would be shim's fallback: firmware boot entry + restart at every boot), each try on one line so a missing file
/// falls through to the next, the default loader last.
#[test]
fn linux_goldens_boot_their_distribution_loader() {
    let uri = "iscsi:10.20.0.1::::iqn.x:golden-u.m0011";
    assert_eq!(
        san_boot("windows", uri),
        format!("sanboot --drive 0x80 {uri} || goto failed")
    );
    let l = san_boot("linux", uri);
    let lines: Vec<&str> = l.lines().collect();
    assert_eq!(lines.len(), 2, "{l}");
    assert_eq!(
        lines[0],
        format!("sanhook --drive 0x80 {uri} || goto failed")
    );
    let tries: Vec<&str> = lines[1].split(" || ").collect();
    assert_eq!(tries.len(), LINUX_LOADERS.len() + 2);
    assert_eq!(
        tries[0],
        r"sanboot --drive 0x80 --filename \EFI\ubuntu\shimx64.efi"
    );
    assert!(
        tries[..LINUX_LOADERS.len()]
            .iter()
            .all(|t| t.starts_with("sanboot --drive 0x80 --filename \\EFI\\"))
    );
    assert_eq!(tries[LINUX_LOADERS.len()], "sanboot --drive 0x80");
    assert_eq!(tries[LINUX_LOADERS.len() + 1], "goto failed");
}

/// Ubuntu installer: golden attached, the ISO's kernel + initrd from the server, the live system fetches the ISO
/// (casper wants a URL ending in .iso) and its seed over HTTP.
#[test]
fn ubuntu_installer_boot() {
    let s = casper_script("ubu", "iscsi:10.20.0.1::::iqn.x:golden-ubu.g3", "10.20.0.1");
    let lines: Vec<&str> = s.lines().collect();
    assert_eq!(
        lines[0],
        "sanhook --drive 0x80 iscsi:10.20.0.1::::iqn.x:golden-ubu.g3 || goto failed"
    );
    assert!(lines[1].starts_with("kernel /boot/iso/ubu/vmlinuz initrd=initrd ip=dhcp "));
    assert!(lines[1].contains(" url=http://10.20.0.1/boot/iso/ubu/installer.iso "));
    assert!(
        lines[1].contains(" cloud-config-url=/dev/null "),
        "else cloud-init fetches url= again"
    );
    assert!(lines[1].contains(" ds=nocloud;s=http://10.20.0.1/boot/nocloud/ubu/ "));
    assert!(lines[1].ends_with(" --- || goto failed"));
    assert_eq!(
        lines[2],
        "initrd --name initrd /boot/iso/ubu/initrd || goto failed"
    );
    assert_eq!(lines[3], "boot || goto failed");
}

/// The seed: interactive, logs in to the golden before the disks are probed, installs broom-diskless.sh in the target.
#[test]
fn ubuntu_installer_seed() {
    let u = nocloud_user_data("10.20.0.1");
    assert!(u.starts_with("#cloud-config\nautoinstall:\n  version: 1\n"));
    assert!(u.contains("  interactive-sections: [\"*\"]\n"));
    let early = u.split("  early-commands:\n").nth(1).unwrap();
    assert!(early.starts_with("    - modprobe iscsi_ibft\n    - iscsistart -b\n"));
    assert!(u.contains(
        "  late-commands:\n    - \"curtin in-target --target=/target -- sh -c 'curl -fsS http://10.20.0.1/broom-diskless.sh | sh'\"\n"
    ));
    assert!(u.is_ascii() && !u.contains('\t'), "YAML: spaces only");
}

/// fmt=env for the shell script: fixed keys, values cut to a safe set (nothing a shell or sed would interpret).
#[test]
fn client_env_lines() {
    let v = serde_json::json!({"role": "diskless", "golden": "ubu", "ver": 3, "first": true, "host": "PC-01"});
    assert_eq!(
        client_env(&v),
        "ROLE=diskless\nGOLDEN=ubu\nVER=3\nFIRST=1\nHOST=PC-01\n"
    );
    let v = serde_json::json!({"role": "none", "host": "a$(reboot);b`x`/\\\n\"c"});
    assert_eq!(
        client_env(&v),
        "ROLE=none\nGOLDEN=\nVER=\nFIRST=\nHOST=arebootbxc\n"
    );
}

/// A failed try lets its drives go (else the next try in the same iPXE fails: "Address already in use").
#[test]
fn boot_scripts_let_their_drives_go() {
    let s = boot_script("sanboot --drive 0x80 x || goto failed", "w11");
    let lines: Vec<&str> = s.lines().collect();
    assert_eq!(
        lines[..4],
        [
            "#!ipxe",
            "sanunhook --drive 0x80 ||",
            "sanunhook --drive 0x81 ||",
            "sanboot --drive 0x80 x || goto failed"
        ]
    );
    let failed = s.split(":failed\n").nth(1).unwrap();
    assert!(failed.starts_with(
        "sanunhook --drive 0x80 ||\nsanunhook --drive 0x81 ||\necho Could not boot w11"
    ));
    assert!(failed.ends_with("chain /boot.ipxe?mac=${net0/mac}&ip=${net0/ip}\n"));
}

#[test]
fn windows_gets_no_ibft_gateway_on_the_servers_subnet() {
    // This host's own address stands in for the server's: a client on its subnet → no gateway for Windows.
    if let Some((own, _)) = crate::tls::local_ipv4_nets().into_iter().next() {
        let srv = own.to_string();
        assert_eq!(
            ibft_gateway_line("windows", &srv, &srv),
            "set net0/gateway 0.0.0.0\n"
        );
        assert_eq!(
            ibft_gateway_line("linux", &srv, &srv),
            "",
            "Linux keeps its gateway"
        );
    }
    // A server address this host does not have (or none set): nothing changes.
    assert_eq!(
        ibft_gateway_line("windows", "203.0.113.77", "203.0.113.78"),
        ""
    );
    assert_eq!(ibft_gateway_line("windows", "", "192.168.1.121"), "");
}

#[test]
fn router_kept_only_when_the_boot_left_it_out() {
    let mac = "AA:BB:CC:00:11:22";
    note_router(mac, "set net0/gateway 0.0.0.0\n", Some("192.168.1.254"));
    assert_eq!(
        router_of("aa:bb:cc:00:11:22").as_deref(),
        Some("192.168.1.254")
    );
    // Its next boot keeps the iBFT gateway (another subnet / Linux): nothing for its script to add.
    note_router(mac, "", Some("192.168.1.254"));
    assert_eq!(router_of(mac), None);
    // Not an address (or none, or 0.0.0.0): forgotten, never passed on.
    for bad in [Some("192.168.1.254\nX"), Some("0.0.0.0"), Some(""), None] {
        note_router(mac, "set net0/gateway 0.0.0.0\n", Some("10.0.0.1"));
        note_router(mac, "set net0/gateway 0.0.0.0\n", bad);
        assert_eq!(router_of(mac), None, "{bad:?}");
    }
}
