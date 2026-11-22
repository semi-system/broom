use super::*;

fn args() -> Vec<String> {
    qemu_args(
        "w11",
        "iqn.test:w11.g1.u0123456789abcdef",
        &[("iqn.test:g.g2.u0123456789abcdef".into(), "BROOMG1".into())],
        ("/ovmf/code.fd", "/vm/vars.fd"),
        ("/vm/qmp.sock", "/vm/vnc.sock"),
        (6, 12),
    )
}

fn after<'a>(a: &'a [String], flag: &str) -> Vec<&'a str> {
    a.windows(2)
        .filter(|w| w[0] == flag)
        .map(|w| w[1].as_str())
        .collect()
}

/// The golden boots from AHCI port 0; each games disk is on the next port with the serial Windows finds it by; the
/// screen is VNC on a Unix socket only (no TCP port); internet through QEMU's NAT; restarts stay inside the VM
/// (Windows Update), so no -no-reboot.
#[test]
fn vm_command_line() {
    let a = args();
    let dev = after(&a, "-device");
    assert!(
        dev.contains(&"ide-hd,drive=d0,bus=sata.0,bootindex=1"),
        "{dev:?}"
    );
    assert!(
        dev.contains(&"ide-hd,drive=g0,bus=sata.1,serial=BROOMG1"),
        "{dev:?}"
    );
    assert!(dev.contains(&"usb-tablet,bus=usb.0"));
    assert!(
        dev.iter()
            .any(|d| d.starts_with("e1000e,netdev=n0,mac=52:54:00:"))
    );
    // The disks are the daemon's NBD exports on its root-only socket, named like the iSCSI targets of the sessions:
    // no block device, no file path of the server.
    let disks = after(&a, "-blockdev");
    assert_eq!(
        disks,
        [
            "driver=nbd,node-name=d0,server.type=unix,server.path=/run/broom-nbd.sock,export=iqn.test:w11.g1.u0123456789abcdef",
            "driver=nbd,node-name=g0,server.type=unix,server.path=/run/broom-nbd.sock,export=iqn.test:g.g2.u0123456789abcdef",
        ]
    );
    let drives = after(&a, "-drive");
    assert!(drives.contains(&"if=pflash,format=raw,readonly=on,file=/ovmf/code.fd"));
    assert!(
        !drives.iter().any(|d| d.contains("/dev/")),
        "no block device of the server: {drives:?}"
    );
    assert_eq!(after(&a, "-vnc"), ["unix:/vm/vnc.sock"]);
    assert_eq!(after(&a, "-netdev"), ["user,id=n0"]);
    assert_eq!(after(&a, "-qmp"), ["unix:/vm/qmp.sock,server=on,wait=off"]);
    assert_eq!(after(&a, "-name"), ["broom-vm-w11,process=broom-vm-w11"]);
    assert!(!a.iter().any(|x| x == "-no-reboot"));
    assert!(
        !a.iter().any(|x| x.contains("tcp") || x.contains("0.0.0.0")),
        "no network listener: {a:?}"
    );
}

/// One MAC per golden, locally administered (QEMU's 52:54:00), the same every time.
#[test]
fn mac_per_golden() {
    assert_eq!(mac_of("w11"), mac_of("w11"));
    assert_ne!(mac_of("w11"), mac_of("w10"));
    assert!(mac_of("w11").starts_with("52:54:00:") && mac_of("w11").len() == 17);
}

/// The lines broom-games.ps1 reads (-LinesFile) match its pattern '^([a-z0-9-]+) (\S+) ([D-Z]) ([012])\s*$'.
#[test]
fn games_lines_for_the_script() {
    let g = vec![
        GamesDisk {
            name: "games".into(),
            letter: "G".into(),
            serial: "BROOMG1".into(),
            target: "t".into(),
        },
        GamesDisk {
            name: "more-2".into(),
            letter: "H".into(),
            serial: "BROOMG2".into(),
            target: "t".into(),
        },
    ];
    assert_eq!(
        games_lines(&g),
        "games serial:BROOMG1 G 1\nmore-2 serial:BROOMG2 H 1\n"
    );
}

/// Only this server itself counts as the VM (it reaches Broom through QEMU's NAT).
#[test]
fn own_addresses() {
    let own = vec!["10.20.0.1".to_string(), "192.168.1.111".to_string()];
    assert!(is_own("127.0.0.1".parse().unwrap(), &own));
    assert!(is_own("10.20.0.1".parse().unwrap(), &own));
    assert!(!is_own("10.20.0.21".parse().unwrap(), &own));
    assert!(!is_own("192.168.1.50".parse().unwrap(), &own));
}

#[test]
fn active_states() {
    for (st, on) in [
        ("starting", true),
        ("running", true),
        ("stopping", true),
        ("stopped", false),
        ("failed", false),
    ] {
        let s = Session {
            state: st.into(),
            ..Default::default()
        };
        assert_eq!(s.active(), on, "{st}");
    }
}

/// The maintenance VM's unit: systemd's limits around QEMU — read-only file system but its work folder, no new
/// privileges, only the two capabilities QEMU needs to change to its unprivileged user — and nothing that narrows
/// its network or devices (it must reach the internet and the server's LANs, KVM and its disks).
#[test]
fn vm_unit_limits() {
    let v = super::unit_limits(std::path::Path::new("/data/wb/diskless/.vm/w11"));
    assert_eq!(v.len() % 2, 0);
    assert!(v.chunks(2).all(|c| c[0] == "-p"), "{v:?}");
    let props: Vec<&str> = v.chunks(2).map(|c| c[1].as_str()).collect();
    for want in [
        "NoNewPrivileges=yes",
        "CapabilityBoundingSet=CAP_SETUID CAP_SETGID",
        "ProtectSystem=strict",
        "ReadWritePaths=/data/wb/diskless/.vm/w11",
        "ProtectHome=yes",
        "PrivateTmp=yes",
        "RestrictSUIDSGID=yes",
    ] {
        assert!(props.contains(&want), "{want} missing: {props:?}");
    }
    for p in &props {
        for narrow in [
            "PrivateNetwork",
            "RestrictAddressFamilies",
            "IPAddress",
            "PrivateDevices",
            "DevicePolicy",
        ] {
            assert!(
                !p.starts_with(narrow),
                "{p}: the VM's network and devices are not narrowed"
            );
        }
    }
}

/// The VM's size is a setting held under a ceiling: the server keeps 4 CPU threads and 4 GB for itself, whatever is
/// asked; nothing set = 4 threads and 8 GB where the server has them; the size chosen is what QEMU is started with.
#[test]
fn vm_size_is_set_under_a_ceiling() {
    let gb = 1u64 << 30;
    // A server like the lab's: 8 threads, 32 GB installed (the kernel reports a little less).
    let lab = most(8, 32 * gb - 700 * (1 << 20));
    assert_eq!(lab, (4, 28));
    assert_eq!(sized((0, 0), lab), (4, 8), "nothing set");
    assert_eq!(sized((2, 16), lab), (2, 16), "as set");
    assert_eq!(sized((64, 512), lab), (4, 28), "never past the ceiling");
    // A large server: 40 threads, 64 GB.
    assert_eq!(most(40, 64 * gb), (36, 60));
    assert_eq!(sized((16, 32), most(40, 64 * gb)), (16, 32));
    // A small one: something is left for the VM, the default shrinks to it.
    assert_eq!(most(4, 4 * gb), (1, 2));
    assert_eq!(sized((0, 0), most(4, 6 * gb)), (1, 2));
    let a = args();
    assert_eq!(after(&a, "-smp"), ["6"]);
    assert_eq!(after(&a, "-m"), ["12288"]);
}
