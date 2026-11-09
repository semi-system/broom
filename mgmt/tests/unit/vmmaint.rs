use super::*;

fn args() -> Vec<String> {
    qemu_args(
        "w11",
        "/dev/disk/by-path/golden",
        &[("/dev/disk/by-path/games".into(), "BROOMG1".into())],
        ("/ovmf/code.fd", "/vm/vars.fd"),
        ("/vm/qmp.sock", "/vm/vnc.sock"),
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
    let drives = after(&a, "-drive");
    assert!(drives.contains(
        &"file=/dev/disk/by-path/golden,format=raw,if=none,id=d0,cache=none,aio=threads"
    ));
    assert!(
        drives.contains(
            &"file=/dev/disk/by-path/games,format=raw,if=none,id=g0,cache=none,aio=threads"
        )
    );
    assert!(drives.contains(&"if=pflash,format=raw,readonly=on,file=/ovmf/code.fd"));
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
