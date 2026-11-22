use super::{
    Job, Nic, WINPE_FILES, active, busid_card, client_answer, judge, parse_pnputil, parse_report,
    parse_wmic, put, qemu_args, secure_boot, startnet, vm_asking, vm_job, vm_script, waiting_hint,
    wimboot_script,
};
use std::collections::HashMap;

/// pnputil /enum-devices /class Net /ids as Windows PE 26100 prints it (English), with a miniport and two cards.
const PNPUTIL: &str = "Microsoft PnP Utility\r\n\r\n\
Instance ID:                ROOT\\NET\\0000\r\n\
Device Description:         Microsoft Kernel Debug Network Adapter\r\n\
Class Name:                 Net\r\n\
Class GUID:                 {4d36e972-e325-11ce-bfc1-08002be10318}\r\n\
Manufacturer Name:          Microsoft\r\n\
Status:                     Stopped\r\n\
Driver Name:                kdnic.inf\r\n\
Hardware IDs:               root\\kdnic\r\n\
\r\n\
Instance ID:                PCI\\VEN_8086&DEV_10D3&SUBSYS_00008086&REV_00\\5&2490727a&0&9808F0\r\n\
Device Description:         Intel(R) 82574L Gigabit Network Connection\r\n\
Class Name:                 Net\r\n\
Class GUID:                 {4d36e972-e325-11ce-bfc1-08002be10318}\r\n\
Manufacturer Name:          Intel\r\n\
Status:                     Started\r\n\
Driver Name:                oem3.inf\r\n\
Hardware IDs:               PCI\\VEN_8086&DEV_10D3&SUBSYS_00008086&REV_00\r\n\
                            PCI\\VEN_8086&DEV_10D3&SUBSYS_00008086\r\n\
                            PCI\\VEN_8086&DEV_10D3&CC_020000\r\n\
                            PCI\\VEN_8086&DEV_10D3&CC_0200\r\n\
Compatible IDs:             PCI\\VEN_8086&DEV_10D3&REV_00\r\n\
                            PCI\\VEN_8086&DEV_10D3\r\n\
                            PCI\\VEN_8086&CC_020000\r\n\
                            PCI\\VEN_8086&CC_0200\r\n\
                            PCI\\VEN_8086\r\n\
                            PCI\\CC_020000\r\n\
                            PCI\\CC_0200\r\n\
\r\n\
Instance ID:                PCI\\VEN_1AF4&DEV_1000&SUBSYS_00011AF4&REV_00\\5&2490727a&0&9008F0\r\n\
Device Description:         Ethernet Controller\r\n\
Class Name:                 Net\r\n\
Class GUID:                 {4d36e972-e325-11ce-bfc1-08002be10318}\r\n\
Manufacturer Name:          (Unknown)\r\n\
Status:                     Problem\r\n\
Problem Code:               28 (0x1C) [CM_PROB_FAILED_INSTALL]\r\n\
Hardware IDs:               PCI\\VEN_1AF4&DEV_1000&SUBSYS_00011AF4&REV_00\r\n\
                            PCI\\VEN_1AF4&DEV_1000&SUBSYS_00011AF4\r\n\
Compatible IDs:             PCI\\VEN_1AF4&DEV_1000&REV_00\r\n\
\r\n\
Instance ID:                SWD\\MSRRAS\\MS_NDISWANIP\r\n\
Device Description:         WAN Miniport (IP)\r\n\
Hardware IDs:               ms_ndiswanip\r\n";

#[test]
fn pnputil_physical_cards_only() {
    let n = parse_pnputil(PNPUTIL);
    assert_eq!(n.len(), 2, "ROOT\\ and SWD\\ devices are not cards: {n:?}");
    assert_eq!(
        n[0].instance,
        "PCI\\VEN_8086&DEV_10D3&SUBSYS_00008086&REV_00\\5&2490727a&0&9808F0"
    );
    assert_eq!(n[0].name, "Intel(R) 82574L Gigabit Network Connection");
    assert_eq!(n[0].status, "Started");
    assert_eq!(n[0].hwids.len(), 4);
    assert_eq!(n[0].hwids[3], "PCI\\VEN_8086&DEV_10D3&CC_0200");
    assert_eq!(n[0].compat.len(), 7);
    assert_eq!(n[0].compat[6], "PCI\\CC_0200");
    assert_eq!(
        n[1].status, "Problem",
        "a card without a driver in Windows PE is still reported"
    );
    assert_eq!(n[1].hwids.len(), 2);
    assert_eq!(
        n[1].compat,
        vec!["PCI\\VEN_1AF4&DEV_1000&REV_00".to_string()]
    );
}

#[test]
fn pnputil_hostile_or_empty() {
    assert!(parse_pnputil("").is_empty());
    assert!(parse_pnputil("garbage\nInstance ID: nothing").is_empty());
    // An ID with characters Windows never uses (quote, space, $) is dropped: it would reach the VM's script.
    let evil = "Instance ID: PCI\\VEN_1&DEV_2\\x\"; rm\r\nHardware IDs: PCI\\VEN_1&DEV_2\r\n";
    assert!(parse_pnputil(evil).is_empty());
    let bad_hw =
        "Instance ID: PCI\\VEN_1&DEV_2\\3&4&0&08\r\nHardware IDs: PCI\\VEN_1&DEV_2 $(x)\r\n";
    assert!(
        parse_pnputil(bad_hw).is_empty(),
        "no usable hardware ID left"
    );
    // The same card twice (pnputil with /ids, then /properties) counts once.
    let twice = format!("{PNPUTIL}\r\n{PNPUTIL}");
    assert_eq!(parse_pnputil(&twice).len(), 2);
    // USB cards count too.
    let usb = "Instance ID: USB\\VID_0B95&PID_1790\\0000000000001\r\nDevice Description: ASIX AX88179\r\nHardware IDs: USB\\VID_0B95&PID_1790&REV_0100\r\n";
    assert_eq!(parse_pnputil(usb).len(), 1);
}

#[test]
fn wimboot_script_boots_plain_winpe() {
    let s = wimboot_script("w11", "abc123", false);
    assert!(
        !s.contains("broom-drivers.tar"),
        "no network-card package in the library"
    );
    let d = wimboot_script("w11", "abc123", true);
    assert!(d.contains(
        "initrd --name broom-drivers.tar /boot/onboard/broom-drivers.tar?t=abc123 broom-drivers.tar || goto failed\n"
    ));
    assert!(s.starts_with("#!ipxe\n"));
    assert!(s.is_ascii());
    assert!(s.contains("kernel /boot/onboard/wimboot?t=abc123 index=1 || goto failed\n"));
    for (_, n) in WINPE_FILES {
        assert!(
            s.contains(&format!(
                "initrd --name {n} /boot/onboard/{n}?t=abc123 {n} || goto failed"
            )),
            "{n} missing: {s}"
        );
    }
    assert!(s.contains(
        "initrd --name broom-report.exe /boot/onboard/broom-report.exe?t=abc123 broom-report.exe"
    ));
    assert!(s.contains(
        "startnet.cmd?t=abc123&ip=${net0/ip}&mask=${net0/netmask}&gw=${net0/gateway} startnet.cmd || goto failed"
    ));
    assert!(s.contains("boot || goto failed\n:failed\n"));
    assert!(s.ends_with("chain /boot.ipxe?mac=${net0/mac}&ip=${net0/ip}\n"));
}

#[test]
fn startnet_runs_the_reporter() {
    let c = startnet(
        "10.20.0.1",
        "tok",
        "10.20.0.22",
        "255.255.255.0",
        "10.20.0.1",
    );
    assert_eq!(
        c,
        "@echo off\r\nwpeinit\r\ncls\r\necho.\r\nbroom-report.exe http://10.20.0.1 tok 10.20.0.22 255.255.255.0 10.20.0.1\r\n"
    );
}

/// The job's VM: the golden is an NBD export of the daemon on its root-only socket (AHCI: Windows has storahci at
/// boot), no block device of the server, QEMU's NAT with an e1000e for the script's way to the server, no screen, and
/// it exits at the first restart (a try ends there).
#[test]
fn qemu_disk_is_ahci_over_nbd() {
    let a = qemu_args(
        "iqn.x:golden-w.g2.u0123456789abcdef",
        "/c.fd",
        "/v.fd",
        "/q.sock",
    );
    let j = a.join(" ");
    assert!(j.contains("-machine q35,accel=kvm -cpu host"));
    assert!(j.contains(
        "-blockdev driver=nbd,node-name=d0,server.type=unix,server.path=/run/broom-nbd.sock,export=iqn.x:golden-w.g2.u0123456789abcdef"
    ));
    assert!(!j.contains("/dev/"), "no block device of the server: {j}");
    assert!(j.contains("-device ahci,id=sata -device ide-hd,drive=d0,bus=sata.0,bootindex=1"));
    assert!(j.contains("-netdev user,id=n0 -device e1000e,netdev=n0"));
    assert!(j.contains("if=pflash,format=raw,readonly=on,file=/c.fd"));
    assert!(j.contains("-display none"));
    assert!(j.ends_with("-no-reboot"));
}

#[test]
fn job_states() {
    let mut j = Job {
        state: "waiting".into(),
        ..Default::default()
    };
    assert!(active(&j));
    j.state = "installing".into();
    assert!(active(&j));
    for s in ["done", "failed", "cancelled"] {
        j.state = s.into();
        assert!(!active(&j), "{s}");
    }
    // Old / partial stored jobs still read.
    let j: Job =
        serde_json::from_str(r#"{"golden":"w11","machine":3,"mac":"aa","state":"done"}"#).unwrap();
    assert_eq!(j.machine, 3);
    assert!(j.nics.is_empty() && j.token.is_empty());
}

const WMIC: &str = "MACAddress         PNPDeviceID\r\n\
                   ROOT\\NET\\0000\r\n\
52:54:00:6A:35:EC  PCI\\VEN_8086&DEV_10D3&SUBSYS_00008086&REV_00\\5&2490727A&0&9808F0\r\n\
                   SWD\\MSRRAS\\MS_NDISWANIP\r\n\
\r\n";

#[test]
fn report_maps_macs() {
    assert_eq!(
        parse_wmic(WMIC),
        vec![(
            "5254006a35ec".to_string(),
            "PCI\\VEN_8086&DEV_10D3&SUBSYS_00008086&REV_00\\5&2490727A&0&9808F0".to_string()
        )]
    );
    let r = parse_report(&format!("{PNPUTIL}\r\n=== wmic nic ===\r\n{WMIC}"));
    assert_eq!(r.len(), 2);
    assert_eq!(
        r[0].mac, "5254006a35ec",
        "instance IDs compared without case"
    );
    assert_eq!(r[1].mac, "", "no driver in Windows PE → no MAC");
    assert_eq!(
        r[0].compat.len(),
        7,
        "the wmic section does not leak into the IDs"
    );
    // pnputil's text alone (an older reporter) still works.
    assert_eq!(parse_report(PNPUTIL).len(), 2);
}

fn nic(i: &str, mac: &str) -> Nic {
    Nic {
        instance: i.into(),
        name: format!("card {i}"),
        mac: mac.into(),
        ..Default::default()
    }
}

#[test]
fn judge_needs_the_boot_card() {
    let nics = [nic("PCI\\A\\1", "aabbccddeeff"), nic("PCI\\B\\2", "")];
    let r = |a: bool, b: bool| {
        vec![
            serde_json::json!({"instance": "pci\\a\\1", "ok": a}),
            serde_json::json!({"instance": "PCI\\B\\2", "ok": b}),
        ]
    };
    assert_eq!(
        judge(&nics, &r(true, true), "AA:BB:CC:DD:EE:FF", "").unwrap(),
        "2 card(s) installed"
    );
    let m = judge(&nics, &r(true, false), "aa:bb:cc:dd:ee:ff", "").unwrap();
    assert!(
        m.contains("1 card(s) installed") && m.contains("card PCI\\B\\2"),
        "{m}"
    );
    assert!(
        judge(&nics, &r(false, true), "aa:bb:cc:dd:ee:ff", "").is_err(),
        "boot card missing"
    );
    assert!(judge(&nics, &r(false, false), "", "").is_err());
    // Boot card unknown (no MAC from Windows PE): any card installed is enough.
    assert!(judge(&nics, &r(false, true), "", "").is_ok());
}

#[test]
fn secure_boot_from_windows_pe() {
    let on = "x\r\n=== secure boot ===\r\n\r\nHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State\r\n    UEFISecureBootEnabled    REG_DWORD    0x1\r\n";
    assert_eq!(secure_boot(on), Some(true));
    assert_eq!(secure_boot(&on.replace("0x1", "0x0")), Some(false));
    assert_eq!(secure_boot("no section"), None);
    assert_eq!(
        secure_boot("=== secure boot ===\r\nERROR: not found\r\n"),
        None
    );
    // The section does not reach the card parser.
    assert_eq!(parse_report(&format!("{PNPUTIL}{on}")).len(), 2);
}

/// iPXE's ${net0/busid}: bus type 1 (PCI) + vendor + device, with or without colons; anything else is not a card ID.
#[test]
fn busid_from_ipxe() {
    assert_eq!(
        busid_card("01:80:86:10:d3").as_deref(),
        Some("PCI\\VEN_8086&DEV_10D3")
    );
    assert_eq!(
        busid_card("0110ec8139").as_deref(),
        Some("PCI\\VEN_10EC&DEV_8139")
    );
    assert_eq!(busid_card(""), None, "an empty setting (iPXE without it)");
    assert_eq!(busid_card("02:12:34:56:78"), None, "another bus");
    assert_eq!(busid_card("01:80:86:10"), None);
    assert_eq!(busid_card("01:80:86:10:zz"), None);
}

/// A job waiting long after Windows PE was fetched tells why (no driver for the card), naming the card iPXE saw.
#[test]
fn hint_when_windows_pe_never_reports() {
    let mut j = Job {
        state: "waiting".into(),
        ..Default::default()
    };
    assert_eq!(waiting_hint(&j, 10_000), None, "Windows PE not fetched yet");
    j.winpe_at = 10_000;
    assert_eq!(
        waiting_hint(&j, 10_100),
        None,
        "still within the time it takes"
    );
    let h = waiting_hint(&j, 10_400).unwrap();
    assert!(
        h.contains("no driver for its network card.") && h.contains("Retry"),
        "{h}"
    );
    j.boot_card = "PCI\\VEN_8086&DEV_125C".into();
    assert!(
        waiting_hint(&j, 10_400)
            .unwrap()
            .contains("(PCI\\VEN_8086&DEV_125C)")
    );
    j.state = "installing".into();
    assert_eq!(waiting_hint(&j, 10_400), None, "it reported");
}

/// Windows PE without a driver for a card lists it among the problem devices (class Unknown): kept when its IDs say
/// network controller (CC_02xx), other problem devices (a display adapter) dropped; the Net class is always kept.
#[test]
fn driverless_network_card_is_reported() {
    let prob = "Instance ID:                PCI\\VEN_15AD&DEV_07B0&SUBSYS_07B015AD&REV_01\\4&3b4d2e6&0&0010\r\n\
Device Description:         Ethernet Controller\r\n\
Class Name:                 Unknown\r\n\
Status:                     Problem\r\n\
Hardware IDs:               PCI\\VEN_15AD&DEV_07B0&SUBSYS_07B015AD&REV_01\r\n\
                            PCI\\VEN_15AD&DEV_07B0&CC_020000\r\n\
Compatible IDs:             PCI\\VEN_15AD&CC_0200\r\n\
\r\n\
Instance ID:                PCI\\VEN_1234&DEV_1111&SUBSYS_11001AF4&REV_02\\3&267a616a&0&08\r\n\
Device Description:         Video Controller (VGA Compatible)\r\n\
Class Name:                 Unknown\r\n\
Status:                     Problem\r\n\
Hardware IDs:               PCI\\VEN_1234&DEV_1111&SUBSYS_11001AF4&REV_02\r\n\
                            PCI\\VEN_1234&DEV_1111&CC_030000\r\n";
    let n = parse_report(&format!(
        "{PNPUTIL}\r\n{prob}\r\n=== wmic nic ===\r\n{WMIC}"
    ));
    let names: Vec<&str> = n.iter().map(|x| x.name.as_str()).collect();
    assert_eq!(
        names,
        vec![
            "Intel(R) 82574L Gigabit Network Connection",
            "Ethernet Controller",
            "Ethernet Controller"
        ],
        "the two Net-class cards + the driverless vmxnet3, not the display adapter"
    );
    assert_eq!(n[2].class, "Unknown");
    assert_eq!(n[2].mac, "", "no driver: no MAC");
}

/// The boot card is found by the vendor + device iPXE saw when Windows PE has no MAC for it.
#[test]
fn judge_finds_the_boot_card_by_ipxe() {
    let mut vmx = nic("PCI\\VEN_15AD&DEV_07B0&SUBSYS_07B015AD&REV_01\\4&1", "");
    vmx.hwids = vec!["PCI\\VEN_15AD&DEV_07B0&SUBSYS_07B015AD&REV_01".into()];
    let nics = [nic("PCI\\VEN_8086&DEV_10D3\\x", "5254006a35ec"), vmx];
    let r = |a: bool, b: bool| {
        vec![
            serde_json::json!({"instance": "PCI\\VEN_8086&DEV_10D3\\x", "ok": a}),
            serde_json::json!({"instance": "PCI\\VEN_15AD&DEV_07B0&SUBSYS_07B015AD&REV_01\\4&1", "ok": b}),
        ]
    };
    // The PC's MAC is the vmxnet3's (no driver in Windows PE → no MAC): iPXE's card decides.
    let mac = "52:54:00:d1:74:40";
    assert!(judge(&nics, &r(true, false), mac, "PCI\\VEN_15AD&DEV_07B0").is_err());
    assert!(judge(&nics, &r(false, true), mac, "PCI\\VEN_15AD&DEV_07B0").is_ok());
    assert!(
        judge(&nics, &r(true, false), mac, "").is_ok(),
        "boot card unknown: any card"
    );
}

/// A Windows PE report counts only with the job's token AND from the job's machine (its MAC behind the sender): the
/// token crosses the LAN in plain-HTTP URLs.
#[test]
fn report_needs_token_and_machine() {
    use super::{from_job_machine, token_matches};
    assert!(token_matches("abc123", "abc123"));
    assert!(!token_matches("abc123", "abc124"));
    assert!(!token_matches("", ""), "no job token: nothing matches");
    assert!(from_job_machine(
        "52:54:00:aa:bb:01",
        Some("52-54-00-AA-BB-01")
    ));
    assert!(
        !from_job_machine("52:54:00:aa:bb:01", Some("52:54:00:aa:bb:02")),
        "another PC"
    );
    assert!(
        !from_job_machine("52:54:00:aa:bb:01", None),
        "no ARP entry (not on this LAN)"
    );
    assert!(!from_job_machine("", None), "a job without a MAC");
    assert!(!from_job_machine("", Some("")));
}

/// The server's own update logins carry the job's key in the target name.
#[test]
fn local_target_carries_the_key() {
    let k = super::new_write_key();
    assert!(k.len() >= 32 && k.bytes().all(|b| b.is_ascii_hexdigit()));
    assert_ne!(k, super::new_write_key());
    let t = super::local_target("iqn.x:golden-w11.g7", &k);
    assert_eq!(
        crate::iscsid::games::split_key(&t),
        ("iqn.x:golden-w11.g7", Some(k.as_str()))
    );
}

/// QEMU is confined on every start: it drops to an unprivileged user (the option depends on its version) and runs
/// under its seccomp filter, which must allow that one change of user.
#[test]
fn qemu_confinement_args() {
    use super::{QEMU_USER, confine_args, parse_qemu_version};
    assert_eq!(
        parse_qemu_version(
            "QEMU emulator version 8.2.2 (Debian 1:8.2.2+ds-0ubuntu1.18)\nCopyright"
        ),
        Some((8, 2))
    );
    assert_eq!(
        parse_qemu_version("QEMU emulator version 10.2.1"),
        Some((10, 2))
    );
    assert_eq!(
        parse_qemu_version("QEMU emulator version 9.1.0-rc2"),
        Some((9, 1))
    );
    assert_eq!(parse_qemu_version("something else"), None);
    let sandbox = "on,obsolete=deny,elevateprivileges=allow,spawn=deny,resourcecontrol=deny";
    for v in [Some((8, 2)), Some((9, 0)), None] {
        assert_eq!(
            confine_args(v),
            ["-runas", QEMU_USER, "-sandbox", sandbox],
            "{v:?}"
        );
    }
    for v in [Some((9, 1)), Some((10, 2)), Some((11, 0))] {
        assert_eq!(
            confine_args(v),
            [
                "-run-with",
                &format!("user={QEMU_USER}"),
                "-sandbox",
                sandbox
            ],
            "{v:?}"
        );
    }
    assert_eq!(QEMU_USER, "65534:65534");
}

/// Live (needs qemu-system-x86_64 and root; no KVM needed): QEMU started with this server's confinement arguments
/// runs as the unprivileged user, with no_new_privs and a seccomp filter, a disk and user-mode networking attached.
#[test]
#[ignore]
fn live_qemu_is_confined() {
    use super::{confine_args, qemu_version, which};
    let Some(qemu) = which("qemu-system-x86_64") else {
        return;
    };
    let d = std::env::temp_dir().join(format!("broom-qemu-confine-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    let img = d.join("disk.img");
    std::fs::File::create(&img)
        .unwrap()
        .set_len(16 << 20)
        .unwrap();
    let mut c = std::process::Command::new(qemu)
        .args([
            "-machine",
            "q35,accel=tcg",
            "-m",
            "64",
            "-display",
            "none",
            "-vga",
            "none",
            "-nodefaults",
            "-S",
        ])
        .args([
            "-drive",
            &format!("file={},format=raw,if=none,id=d0", img.display()),
        ])
        .args([
            "-device",
            "ahci,id=sata",
            "-device",
            "ide-hd,drive=d0,bus=sata.0",
        ])
        .args(["-netdev", "user,id=n0", "-device", "e1000e,netdev=n0"])
        .args([
            "-qmp",
            &format!("unix:{},server=on,wait=off", d.join("qmp.sock").display()),
        ])
        .args(confine_args(qemu_version()))
        .spawn()
        .unwrap();
    std::thread::sleep(std::time::Duration::from_secs(3));
    let status = std::fs::read_to_string(format!("/proc/{}/status", c.id())).unwrap_or_default();
    let field = |k: &str| {
        status
            .lines()
            .find_map(|l| l.strip_prefix(k))
            .map(|v| v.split_whitespace().map(String::from).collect::<Vec<_>>())
            .unwrap_or_default()
    };
    let _ = c.kill();
    let _ = c.wait();
    let _ = std::fs::remove_dir_all(&d);
    assert!(
        !status.is_empty(),
        "QEMU did not stay up with the confinement arguments"
    );
    assert_eq!(field("Uid:"), ["65534"; 4], "runs as nobody");
    assert_eq!(field("Gid:"), ["65534"; 4]);
    assert_eq!(field("Groups:"), ["65534"], "no other group kept");
    assert_eq!(field("NoNewPrivs:"), ["1"]);
    assert_eq!(field("Seccomp:"), ["2"], "seccomp filter on");
    assert_eq!(field("CapEff:"), ["0000000000000000"], "no capability left");
}

/// broom-report.exe is not in the repository nor embedded: a release brings it in its assets (built by CI from
/// winpe/broom-report.c), a local build needs the one winpe/build.sh makes — and Add hardware says so instead of
/// starting a job that cannot boot Windows PE.
#[test]
fn reporter_is_built_not_committed() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    assert!(root.join("winpe/broom-report.c").is_file());
    assert!(
        !root.join("scripts/broom-report.exe").exists(),
        "no built program of our own in the repository"
    );
    // This (test) build has no release assets and no file in Broom's folder.
    if super::reporter().is_none() {
        let why = super::reporter_missing().expect("says why");
        assert!(
            why.contains("winpe/build.sh") && why.contains("broom-report.exe"),
            "{why}"
        );
    }
}

/// The boot files kept in the repository as binaries (they are signed, so they cannot be rebuilt here) are exactly
/// the pinned releases: wimboot = the SHA-256 in ipxe/fetch-signed.sh, the signed iPXE and its shim = the ones
/// fetch-signed.sh wrote into ipxe/signed/VERSION. A changed file fails here, not on a PC.
#[test]
fn committed_boot_binaries_are_the_pinned_releases() {
    use sha2::{Digest, Sha256};
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("ipxe");
    let sum = |f: &str| {
        let b = std::fs::read(dir.join(f)).unwrap_or_else(|e| panic!("{f}: {e}"));
        Sha256::digest(&b)
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect::<String>()
    };
    let script = std::fs::read_to_string(dir.join("fetch-signed.sh")).unwrap();
    let pinned = script
        .lines()
        .find_map(|l| l.strip_prefix("WIMBOOT_SHA256="))
        .expect("WIMBOOT_SHA256 in fetch-signed.sh");
    assert_eq!(sum("wimboot"), pinned.trim(), "ipxe/wimboot");
    let version = std::fs::read_to_string(dir.join("signed/VERSION")).unwrap();
    let mut seen = 0;
    for l in version.lines().skip(1) {
        let (want, file) = l.split_once("  ").expect("sha256  file");
        assert_eq!(sum(&format!("signed/{file}")), want, "ipxe/signed/{file}");
        seen += 1;
    }
    assert_eq!(seen, 2, "snponly-shim.efi and snponly.efi");
}

/// A comma in a folder's name does not split a QEMU option in two.
#[test]
fn qemu_paths_keep_their_commas() {
    assert_eq!(
        super::qpath("/data/write,back/vars.fd"),
        "/data/write,,back/vars.fd"
    );
    assert_eq!(
        super::qpath(std::path::Path::new("/plain/vars.fd").display()),
        "/plain/vars.fd"
    );
}

/// A server state over an in-memory database (what the job's endpoints read).
fn state() -> crate::SharedState {
    std::sync::Arc::new(crate::AppState {
        db: crate::db::open(":memory:").unwrap(),
        jobs: Default::default(),
        job_tx: tokio::sync::broadcast::channel(8).0,
        versions_lock: Default::default(),
        net: Default::default(),
        pxe_seen: Default::default(),
        pxe_ip: Default::default(),
        not_reset: Default::default(),
        ssd_low: Default::default(),
    })
}

fn running_job() -> Job {
    Job {
        golden: "w11".into(),
        token: "0123456789abcdef0123456789abcdef".into(),
        state: "installing".into(),
        nics: vec![nic("PCI\\VEN_8086&DEV_10D3\\1", "aa:bb:cc:dd:ee:01")],
        drivers: vec!["intel-e1000e".into()],
        ..Job::default()
    }
}

/// Who the job's VM is: the connection comes from this server itself (QEMU's NAT: loopback or one of its addresses),
/// and only while the job is installing — a PC on the LAN, a waiting or finished job and no job at all get nothing.
#[test]
fn only_this_server_is_the_vm() {
    use std::net::IpAddr;
    let st = state();
    let lo: IpAddr = "127.0.0.1".parse().unwrap();
    let lan: IpAddr = "203.0.113.9".parse().unwrap();
    assert!(vm_job(&st, lo).is_none(), "no job");
    let mut j = running_job();
    put(&st, &j);
    assert!(vm_job(&st, lo).is_some());
    assert!(
        vm_job(&st, lan).is_none(),
        "a host on the LAN is not the VM"
    );
    assert!(client_answer(&st, lan).is_none() && vm_script(&st, lan).is_none());
    for state in ["waiting", "done", "failed", "cancelled"] {
        j.state = state.into();
        put(&st, &j);
        assert!(vm_job(&st, lo).is_none(), "{state}");
    }
}

/// The VM is told it is a maintenance machine (no base, no agent) and gets the job's script with this server's address
/// and the job's token in it — and the token is nowhere else.
#[test]
fn the_vm_gets_the_onboarding_script() {
    let st = state();
    st.db.set_config("dhcp_server_ip", "192.168.50.2").unwrap();
    put(&st, &running_job());
    let lo: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    let v = client_answer(&st, lo).unwrap();
    assert_eq!(v["role"], "maintenance");
    assert_eq!(v["golden"], "w11");
    let text = vm_script(&st, lo).unwrap();
    assert!(
        text.contains("$srv = '192.168.50.2'"),
        "the server's address"
    );
    assert!(
        text.contains("$tok = '0123456789abcdef0123456789abcdef'"),
        "the job's token"
    );
    assert!(!text.contains("__SERVER__") && !text.contains("__TOKEN__"));
    assert!(text.is_ascii(), "Windows scripts are ASCII only");
    // The same file as the repository's, with nothing but those two values filled in.
    let raw = crate::assets::text("scripts/broom-onboard.ps1");
    assert_eq!(
        text,
        raw.replace("__SERVER__", "192.168.50.2")
            .replace("__TOKEN__", "0123456789abcdef0123456789abcdef")
    );
}

/// A request of the VM needs the job's token as well as this server's address: no token, an empty one and a wrong one
/// are refused, a running job's own is not.
#[test]
fn the_vm_needs_the_token() {
    let st = state();
    put(&st, &running_job());
    let lo: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    let q = |t: Option<&str>| -> HashMap<String, String> {
        t.map(|t| ("t".to_string(), t.to_string()))
            .into_iter()
            .collect()
    };
    assert!(vm_asking(&st, &q(None), lo).is_err());
    assert!(vm_asking(&st, &q(Some("")), lo).is_err());
    assert!(vm_asking(&st, &q(Some("0123456789abcdef0123456789abcdeg")), lo).is_err());
    let lan: std::net::IpAddr = "203.0.113.9".parse().unwrap();
    assert!(
        vm_asking(&st, &q(Some("0123456789abcdef0123456789abcdef")), lan).is_err(),
        "the right token from another host"
    );
    let j = vm_asking(&st, &q(Some("0123456789abcdef0123456789abcdef")), lo).unwrap();
    assert_eq!(j.golden, "w11");
}

/// The three endpoints the VM calls are open to the network layer's login (the VM has no account) — and guarded by the
/// token and the address above; everything else of Add hardware still needs a session.
#[test]
fn the_vm_endpoints_are_public_the_rest_is_not() {
    use axum::http::Method;
    for p in [
        "/api/onboard/job",
        "/api/onboard/drivers",
        "/api/onboard/result",
    ] {
        assert!(
            crate::auth::is_public(&Method::GET, p) && crate::auth::is_public(&Method::POST, p),
            "{p}"
        );
    }
    for p in [
        "/api/onboard",
        "/api/onboard/start",
        "/api/onboard/cancel",
        "/api/onboard/retry",
    ] {
        assert!(!crate::auth::is_public(&Method::POST, p), "{p}");
    }
    assert!(!crate::auth::is_public(
        &Method::POST,
        "/api/diskless/refresh"
    ));
}
