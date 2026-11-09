use super::{
    Job, Nic, WINPE_FILES, active, busid_card, judge, parse_pnputil, parse_report, parse_wmic,
    qemu_args, secure_boot, startnet, waiting_hint, wimboot_script,
};

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
    assert!(super::super::assets::bytes("scripts/broom-report.exe").starts_with(b"MZ"));
}

#[test]
fn qemu_disk_is_ahci_without_network() {
    let a = qemu_args("/dev/disk/by-path/x", "/c.fd", "/v.fd", "/q.sock");
    let j = a.join(" ");
    assert!(j.contains("-machine q35,accel=kvm -cpu host"));
    assert!(j.contains("file=/dev/disk/by-path/x,format=raw,if=none,id=d0,cache=none"));
    assert!(j.contains("-device ahci,id=sata -device ide-hd,drive=d0,bus=sata.0,bootindex=1"));
    assert!(
        j.contains("-nic none"),
        "the golden must not reach the LAN from the VM"
    );
    assert!(j.contains("if=pflash,format=raw,readonly=on,file=/c.fd"));
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
