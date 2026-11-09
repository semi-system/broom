use super::*;

#[test]
fn inf_ids_utf8_and_utf16() {
    let inf = "[NVIDIA_Devices.NTamd64]\n%NVIDIA_DEV.2504% = Section001, PCI\\VEN_10DE&DEV_2504&SUBSYS_12345678\n\
                   %X% = S, pci\\ven_10de&dev_2504\nUSB\\VID_046d&PID_C52B&MI_00\nPCI\\VEN_ZZZZ&DEV_1\nHDAUDIO\\FUNC_01&VEN_10EC";
    let want: Vec<&str> = vec!["PCI\\VEN_10DE&DEV_2504", "USB\\VID_046D&PID_C52B"];
    assert_eq!(
        inf_hwids(&inf_text(inf.as_bytes()))
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        want
    );
    let mut le = vec![0xFF, 0xFE];
    le.extend(inf.encode_utf16().flat_map(u16::to_le_bytes));
    assert_eq!(
        inf_hwids(&inf_text(&le))
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        want
    );
    let mut be = vec![0xFE, 0xFF];
    be.extend(inf.encode_utf16().flat_map(u16::to_be_bytes));
    assert_eq!(inf_hwids(&inf_text(&be)).len(), 2);
}

#[test]
fn pick_by_hardware_group_or_all() {
    let d = |id, name: &str, hw: &[&str], all, groups: &[&str]| Driver {
        id,
        name: name.into(),
        sha256: String::new(),
        size: 0,
        hwids: hw.iter().map(|s| s.to_string()).collect(),
        all_machines: all,
        groups: groups.iter().map(|s| s.to_string()).collect(),
        created: 0,
    };
    let ds = [
        d(1, "nvidia", &["PCI\\VEN_10DE&DEV_2504"], false, &[]),
        d(2, "amd", &["PCI\\VEN_1002&DEV_73BF"], false, &["VIP"]),
        d(3, "tools", &[], true, &[]),
    ];
    let names = |hw: &[&str], grp| {
        let hw: BTreeSet<String> = hw.iter().map(|s| s.to_string()).collect();
        pick(&ds, &hw, grp)
            .iter()
            .map(|d| d.name.clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        names(&["PCI\\VEN_10DE&DEV_2504"], None),
        ["nvidia", "tools"]
    );
    assert_eq!(names(&[], Some("vip")), ["amd", "tools"]); // group, case-insensitive
    assert_eq!(names(&[], None), ["tools"]);
    assert!(group_ok("VIP-1") && !group_ok("") && !group_ok("a b"));
}

/// Network-card packages: Class=Net (any spacing / case) or the Net class GUID; other classes are not.
#[test]
fn network_card_inf() {
    assert!(inf_is_net(
        "[Version]\r\nSignature=\"$WINDOWS NT$\"\r\nClass       = Net\r\n"
    ));
    assert!(inf_is_net(
        "[Version]\nClassGUID = {4D36E972-E325-11CE-BFC1-08002BE10318}\n"
    ));
    assert!(!inf_is_net(
        "[Version]\nClass=Display\nClassGuid={4d36e968-e325-11ce-bfc1-08002be10318}\n"
    ));
    assert!(!inf_is_net(
        "; Class=Net in a comment line is not the [Version] key\nClass=Network"
    ));
}

/// A card's full hardware IDs → the vendor + device the library indexes; packages picked by those.
#[test]
fn packages_for_a_card() {
    assert_eq!(
        ven_dev("PCI\\VEN_8086&DEV_125C&SUBSYS_00008086&REV_04").as_deref(),
        Some("PCI\\VEN_8086&DEV_125C")
    );
    assert_eq!(
        ven_dev("pci\\ven_10ec&dev_8126").as_deref(),
        Some("PCI\\VEN_10EC&DEV_8126")
    );
    assert_eq!(ven_dev("PCI\\VEN_8086&CC_0200"), None);
    assert_eq!(
        ven_dev("USB\\VID_0B95&PID_1790&REV_0100").as_deref(),
        Some("USB\\VID_0B95&PID_1790")
    );
    let pkg = |id: i64, name: &str, ids: &[&str]| Driver {
        id,
        name: name.into(),
        sha256: String::new(),
        size: 0,
        hwids: ids.iter().map(|s| s.to_string()).collect(),
        all_machines: false,
        groups: vec![],
        created: 0,
    };
    let lib = [
        pkg(
            1,
            "intel-e2f",
            &["PCI\\VEN_8086&DEV_125B", "PCI\\VEN_8086&DEV_125C"],
        ),
        pkg(2, "realtek-ws640", &["PCI\\VEN_10EC&DEV_8126"]),
    ];
    let card = vec![
        "PCI\\VEN_8086&DEV_125C&SUBSYS_00008086&REV_04".to_string(),
        "PCI\\VEN_8086&CC_020000".to_string(),
    ];
    let got: Vec<&str> = matching(&lib, &card)
        .iter()
        .map(|d| d.name.as_str())
        .collect();
    assert_eq!(got, vec!["intel-e2f"]);
    assert!(matching(&lib, &["PCI\\VEN_15AD&DEV_07B0".to_string()]).is_empty());
}
