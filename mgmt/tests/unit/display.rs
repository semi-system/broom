use super::*;

/// Modes typed by people: "1920x1080@165", "1920 × 1080 @ 165 Hz"; nonsense refused.
#[test]
fn mode_text() {
    assert_eq!(parse_mode("1920x1080@165"), Some((1920, 1080, 165)));
    assert_eq!(
        parse_mode(" 2560 × 1440 @ 144 Hz "),
        Some((2560, 1440, 144))
    );
    assert_eq!(parse_mode("1920X1080@60hz"), Some((1920, 1080, 60)));
    assert_eq!(parse_mode("1920x1080"), None, "refresh needed");
    assert_eq!(parse_mode("10x10@60"), None);
    assert_eq!(parse_mode("1920x1080@5000"), None);
    assert_eq!(parse_mode(""), None);
    assert_eq!(fmt_mode((1920, 1080, 165)), "1920x1080@165");
    let c: serde_json::Value = serde_json::from_str(&command((1920, 1080, 165))).unwrap();
    assert_eq!(
        (c["op"].as_str(), c["w"].as_u64(), c["hz"].as_u64()),
        (Some("display"), Some(1920), Some(165))
    );
}

/// A machine's own setting wins; else its group's (any case); else none.
#[test]
fn machine_then_group() {
    let m = |mac: &str, g: Option<&str>| Machine {
        mac: mac.into(),
        grp: g.map(Into::into),
        ..Default::default()
    };
    let mut s = Settings::default();
    s.groups.insert("Lounge".into(), "1920x1080@165".into());
    s.machines
        .insert("aa:bb:cc:00:00:01".into(), "2560x1440@144".into());
    assert_eq!(
        effective(&s, &m("AA:BB:CC:00:00:01", Some("lounge"))),
        Some((2560, 1440, 144))
    );
    assert_eq!(
        effective(&s, &m("aa:bb:cc:00:00:02", Some("LOUNGE"))),
        Some((1920, 1080, 165))
    );
    assert_eq!(effective(&s, &m("aa:bb:cc:00:00:03", Some("VIP"))), None);
    assert_eq!(effective(&s, &m("aa:bb:cc:00:00:04", None)), None);
}
