use super::*;

fn pins(p: &[(&str, u64)]) -> BTreeMap<String, u64> {
    p.iter().map(|(k, v)| (k.to_string(), *v)).collect()
}

/// A machine's group picks its version (any case); no group or not held = the newest; the oldest held version is kept.
#[test]
fn version_per_group() {
    let p = pins(&[("Lounge", 6), ("VIP", 5)]);
    assert_eq!(pin_for(&p, Some("lounge")), Some(6));
    assert_eq!(pin_for(&p, Some("VIP")), Some(5));
    assert_eq!(pin_for(&p, Some("Test")), None);
    assert_eq!(pin_for(&p, None), None);
    assert_eq!(keep_from(&p), Some(5));
    assert_eq!(keep_from(&BTreeMap::new()), None);
}

/// Pins of groups that no longer get the disk go; a games disk for every machine (no groups) keeps all.
#[test]
fn pins_follow_groups() {
    let p = pins(&[("Lounge", 6), ("Old", 3)]);
    assert_eq!(
        pruned(&p, &["lounge".into()], false),
        pins(&[("Lounge", 6)])
    );
    assert_eq!(
        pruned(&p, &[], false),
        BTreeMap::new(),
        "a golden with no group boots on no machine"
    );
    assert_eq!(
        pruned(&p, &[], true),
        p,
        "a games disk with no group is for every machine"
    );
}

/// After a Save: which groups still wait on an older version.
#[test]
fn held_message() {
    assert_eq!(
        held_note(&pins(&[("Lounge", 6), ("Test", 7)]), 7),
        " — held: Lounge on g6 (move them to g7 once it is checked)"
    );
    assert_eq!(held_note(&pins(&[("Test", 7)]), 7), "");
}
