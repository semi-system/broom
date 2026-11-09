use super::*;

/// The message ends up inside shutdown.exe's /c "…" on the PC: one line, no quotes, backslashes or shell characters,
/// spaces collapsed, at most 200 characters; letters of any language stay.
#[test]
fn message_is_cleaned() {
    assert_eq!(
        clean_msg("  Closing in 5 min,\r\n save your game!  "),
        "Closing in 5 min, save your game!"
    );
    assert_eq!(clean_msg("a\"b\\c%d^e&f|g<h>i"), "abcdefghi");
    assert_eq!(clean_msg("سنغلق بعد قليل"), "سنغلق بعد قليل");
    assert_eq!(clean_msg(&"x".repeat(500)).chars().count(), 200);
    assert_eq!(clean_msg(""), "");
}

/// The command the agent gets (vnc.rs signs it): op power, the action, the countdown capped at MAX_DELAY.
#[test]
fn agent_command_shape() {
    let v: serde_json::Value = serde_json::from_str(&agent_command("restart", 30, "bye")).unwrap();
    assert_eq!(v["op"], "power");
    assert_eq!(v["do"], "restart");
    assert_eq!(v["delay"], 30);
    assert_eq!(v["msg"], "bye");
    let v: serde_json::Value =
        serde_json::from_str(&agent_command("shutdown", 99_999, "")).unwrap();
    assert_eq!(v["delay"], MAX_DELAY);
}

/// A sent action shows while it plays out (its countdown + a few minutes), then goes; MACs compared without case.
#[test]
fn pending_expires() {
    let now = crate::now_secs();
    PENDING.lock().insert(
        "aa:bb:cc:00:00:01".into(),
        Pending {
            what: "restart".into(),
            at: now,
            delay: 30,
        },
    );
    assert_eq!(
        pending("AA:BB:CC:00:00:01").map(|p| p.what),
        Some("restart".to_string())
    );
    PENDING.lock().insert(
        "aa:bb:cc:00:00:02".into(),
        Pending {
            what: "shutdown".into(),
            at: now - 1000,
            delay: 30,
        },
    );
    assert_eq!(pending("aa:bb:cc:00:00:02"), None);
    assert!(
        !PENDING.lock().contains_key("aa:bb:cc:00:00:02"),
        "an old one is dropped"
    );
    assert_eq!(pending("aa:bb:cc:00:00:03"), None);
}
