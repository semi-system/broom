use super::*;

/// The CSV row: one machine's list summed up, fields quoted, a formula-looking value neutralised, nothing for a
/// machine whose agent never sent a list.
#[test]
fn csv_row() {
    let v = serde_json::json!({
        "maker": "Micro-Star", "model": "MS-7E06", "board": "MAXSUN B860M", "bios": "AMI 1.10 (2025-08-01)",
        "os": "Windows 11 Pro", "build": "10.0.26100", "ram_total": 34359738368u64,
        "cpus": [{"name": "Intel Core Ultra 5 225F", "cores": 10, "threads": 10, "mhz": 3300}],
        "ram": [{"slot": "DIMM1", "size": 17179869184u64, "speed": 6000, "maker": "X", "part": "KF560"}],
        "gpus": [{"name": "NVIDIA \"RTX\" 5060", "driver": "32.0.15.7680", "w": 1920, "h": 1080, "hz": 165}],
        "drives": [], "nics": [{"name": "Realtek 5GbE", "mac": "AA", "speed": 5000000000u64, "up": true}],
        "monitors": [{"name": "=cmd", "maker": "AOC"}],
        "displays": [{"device": "\\\\.\\DISPLAY1", "w": 1920, "h": 1080, "hz": 165, "modes": [[1920, 1080, 165]]}],
        "at": 1793480000u64
    });
    let r = row("PC01", "aa:bb", "Lounge", Some(&v));
    let cols: Vec<&str> = CSV_HEADER.split(',').collect();
    assert_eq!(cols.len(), 16);
    assert!(
        r.starts_with("\"PC01\",\"aa:bb\",\"Lounge\",\"Micro-Star MS-7E06\",\"MAXSUN B860M\""),
        "{r}"
    );
    assert!(r.contains("\"Intel Core Ultra 5 225F (10C/10T)\""));
    assert!(r.contains("\"32 GB\""));
    assert!(r.contains("\"DIMM1 16 GB 6000 MT/s KF560\""));
    assert!(
        r.contains("NVIDIA \"\"RTX\"\" 5060 (driver 32.0.15.7680)"),
        "quotes doubled"
    );
    assert!(r.contains("\"Realtek 5GbE 5000 Mb/s\""));
    assert!(
        r.contains("\"AOC =cmd\""),
        "only a leading = is neutralised"
    );
    assert!(r.contains("\"1920x1080 @ 165 Hz\""));
    assert!(r.ends_with("\"1793480000\""));
    let empty = row("PC02", "cc:dd", "", None);
    assert_eq!(empty.matches(',').count(), 15);
    assert_eq!(field("=1+1"), "\"'=1+1\"");
}
