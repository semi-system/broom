use super::*;

const S: usize = 2048;

fn tmp(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("broom_t_iso_{name}"));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A directory record: name bytes as stored, extent sector, length, directory?, Rock Ridge NM name.
fn rec(name: &[u8], sector: u32, len: u32, dir: bool, nm: Option<&str>) -> Vec<u8> {
    let mut r = vec![0u8; 33];
    r[2..6].copy_from_slice(&sector.to_le_bytes());
    r[6..10].copy_from_slice(&sector.to_be_bytes());
    r[10..14].copy_from_slice(&len.to_le_bytes());
    r[14..18].copy_from_slice(&len.to_be_bytes());
    r[25] = if dir { 2 } else { 0 };
    r[32] = name.len() as u8;
    r.extend_from_slice(name);
    if name.len().is_multiple_of(2) {
        r.push(0);
    }
    if let Some(n) = nm {
        r.extend_from_slice(b"NM");
        r.push(5 + n.len() as u8);
        r.extend_from_slice(&[1, 0]);
        r.extend_from_slice(n.as_bytes());
    }
    if r.len() % 2 == 1 {
        r.push(0);
    }
    r[0] = r.len() as u8;
    r
}

fn put(img: &mut [u8], sector: usize, data: &[u8]) {
    img[sector * S..sector * S + data.len()].copy_from_slice(data);
}

/// An image: root (2 sectors, the second record in the second sector) → CASPER/ (VMLINUZ.;1 plain, INITRD.;1 with
/// Rock Ridge "initrd"), README.TXT;1.
fn image(dir: &std::path::Path) -> (std::path::PathBuf, Vec<u8>, Vec<u8>) {
    let kernel: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
    let initrd: Vec<u8> = (0..3000u32).map(|i| (i % 13) as u8 + 1).collect();
    let mut img = vec![0u8; 40 * S];
    let mut pvd = vec![0u8; S];
    pvd[0] = 1;
    pvd[1..6].copy_from_slice(b"CD001");
    pvd[6] = 1;
    let root = rec(&[0], 20, 2 * S as u32, true, None);
    pvd[156..156 + root.len()].copy_from_slice(&root);
    put(&mut img, 16, &pvd);
    let mut term = vec![0u8; 7];
    term[0] = 255;
    term[1..6].copy_from_slice(b"CD001");
    put(&mut img, 17, &term);
    // Root: ".", "..", CASPER in the first sector; README in the second (the first one padded with zeros).
    let mut r1 = rec(&[0], 20, 2 * S as u32, true, None);
    r1.extend(rec(&[1], 20, 2 * S as u32, true, None));
    r1.extend(rec(b"CASPER", 22, S as u32, true, None));
    put(&mut img, 20, &r1);
    put(&mut img, 21, &rec(b"README.TXT;1", 30, 3, false, None));
    let mut c = rec(&[0], 22, S as u32, true, None);
    c.extend(rec(&[1], 20, 2 * S as u32, true, None));
    c.extend(rec(b"VMLINUZ.;1", 24, kernel.len() as u32, false, None));
    c.extend(rec(
        b"INITRD.;1",
        28,
        initrd.len() as u32,
        false,
        Some("initrd"),
    ));
    put(&mut img, 22, &c);
    put(&mut img, 24, &kernel);
    put(&mut img, 28, &initrd);
    put(&mut img, 30, b"hi\n");
    let p = dir.join("t.iso");
    std::fs::write(&p, &img).unwrap();
    (p, kernel, initrd)
}

#[test]
fn finds_and_extracts_files() {
    let d = tmp("find");
    let (iso, kernel, initrd) = image(&d);
    let k = find(&iso, "casper/vmlinuz").unwrap().unwrap();
    assert_eq!((k.offset, k.len, k.dir), (24 * S as u64, 5000, false));
    assert!(find(&iso, "CASPER").unwrap().unwrap().dir);
    assert!(
        find(&iso, "readme.txt").unwrap().is_some(),
        "record after the sector padding"
    );
    assert!(find(&iso, "casper/nope").unwrap().is_none());
    assert!(
        find(&iso, "readme.txt/x").unwrap().is_none(),
        "a file is not a directory"
    );

    let out = d.join("vmlinuz");
    assert!(extract(&iso, "casper/vmlinuz", &out, 1 << 20).unwrap());
    assert_eq!(std::fs::read(&out).unwrap(), kernel);
    let out = d.join("initrd");
    assert!(
        extract(&iso, "/casper/initrd/", &out, 1 << 20).unwrap(),
        "Rock Ridge name"
    );
    assert_eq!(std::fs::read(&out).unwrap(), initrd);
    assert!(
        !extract(&iso, "casper/vmlinuz", &d.join("x"), 100).unwrap(),
        "over max"
    );
    assert!(!extract(&iso, "casper/missing", &d.join("y"), 1 << 20).unwrap());
    assert!(!d.join("x").exists() && !d.join("x.part").exists());
}

#[test]
fn not_an_iso() {
    let d = tmp("not");
    let p = d.join("zero.iso");
    std::fs::write(&p, vec![0u8; 40 * S]).unwrap();
    assert!(find(&p, "casper/vmlinuz").is_err());
    let short = d.join("short.iso");
    std::fs::write(&short, b"tiny").unwrap();
    assert!(find(&short, "x").is_err());
}

#[test]
fn hostile_records_do_not_panic() {
    // Garbage records: lengths past the end, names longer than the record, NM with bad lengths.
    for seed in 0..200u32 {
        let mut r: Vec<u8> = (0..80u32)
            .map(|i| ((i * 31 + seed * 17) % 256) as u8)
            .collect();
        r[0] = (seed % 90) as u8;
        let _ = record(&r);
        let _ = rock_ridge_name(&r);
    }
}
