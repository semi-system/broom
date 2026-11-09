use super::*;

fn cdb(b: &[u8]) -> [u8; 16] {
    let mut c = [0u8; 16];
    c[..b.len()].copy_from_slice(b);
    c
}
const SIZE: u64 = 1000 * 512 + 100; // a tail shorter than a block is not exposed (like LIO)

#[test]
fn capacity_and_reads() {
    assert_eq!(
        handle(&cdb(&[0x25]), SIZE, "t", false),
        Cmd::Data(vec![0, 0, 3, 231, 0, 0, 2, 0])
    );
    let Cmd::Data(d) = handle(&cdb(&[0x9e, 0x10]), SIZE, "t", false) else {
        panic!()
    };
    assert_eq!((be(&d[..8]), be(&d[8..12])), (999, 512));
    assert_eq!(
        handle(&cdb(&[0x28, 0, 0, 0, 0, 10, 0, 0, 4]), SIZE, "t", false),
        Cmd::Read { lba: 10, blocks: 4 }
    );
    assert_eq!(
        handle(
            &cdb(&[0x88, 0, 0, 0, 0, 0, 0, 0, 3, 0xe6, 0, 0, 0, 2]),
            SIZE,
            "t",
            false
        ),
        Cmd::Read {
            lba: 998,
            blocks: 2
        }
    );
    assert_eq!(
        handle(
            &cdb(&[0x88, 0, 0, 0, 0, 0, 0, 0, 3, 0xe7, 0, 0, 0, 2]),
            SIZE,
            "t",
            false
        ),
        Cmd::Check(5, 0x21, 0),
        "past the end"
    );
    assert_eq!(
        handle(&cdb(&[0x08, 0, 0, 5, 0]), SIZE, "t", false),
        Cmd::Read {
            lba: 5,
            blocks: 256
        },
        "READ(6): 0 = 256"
    );
    let big = 1u64 << 40;
    assert_eq!(
        handle(
            &cdb(&[0x88, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x08, 1]),
            big,
            "t",
            false
        ),
        Cmd::Check(5, 0x24, 0),
        "> 1 MB in one READ"
    );
    assert_eq!(
        handle(
            &cdb(&[
                0x88, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 1
            ]),
            SIZE,
            "t",
            false
        ),
        Cmd::Check(5, 0x21, 0),
        "no overflow"
    );
}

#[test]
fn read_only_and_unknown() {
    for w in [0x2a, 0x8a, 0x0a, 0x42, 0x93] {
        assert_eq!(
            handle(&cdb(&[w]), SIZE, "t", false),
            Cmd::Check(7, 0x27, 0),
            "write {w:#x}"
        );
    }
    assert_eq!(
        handle(&cdb(&[0xee]), SIZE, "t", false),
        Cmd::Check(5, 0x20, 0)
    );
    let Cmd::Data(m) = handle(&cdb(&[0x1a, 0, 0x3f, 0, 255]), SIZE, "t", false) else {
        panic!()
    };
    assert_eq!(
        (m[0] as usize + 1, m[2] & 0x80),
        (m.len(), 0x80),
        "length + write-protect bit"
    );
    let Cmd::Data(m) = handle(&cdb(&[0x5a, 0, 0x08]), SIZE, "t", false) else {
        panic!()
    };
    assert_eq!(
        (be(&m[..2]) as usize + 2, m[3] & 0x80, m[8]),
        (m.len(), 0x80, 0x08)
    );
    assert_eq!(
        handle(&cdb(&[0x28, 0x20, 0, 0, 0, 0, 0, 0, 1]), SIZE, "t", false),
        Cmd::Check(5, 0x24, 0),
        "RDPROTECT"
    );
    assert_eq!(
        handle(&cdb(&[0x28, 0x18, 0, 0, 0, 0, 0, 0, 1]), SIZE, "t", false),
        Cmd::Read { lba: 0, blocks: 1 },
        "DPO+FUA"
    );
}

#[test]
fn writable_session() {
    let h = |c: &[u8]| handle(&cdb(c), SIZE, "t", true);
    assert_eq!(
        h(&[0x2a, 0, 0, 0, 0, 10, 0, 0, 4]),
        Cmd::Write { lba: 10, blocks: 4 }
    );
    assert_eq!(
        h(&[0x8a, 0, 0, 0, 0, 0, 0, 0, 3, 0xe6, 0, 0, 0, 2]),
        Cmd::Write {
            lba: 998,
            blocks: 2
        }
    );
    assert_eq!(
        h(&[0x8a, 0, 0, 0, 0, 0, 0, 0, 3, 0xe7, 0, 0, 0, 2]),
        Cmd::Check(5, 0x21, 0),
        "past the end"
    );
    assert_eq!(
        h(&[0x2a, 0x20, 0, 0, 0, 0, 0, 0, 1]),
        Cmd::Check(5, 0x24, 0),
        "WRPROTECT"
    );
    assert_eq!(h(&[0x35]), Cmd::Sync);
    assert_eq!(h(&[0x42]), Cmd::Check(5, 0x20, 0), "UNMAP not offered");
    let Cmd::Data(m) = h(&[0x5a, 0, 0x08]) else {
        panic!()
    };
    assert_eq!(
        (m[3], m[8], m[10] & 0x04),
        (0, 0x08, 0x04),
        "no WP / FUA, write cache on"
    );
}

#[test]
fn inquiry_pages() {
    let Cmd::Data(d) = handle(&cdb(&[0x12, 0, 0, 0, 96]), SIZE, "t", false) else {
        panic!()
    };
    assert_eq!((d.len(), d[0], d[4] as usize + 5), (74, 0, 74));
    assert_eq!(
        be(&d[64..66]),
        0x04c0,
        "claims SBC-3 (its Block Limits page length)"
    );
    let Cmd::Data(p) = handle(&cdb(&[0x12, 1, 0x00]), SIZE, "t", false) else {
        panic!()
    };
    assert_eq!(&p[4..], &[0x00, 0x80, 0x83, 0xb0]);
    let Cmd::Data(a) = handle(&cdb(&[0x12, 1, 0x83]), SIZE, "iqn.a", false) else {
        panic!()
    };
    let Cmd::Data(b) = handle(&cdb(&[0x12, 1, 0x83]), SIZE, "iqn.b", false) else {
        panic!()
    };
    assert!(
        a != b && be(&a[2..4]) as usize + 4 == a.len(),
        "distinct id per target"
    );
    let Cmd::Data(l) = handle(&cdb(&[0x12, 1, 0xb0]), SIZE, "t", false) else {
        panic!()
    };
    assert_eq!(be(&l[8..12]), MAX_XFER_BLOCKS as u64);
    assert_eq!(
        handle(&cdb(&[0x12, 1, 0x99]), SIZE, "t", false),
        Cmd::Check(5, 0x24, 0)
    );
}

/// Any CDB (random, or real ones mangled: opcodes, LBAs, lengths at their edges) → an answer, never a panic; a read
/// or write never reaches past the disk or beyond the size served at once.
#[test]
fn fuzz_cdbs() {
    let seeds: Vec<Vec<u8>> = [
        &[0x28, 0, 0, 0, 0, 10, 0, 0, 4][..],
        &[0x88, 0, 0, 0, 0, 0, 0, 0, 3, 0xe6, 0, 0, 0, 2],
        &[0x2a, 0, 0, 0, 0, 20, 0, 0, 1],
        &[0x8a, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1],
        &[0x12, 1, 0xb0, 0, 64],
        &[0x9e, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32],
        &[0x1a, 0, 0x3f, 0, 64],
        &[0xa0, 0, 0, 0, 0, 0, 0, 0, 0, 16],
    ]
    .iter()
    .map(|c| cdb(c).to_vec())
    .collect();
    let nblocks = SIZE / BLOCK;
    crate::fuzz::run("scsi", crate::fuzz::inputs(&seeds, 50_000), |b| {
        let c = cdb(&b[..b.len().min(16)]);
        for writable in [false, true] {
            match handle(&c, SIZE, "t", writable) {
                Cmd::Read { lba, blocks } | Cmd::Write { lba, blocks } => {
                    assert!(
                        lba + blocks as u64 <= nblocks && blocks as u64 <= 2048,
                        "{lba}+{blocks}"
                    );
                }
                _ => {}
            }
        }
    });
}

/// An installer ISO as a DVD-ROM: CD/DVD device type, 2048-byte blocks, reads in those blocks, the table of contents
/// (track 1 + lead-out, LBA and MSF), session info, DVD-ROM profile, media present, read-only.
#[test]
fn iso_as_dvd_rom() {
    let size = 6_000_000 * 2048 + 10; // a last partial sector is still readable (rounded up)
    let h = |b: &[u8]| handle_cd(&cdb(b), size, "iqn.x:iso");
    let Cmd::Data(d) = h(&[0x12, 0, 0, 0, 96]) else {
        panic!()
    };
    assert_eq!(
        (d[0], d[1] & 0x80, &d[8..13]),
        (0x05, 0x80, &b"BROOM"[..]),
        "CD/DVD, removable"
    );
    assert_eq!(
        h(&[0x25]),
        Cmd::Data(vec![0, 0x5b, 0x8d, 0x80, 0, 0, 8, 0]),
        "last LBA 6000000, 2048"
    );
    assert_eq!(
        h(&[0x28, 0, 0, 0, 0, 16, 0, 0, 1]),
        Cmd::Read { lba: 16, blocks: 1 }
    );
    assert_eq!(
        h(&[0xa8, 0, 0, 0x5b, 0x8d, 0x80, 0, 0, 0, 1]),
        Cmd::Read {
            lba: 6_000_000,
            blocks: 1
        },
        "the rounded-up last sector"
    );
    assert_eq!(
        h(&[0x28, 0, 0, 0x5b, 0x8d, 0x81, 0, 0, 1]),
        Cmd::Check(0x05, 0x21, 0),
        "past the end"
    );
    assert_eq!(
        h(&[0x28, 0, 0, 0, 0, 0, 0, 0x02, 0x01]),
        Cmd::Check(0x05, 0x24, 0),
        "over 1 MB"
    );
    // TOC, LBA form: header, track 1 at 0, lead-out at the end.
    let Cmd::Data(t) = h(&[0x43, 0, 0, 0, 0, 0, 0, 0x03, 0x24]) else {
        panic!()
    };
    assert_eq!(&t[..4], &[0, 18, 1, 1]);
    assert_eq!(&t[4..12], &[0, 0x14, 1, 0, 0, 0, 0, 0]);
    assert_eq!(&t[12..20], &[0, 0x14, 0xaa, 0, 0, 0x5b, 0x8d, 0x81]);
    // MSF form: track 1 at 00:02:00.
    let Cmd::Data(t) = h(&[0x43, 0x02, 0, 0, 0, 0, 0, 0x03, 0x24]) else {
        panic!()
    };
    assert_eq!(&t[8..12], &[0, 0, 2, 0]);
    // Session info.
    let Cmd::Data(t) = h(&[0x43, 0, 1, 0, 0, 0, 0, 0, 12]) else {
        panic!()
    };
    assert_eq!(t, [0, 10, 1, 1, 0, 0x14, 1, 0, 0, 0, 0, 0]);
    // Allocation length cuts the answer.
    let Cmd::Data(t) = h(&[0x43, 0, 0, 0, 0, 0, 0, 0, 4]) else {
        panic!()
    };
    assert_eq!(t.len(), 4);
    // GET CONFIGURATION: current profile DVD-ROM; the profile list feature first.
    let Cmd::Data(c) = h(&[0x46, 0, 0, 0, 0, 0, 0, 0x01, 0]) else {
        panic!()
    };
    assert_eq!(be(&c[6..8]), 0x0010);
    assert_eq!(be(&c[..4]) as usize, c.len() - 4);
    assert_eq!(&c[8..10], &[0, 0], "profile list");
    // One feature only (RT=2).
    let Cmd::Data(c) = h(&[0x46, 2, 0, 0x10, 0, 0, 0, 0x01, 0]) else {
        panic!()
    };
    assert_eq!(
        (c.len(), &c[8..10]),
        (8 + 12, &[0u8, 0x10][..]),
        "random readable"
    );
    // Media event: present, no change. Asynchronous form refused.
    assert_eq!(
        h(&[0x4a, 1, 0, 0, 0x10, 0, 0, 0, 8]),
        Cmd::Data(vec![0, 6, 4, 0x10, 0, 2, 0, 0])
    );
    assert_eq!(
        h(&[0x4a, 0, 0, 0, 0x10, 0, 0, 0, 8]),
        Cmd::Check(0x05, 0x24, 0)
    );
    // Capabilities page; other pages refused.
    let Cmd::Data(m) = h(&[0x5a, 0, 0x2a, 0, 0, 0, 0, 0, 0xff]) else {
        panic!()
    };
    assert_eq!((m[8], m[9]), (0x2a, 20));
    assert_eq!(
        h(&[0x5a, 0, 0x08, 0, 0, 0, 0, 0, 0xff]),
        Cmd::Check(0x05, 0x24, 0)
    );
    // Read-only; no CSS.
    assert_eq!(
        h(&[0x2a, 0, 0, 0, 0, 0, 0, 0, 1]),
        Cmd::Check(0x07, 0x27, 0)
    );
    assert_eq!(
        h(&[0xad, 0, 0, 0, 0, 0, 0, 1, 0, 8]),
        Cmd::Data(vec![0, 6, 0, 0, 0, 0, 0, 0])
    );
    assert_eq!(h(&[0x00]), Cmd::Ok);
    assert_eq!(h(&[0x99]), Cmd::Check(0x05, 0x20, 0));
}

/// Random CDBs from the LAN never panic the DVD-ROM handler, and reads stay within the disc.
#[test]
fn fuzz_cd_cdbs() {
    let size = 3 * 2048 + 7;
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    for i in 0..200_000u32 {
        let mut c = [0u8; 16];
        for b in c.iter_mut() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *b = x as u8;
        }
        c[0] = [
            0x12, 0x25, 0x28, 0xa8, 0xbe, 0x43, 0x46, 0x4a, 0x51, 0x5a, 0x1a, 0xad, 0xbd,
        ][i as usize % 13];
        if let Cmd::Read { lba, blocks } = handle_cd(&c, size, "t") {
            assert!(lba + blocks as u64 <= 4, "{c:x?}");
        }
    }
}
