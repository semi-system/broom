// iscsid/scsi.rs — the SCSI commands of a disk (SPC/SBC subset that Linux sd, iPXE, UEFI and Windows use), read-only
// unless the session may write (the game update machine). Pure: a CDB in, what to answer out; the connection does the
// actual read / write.

/// 512-byte blocks, like the LIO fileio backstore the clients were set up with.
pub const BLOCK: u64 = 512;
/// Largest READ the Block Limits page allows (keeps one command within one negotiated burst).
pub const MAX_XFER_BLOCKS: u32 = 512;
/// Largest READ / WRITE served at all (1 MB): the port is open to the LAN, a READ(16) could otherwise ask for
/// gigabytes of buffer. Initiators that read the Block Limits page stay at MAX_XFER_BLOCKS anyway.
const MAX_READ_BLOCKS: u64 = 2048;

#[derive(Debug, PartialEq)]
pub enum Cmd {
    /// Good status, no data.
    Ok,
    /// Good status with this data.
    Data(Vec<u8>),
    /// Good status with `blocks` blocks read from block `lba`.
    Read { lba: u64, blocks: u32 },
    /// Good status once `blocks` blocks (the command's data) are written at block `lba`.
    Write { lba: u64, blocks: u32 },
    /// Good status once the writes so far are on disk (SYNCHRONIZE CACHE).
    Sync,
    /// CHECK CONDITION with fixed-format sense (key, ASC, ASCQ).
    Check(u8, u8, u8),
}

const ILLEGAL_REQUEST: u8 = 0x05;
const DATA_PROTECT: u8 = 0x07;

fn be(b: &[u8]) -> u64 {
    b.iter().fold(0, |a, &x| (a << 8) | x as u64)
}

/// Fixed-format sense data (18 bytes).
pub fn sense(key: u8, asc: u8, ascq: u8) -> Vec<u8> {
    let mut s = vec![0u8; 18];
    s[0] = 0x70;
    s[2] = key;
    s[7] = 10;
    s[12] = asc;
    s[13] = ascq;
    s
}

/// Answer a CDB for LUN 0 of `size` bytes. `id` (the target IQN) names the disk in INQUIRY.
pub fn handle(cdb: &[u8; 16], size: u64, id: &str, writable: bool) -> Cmd {
    let nblocks = size / BLOCK;
    let range = |lba: u64, blocks: u64, write: bool| match lba.checked_add(blocks) {
        _ if blocks > MAX_READ_BLOCKS => Cmd::Check(ILLEGAL_REQUEST, 0x24, 0x00), // invalid field in CDB
        Some(end) if end <= nblocks && write => Cmd::Write {
            lba,
            blocks: blocks as u32,
        },
        Some(end) if end <= nblocks => Cmd::Read {
            lba,
            blocks: blocks as u32,
        },
        _ => Cmd::Check(ILLEGAL_REQUEST, 0x21, 0x00), // LBA out of range
    };
    let read = |lba, blocks| range(lba, blocks, false);
    let write = |lba, blocks| range(lba, blocks, true);
    match cdb[0] {
        0x35 | 0x91 if writable => Cmd::Sync,
        0x00 | 0x1b | 0x1e | 0x35 | 0x91 | 0x2f | 0xaf => Cmd::Ok, // TUR, START STOP, PREVENT, SYNC CACHE, VERIFY
        0x03 => Cmd::Data(sense(0, 0, 0)),                         // REQUEST SENSE: nothing pending
        0x12 => inquiry(cdb, nblocks, id),
        0x25 => {
            // READ CAPACITY(10): last LBA (0xffffffff = use the 16-byte form) + block length.
            let last = nblocks.saturating_sub(1).min(0xffff_ffff) as u32;
            Cmd::Data([last.to_be_bytes(), (BLOCK as u32).to_be_bytes()].concat())
        }
        0x9e if cdb[1] & 0x1f == 0x10 => {
            let mut d = vec![0u8; 32];
            d[..8].copy_from_slice(&nblocks.saturating_sub(1).to_be_bytes());
            d[8..12].copy_from_slice(&(BLOCK as u32).to_be_bytes());
            Cmd::Data(d)
        }
        0x08 => {
            let blocks = match cdb[4] {
                0 => 256,
                n => n as u64,
            };
            read(be(&[cdb[1] & 0x1f, cdb[2], cdb[3]]), blocks)
        }
        // No protection information on this disk: RDPROTECT must be 0. DPO/FUA are fine (nothing to bypass).
        0x28 | 0xa8 | 0x88 if cdb[1] >> 5 != 0 => Cmd::Check(ILLEGAL_REQUEST, 0x24, 0x00),
        0x28 => read(be(&cdb[2..6]), be(&cdb[7..9])),
        0xa8 => read(be(&cdb[2..6]), be(&cdb[6..10])),
        0x88 => read(be(&cdb[2..10]), be(&cdb[10..14])),
        // Writes of any kind on a shared read-only disk: DATA PROTECT / WRITE PROTECTED.
        0x0a | 0x2a | 0xaa | 0x8a | 0x2e | 0x8e | 0x41 | 0x93 | 0x42 | 0x89 if !writable => {
            Cmd::Check(DATA_PROTECT, 0x27, 0x00)
        }
        // Same rule as reads for WRPROTECT.
        0x2a | 0xaa | 0x8a if cdb[1] >> 5 != 0 => Cmd::Check(ILLEGAL_REQUEST, 0x24, 0x00),
        0x0a => {
            let blocks = match cdb[4] {
                0 => 256,
                n => n as u64,
            };
            write(be(&[cdb[1] & 0x1f, cdb[2], cdb[3]]), blocks)
        }
        0x2a => write(be(&cdb[2..6]), be(&cdb[7..9])),
        0xaa => write(be(&cdb[2..6]), be(&cdb[6..10])),
        0x8a => write(be(&cdb[2..10]), be(&cdb[10..14])),
        // WRITE AND VERIFY, WRITE SAME, UNMAP, COMPARE AND WRITE: not needed (no thin provisioning advertised).
        0xa0 => {
            // REPORT LUNS: just LUN 0.
            let mut d = vec![0u8; 16];
            d[3] = 8;
            Cmd::Data(d)
        }
        0x1a | 0x5a => mode_sense(cdb, writable),
        _ => Cmd::Check(ILLEGAL_REQUEST, 0x20, 0x00), // invalid command operation code
    }
}

fn inquiry(cdb: &[u8; 16], nblocks: u64, id: &str) -> Cmd {
    let pad = |s: &str, n: usize| format!("{s:<n$}").into_bytes()[..n].to_vec();
    if cdb[1] & 1 == 0 {
        if cdb[2] != 0 {
            return Cmd::Check(ILLEGAL_REQUEST, 0x24, 0x00);
        }
        // Standard data: direct-access disk, SPC-4, command queuing; version descriptors SAM-5, iSCSI, SPC-4, SBC-3.
        let mut d = vec![0x00, 0x00, 0x06, 0x02, 69, 0, 0, 0x02];
        d.extend(pad("BROOM", 8));
        d.extend(pad("golden", 16));
        d.extend(pad("1.0", 4));
        d.resize(58, 0);
        for v in [0x00a0u16, 0x0960, 0x0460, 0x04c0] {
            d.extend(v.to_be_bytes());
        }
        d.resize(74, 0);
        return Cmd::Data(d);
    }
    let serial = blake3::hash(id.as_bytes()).to_hex()[..16].to_string();
    let page = |code: u8, body: Vec<u8>| {
        let mut d = vec![0x00, code];
        d.extend((body.len() as u16).to_be_bytes());
        d.extend(body);
        Cmd::Data(d)
    };
    match cdb[2] {
        0x00 => page(0x00, vec![0x00, 0x80, 0x83, 0xb0]),
        0x80 => page(0x80, serial.into_bytes()),
        0x83 => {
            // One T10 vendor-ID designator (ASCII): vendor + a stable id of the target.
            let des = [pad("BROOM", 8), serial.into_bytes()].concat();
            let mut b = vec![0x02, 0x01, 0x00, des.len() as u8];
            b.extend(des);
            page(0x83, b)
        }
        0xb0 => {
            // Block Limits: max / optimal transfer length.
            let mut b = vec![0u8; 0x3c];
            b[4..8].copy_from_slice(&MAX_XFER_BLOCKS.to_be_bytes());
            b[8..12].copy_from_slice(&(MAX_XFER_BLOCKS.min(nblocks.max(1) as u32)).to_be_bytes());
            page(0xb0, b)
        }
        _ => Cmd::Check(ILLEGAL_REQUEST, 0x24, 0x00),
    }
}

/// MODE SENSE(6)/(10), no block descriptors. Read-only: write-protected (WP + the control page's SWP), DPO/FUA
/// accepted, no write cache. Writable: a write cache (WCE) and no FUA, so durability comes as SYNCHRONIZE CACHE.
fn mode_sense(cdb: &[u8; 16], writable: bool) -> Cmd {
    let dsp = if writable { 0 } else { 0x80 | 0x10 };
    let caching = {
        let mut p = vec![0u8; 20];
        p[0] = 0x08;
        p[1] = 0x12;
        if writable {
            p[2] = 0x04; // WCE
        }
        p
    };
    let pages = match cdb[2] & 0x3f {
        0x08 | 0x3f => caching,
        0x0a => {
            let mut p = vec![0u8; 12];
            p[0] = 0x0a;
            p[1] = 0x0a;
            if !writable {
                p[4] = 0x08; // SWP
            }
            p
        }
        _ => return Cmd::Check(ILLEGAL_REQUEST, 0x24, 0x00),
    };
    let d = if cdb[0] == 0x1a {
        [vec![(3 + pages.len()) as u8, 0, dsp, 0], pages].concat()
    } else {
        let len = (6 + pages.len()) as u16;
        [len.to_be_bytes().to_vec(), vec![0, dsp, 0, 0, 0, 0], pages].concat()
    };
    Cmd::Data(d)
}

// ---------- CD-ROM (MMC): an installer ISO, read-only ----------
//
// Installer ISOs are served as a CD-ROM device so that UEFI (El Torito) boots them and Windows mounts them with its CD
// stack (cdrom.sys + UDF) after it logs in from the iBFT, exactly as a DVD drive: Windows Setup then finds its install
// image on it. The MMC subset Windows, UEFI and iPXE use for a read-only DVD-ROM with one data track; everything else is
// ILLEGAL REQUEST (drives without a feature answer the same).

/// 2048-byte sectors (DVD-ROM).
pub const CD_BLOCK: u64 = 2048;
/// DVD-ROM profile (GET CONFIGURATION).
const PROFILE_DVD_ROM: u16 = 0x0010;

/// Answer a CDB for a read-only DVD-ROM of `size` bytes holding one data track.
pub fn handle_cd(cdb: &[u8; 16], size: u64, id: &str) -> Cmd {
    let nblocks = size.div_ceil(CD_BLOCK);
    let read = |lba: u64, blocks: u64| match lba.checked_add(blocks) {
        _ if blocks > MAX_READ_BLOCKS * BLOCK / CD_BLOCK => Cmd::Check(ILLEGAL_REQUEST, 0x24, 0x00),
        Some(end) if end <= nblocks => Cmd::Read {
            lba,
            blocks: blocks as u32,
        },
        _ => Cmd::Check(ILLEGAL_REQUEST, 0x21, 0x00),
    };
    let alloc = |d: Vec<u8>, len: usize| Cmd::Data(d.into_iter().take(len).collect());
    match cdb[0] {
        // TUR, START STOP, PREVENT ALLOW, SET CD SPEED, MODE SELECT(6/10), SYNC CACHE: nothing to do.
        0x00 | 0x1b | 0x1e | 0xbb | 0x15 | 0x55 | 0x35 => Cmd::Ok,
        0x03 => Cmd::Data(sense(0, 0, 0)),
        0x12 if cdb[1] & 1 == 0 => {
            if cdb[2] != 0 {
                return Cmd::Check(ILLEGAL_REQUEST, 0x24, 0x00);
            }
            // Standard data: CD/DVD device, removable, SPC-3.
            let pad = |s: &str, n: usize| format!("{s:<n$}").into_bytes()[..n].to_vec();
            let mut d = vec![0x05, 0x80, 0x05, 0x02, 31, 0, 0, 0];
            d.extend(pad("BROOM", 8));
            d.extend(pad("ISO", 16));
            d.extend(pad("1.0", 4));
            alloc(d, be(&cdb[3..5]) as usize)
        }
        0x12 => match inquiry(cdb, nblocks, id) {
            // Same pages as a disk; the page header names a CD/DVD device.
            Cmd::Data(mut d) => {
                d[0] = 0x05;
                Cmd::Data(d)
            }
            c => c,
        },
        0x25 => {
            let last = nblocks.saturating_sub(1).min(0xffff_ffff) as u32;
            Cmd::Data([last.to_be_bytes(), (CD_BLOCK as u32).to_be_bytes()].concat())
        }
        0x28 | 0xa8 if cdb[1] >> 5 != 0 => Cmd::Check(ILLEGAL_REQUEST, 0x24, 0x00),
        0x28 => read(be(&cdb[2..6]), be(&cdb[7..9])),
        0xa8 => read(be(&cdb[2..6]), be(&cdb[6..10])),
        // READ CD: user data of data sectors only (what a DVD-ROM's sectors hold).
        0xbe if cdb[9] & 0xf8 == 0x10 && cdb[1] & 0x1c != 0x04 => {
            read(be(&cdb[2..6]), be(&cdb[6..9]))
        }
        0x43 => read_toc(cdb, nblocks),
        0x46 => get_configuration(cdb),
        0x4a => event_status(cdb),
        0x51 if cdb[1] & 0x07 == 0 => {
            // READ DISC INFORMATION: finalized disc, one complete session, track 1.
            let mut d = vec![0u8; 34];
            d[1] = 32;
            d[2] = 0x0e;
            d[3] = 1;
            d[4] = 1;
            d[5] = 1;
            d[6] = 1;
            d[7] = 0x20; // URU
            d[16..20].copy_from_slice(&[0xff; 4]); // last session lead-in: none
            d[20..24].copy_from_slice(&[0xff; 4]); // last possible lead-out: none
            alloc(d, be(&cdb[7..9]) as usize)
        }
        0xbd => alloc(vec![0u8; 8], be(&cdb[8..10]) as usize), // MECHANISM STATUS: idle, no changer
        0xad if cdb[7] == 0x01 => {
            // READ DVD STRUCTURE, copyright: no protection, all regions.
            alloc(vec![0, 6, 0, 0, 0, 0, 0, 0], be(&cdb[8..10]) as usize)
        }
        0x1a | 0x5a => cd_mode_sense(cdb),
        0xa0 => {
            let mut d = vec![0u8; 16];
            d[3] = 8;
            Cmd::Data(d)
        }
        // Any write: the disc is read-only.
        0x0a | 0x2a | 0xaa | 0x2e | 0x41 | 0x93 | 0x42 | 0x8a => {
            Cmd::Check(DATA_PROTECT, 0x27, 0x00)
        }
        _ => Cmd::Check(ILLEGAL_REQUEST, 0x20, 0x00),
    }
}

/// LBA → MSF bytes (minute, second, frame) with the 2-second lead-in, as READ TOC answers with MSF set.
fn msf(lba: u64) -> [u8; 4] {
    let f = lba + 150;
    [
        0,
        (f / 75 / 60).min(255) as u8,
        (f / 75 % 60) as u8,
        (f % 75) as u8,
    ]
}

/// READ TOC/PMA/ATIP: format 0 (TOC: track 1 + lead-out) and 1 (session info).
fn read_toc(cdb: &[u8; 16], nblocks: u64) -> Cmd {
    let use_msf = cdb[1] & 0x02 != 0;
    let addr = |lba: u64| {
        if use_msf {
            msf(lba)
        } else {
            (lba.min(0xffff_ffff) as u32).to_be_bytes()
        }
    };
    let format = match cdb[2] & 0x0f {
        0 if cdb[9] >> 6 != 0 => cdb[9] >> 6, // older drives' format field
        f => f,
    };
    let mut d = match format {
        0 => {
            if cdb[6] > 1 && cdb[6] != 0xaa {
                return Cmd::Check(ILLEGAL_REQUEST, 0x24, 0x00); // no such track
            }
            let mut d = vec![0, 0, 1, 1];
            if cdb[6] <= 1 {
                d.extend([0, 0x14, 1, 0]);
                d.extend(addr(0));
            }
            d.extend([0, 0x14, 0xaa, 0]);
            d.extend(addr(nblocks));
            d
        }
        1 => {
            let mut d = vec![0, 0, 1, 1, 0, 0x14, 1, 0];
            d.extend(addr(0));
            d
        }
        _ => return Cmd::Check(ILLEGAL_REQUEST, 0x24, 0x00),
    };
    let n = (d.len() - 2) as u16;
    d[..2].copy_from_slice(&n.to_be_bytes());
    Cmd::Data(d.into_iter().take(be(&cdb[7..9]) as usize).collect())
}

/// GET CONFIGURATION: a DVD-ROM with the features a reader has.
fn get_configuration(cdb: &[u8; 16]) -> Cmd {
    let rt = cdb[1] & 0x03;
    let start = be(&cdb[2..4]) as u16;
    let feature = |code: u16, flags: u8, body: Vec<u8>| {
        let mut f = code.to_be_bytes().to_vec();
        f.push(flags);
        f.push(body.len() as u8);
        f.extend(body);
        (code, f)
    };
    let mut random = (CD_BLOCK as u32).to_be_bytes().to_vec();
    random.extend([0, 1, 0, 0]);
    let all = [
        feature(
            0x0000,
            0x03,
            [PROFILE_DVD_ROM.to_be_bytes().to_vec(), vec![0x01, 0]].concat(),
        ),
        feature(0x0001, 0x0b, vec![0, 0, 0, 1, 0, 0, 0, 0]), // Core: SCSI interface
        feature(0x0002, 0x07, vec![0x02, 0, 0, 0]),          // Morphing: polled events
        feature(0x0003, 0x03, vec![0x29, 0, 0, 0]),          // Removable medium: tray, eject, lock
        feature(0x0010, 0x01, random),                       // Random readable: 2048-byte blocks
        feature(0x001f, 0x05, vec![0, 0, 0, 0]),             // DVD read
    ];
    let mut d = vec![0u8; 8];
    d[6..8].copy_from_slice(&PROFILE_DVD_ROM.to_be_bytes());
    for (code, f) in all {
        let take = match rt {
            2 => code == start,
            _ => code >= start,
        };
        if take {
            d.extend(f);
        }
    }
    let n = (d.len() - 4) as u32;
    d[..4].copy_from_slice(&n.to_be_bytes());
    Cmd::Data(d.into_iter().take(be(&cdb[7..9]) as usize).collect())
}

/// GET EVENT STATUS NOTIFICATION (polled only): media class — a disc is present, nothing changed.
fn event_status(cdb: &[u8; 16]) -> Cmd {
    if cdb[1] & 0x01 == 0 {
        return Cmd::Check(ILLEGAL_REQUEST, 0x24, 0x00); // asynchronous: not supported
    }
    let d = if cdb[4] & 0x10 != 0 {
        vec![0, 6, 0x04, 0x10, 0, 0x02, 0, 0]
    } else {
        vec![0, 2, 0x80, 0x10] // NEA: no class asked for that we have
    };
    Cmd::Data(d.into_iter().take(be(&cdb[7..9]) as usize).collect())
}

/// MODE SENSE for a DVD-ROM: the capabilities page (2Ah) only.
fn cd_mode_sense(cdb: &[u8; 16]) -> Cmd {
    let page = match cdb[2] & 0x3f {
        0x2a | 0x3f => {
            let mut p = vec![0u8; 22];
            p[0] = 0x2a;
            p[1] = 20;
            p[2] = 0x08 | 0x01; // reads DVD-ROM, CD-R
            p[6] = 0x29; // tray, eject, lock
            p
        }
        _ => return Cmd::Check(ILLEGAL_REQUEST, 0x24, 0x00),
    };
    let d = if cdb[0] == 0x1a {
        [vec![(3 + page.len()) as u8, 0, 0, 0], page].concat()
    } else {
        let len = (6 + page.len()) as u16;
        [len.to_be_bytes().to_vec(), vec![0, 0, 0, 0, 0, 0], page].concat()
    };
    let max = if cdb[0] == 0x1a {
        cdb[4] as usize
    } else {
        be(&cdb[7..9]) as usize
    };
    Cmd::Data(d.into_iter().take(max).collect())
}

#[cfg(test)]
#[path = "../../tests/unit/iscsid/scsi.rs"]
mod tests;
