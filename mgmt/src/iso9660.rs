// iso9660.rs — read one file out of an ISO 9660 image (installer ISOs in the diskless ISO library), no mounting.
//
// Enough of ECMA-119 for installer media: the primary volume descriptor's root directory, directory records, and the
// Rock Ridge NM entry for the real file name. Names are compared without case and without the ";1" version / trailing
// '.' of plain ISO 9660 names, so "casper/vmlinuz" finds "CASPER/VMLINUZ.;1" as well as a Rock Ridge "vmlinuz".
use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;
use std::path::Path;

const SECTOR: u64 = 2048;
/// Directories larger than this are not installer media.
const MAX_DIR: u32 = 4 << 20;

/// A file's place in the image.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Extent {
    pub offset: u64,
    pub len: u64,
    pub dir: bool,
}

fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

fn read_at(f: &File, off: u64, len: usize) -> io::Result<Vec<u8>> {
    let mut v = vec![0u8; len];
    f.read_exact_at(&mut v, off)?;
    Ok(v)
}

/// The root directory of the primary volume descriptor.
fn root(f: &File) -> io::Result<Extent> {
    for i in 16..64u64 {
        let d = read_at(f, i * SECTOR, SECTOR as usize)?;
        if &d[1..6] != b"CD001" {
            break;
        }
        match d[0] {
            1 => return record(&d[156..190]).map(|(_, e)| e).ok_or_else(bad_iso),
            255 => break,
            _ => {}
        }
    }
    Err(bad_iso())
}

fn bad_iso() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "not an ISO 9660 image")
}

/// One directory record: (name as found — Rock Ridge NM if present, else the ISO name normalised), extent.
fn record(r: &[u8]) -> Option<(String, Extent)> {
    let len = *r.first()? as usize;
    if len < 34 || len > r.len() {
        return None;
    }
    let nlen = r[32] as usize;
    if 33 + nlen > len {
        return None;
    }
    let raw = &r[33..33 + nlen];
    let e = Extent {
        offset: le32(&r[2..6]) as u64 * SECTOR,
        len: le32(&r[10..14]) as u64,
        dir: r[25] & 2 != 0,
    };
    // System use area (Rock Ridge): after the name, padded to an even offset.
    let su = 33 + nlen + (1 - nlen % 2);
    let mut name = rock_ridge_name(r.get(su..len).unwrap_or(&[]));
    if name.is_none() {
        name = Some(match raw {
            [0] => ".".into(),
            [1] => "..".into(),
            _ => {
                let s = String::from_utf8_lossy(raw);
                let s = s.split(';').next().unwrap_or("");
                s.strip_suffix('.').unwrap_or(s).to_string()
            }
        });
    }
    Some((name?, e))
}

/// The NM entries of a system use area, joined (an NM may continue in the next one).
fn rock_ridge_name(mut su: &[u8]) -> Option<String> {
    let mut name = Vec::new();
    while su.len() >= 4 {
        let l = su[2] as usize;
        if l < 4 || l > su.len() {
            break;
        }
        if &su[..2] == b"NM" && l >= 5 {
            name.extend_from_slice(&su[5..l]);
        }
        su = &su[l..];
    }
    (!name.is_empty()).then(|| String::from_utf8_lossy(&name).into_owned())
}

/// The entries of a directory.
fn entries(f: &File, d: Extent) -> io::Result<Vec<(String, Extent)>> {
    if d.len > MAX_DIR as u64 {
        return Err(bad_iso());
    }
    let data = read_at(f, d.offset, d.len as usize)?;
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        let l = data[pos] as usize;
        if l == 0 {
            // Records never cross a sector: the rest of this one is padding.
            pos = (pos / SECTOR as usize + 1) * SECTOR as usize;
            continue;
        }
        if let Some((n, e)) = data.get(pos..pos + l).and_then(record)
            && n != "."
            && n != ".."
        {
            out.push((n, e));
        }
        pos += l;
    }
    Ok(out)
}

/// Where `path` ("casper/vmlinuz") is in the image; None if it is not there.
pub fn find(iso: &Path, path: &str) -> io::Result<Option<Extent>> {
    let f = File::open(iso)?;
    let mut cur = root(&f)?;
    for part in path.split('/').filter(|p| !p.is_empty()) {
        if !cur.dir {
            return Ok(None);
        }
        match entries(&f, cur)?
            .into_iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(part))
        {
            Some((_, e)) => cur = e,
            None => return Ok(None),
        }
    }
    Ok(Some(cur))
}

/// Copy `path` out of the image into `dst` (at most `max` bytes). Ok(false) = not in the image.
pub fn extract(iso: &Path, path: &str, dst: &Path, max: u64) -> io::Result<bool> {
    let Some(e) = find(iso, path)? else {
        return Ok(false);
    };
    if e.dir || e.len > max {
        return Ok(false);
    }
    let f = File::open(iso)?;
    let tmp = dst.with_extension("part");
    let out = File::create(&tmp)?;
    let mut off = 0u64;
    let mut buf = vec![0u8; 1 << 20];
    while off < e.len {
        let n = (e.len - off).min(buf.len() as u64) as usize;
        f.read_exact_at(&mut buf[..n], e.offset + off)?;
        out.write_all_at(&buf[..n], off)?;
        off += n as u64;
    }
    out.sync_all()?;
    std::fs::rename(&tmp, dst)?;
    Ok(true)
}

#[cfg(test)]
#[path = "../tests/unit/iso9660.rs"]
mod tests;
