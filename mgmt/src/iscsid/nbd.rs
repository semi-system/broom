// iscsid/nbd.rs — the daemon's NBD server, for the VM of this server (vmmaint.rs): QEMU reads and writes a golden or a
// games disk through the very same layers an iSCSI session of the update machine would (games::View: the disk, the
// frozen versions above it, the update overlay), without the kernel's iSCSI initiator, `iscsiadm` or a block device.
// Transport: a Unix socket only root can open (SOCK, mode 0600). The export name is the target name of the iSCSI
// login — "<iqn>.g<k>" with the job's write key ".u<key>" for a writable session — and `attach` decides exactly as
// it does for iSCSI from 127.0.0.1: without the right key the session is read-only; a name that carries a key and
// does not get the update session is refused (the VM must not start on a disk it cannot write).
// Protocol: fixed newstyle handshake, NBD_OPT_EXPORT_NAME / NBD_OPT_GO / NBD_OPT_ABORT (any other option is answered
// "unsupported", which QEMU takes in its stride), simple replies; READ / WRITE (+ FUA) / FLUSH / TRIM (a no-op) /
// DISC. Requests are served concurrently, their memory bounded per connection.
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Semaphore, mpsc};

use super::Lun;
use super::games;
use super::overlay::{NO_ROOM, Overlay};

pub const SOCK: &str = "/run/broom-nbd.sock";

/// The address a session of this socket is attached for: this server itself (as an iSCSI login over the loopback).
const LOCAL: &str = "127.0.0.1";

const NBDMAGIC: &[u8; 8] = b"NBDMAGIC";
const IHAVEOPT: u64 = 0x4948_4156_454f_5054;
const REP_MAGIC: u64 = 0x0003_e889_0455_65a9;
const REQ_MAGIC: u32 = 0x2560_9513;
const REPLY_MAGIC: u32 = 0x6744_6698;

const FIXED_NEWSTYLE: u16 = 1;
const NO_ZEROES: u16 = 2;

const OPT_EXPORT_NAME: u32 = 1;
const OPT_ABORT: u32 = 2;
const OPT_GO: u32 = 7;

const REP_ACK: u32 = 1;
const REP_INFO: u32 = 3;
const REP_ERR_UNSUP: u32 = 0x8000_0001;
const REP_ERR_POLICY: u32 = 0x8000_0002;
const REP_ERR_UNKNOWN: u32 = 0x8000_0006;
const INFO_EXPORT: u16 = 0;

const FLAG_HAS_FLAGS: u16 = 1;
const FLAG_READ_ONLY: u16 = 2;
const FLAG_SEND_FLUSH: u16 = 4;
const FLAG_SEND_FUA: u16 = 8;

const CMD_READ: u16 = 0;
const CMD_WRITE: u16 = 1;
const CMD_DISC: u16 = 2;
const CMD_FLUSH: u16 = 3;
const CMD_TRIM: u16 = 4;
const CMD_FLAG_FUA: u16 = 1;

const EPERM: u32 = 1;
const EIO: u32 = 5;
const EINVAL: u32 = 22;
const ENOSPC: u32 = 28;

/// The longest request served (what NBD asks every server to take), and the memory a connection may have in flight
/// at once, in units of 64 KB: a request waits for its share.
const MAX_LEN: u32 = 32 << 20;
const UNIT: u32 = 64 << 10;
const BUDGET: usize = 512;
/// A client that does not finish the handshake in this time is dropped.
const HANDSHAKE_S: u64 = 15;

/// The transmission flags of an export: read-only, or writable with flush and FUA.
pub(crate) fn transmission_flags(writable: bool) -> u16 {
    if writable {
        FLAG_HAS_FLAGS | FLAG_SEND_FLUSH | FLAG_SEND_FUA
    } else {
        FLAG_HAS_FLAGS | FLAG_READ_ONLY
    }
}

/// An open export: the disk as a session sees it, and the session itself (detached when this goes).
struct Export {
    lun: Arc<Lun>,
    layers: Vec<Arc<Overlay>>,
    /// Its writes (the update session); None = read-only.
    ov: Option<Arc<Overlay>>,
    view: Option<games::View>,
}

impl Drop for Export {
    fn drop(&mut self) {
        if let Some(v) = &self.view {
            super::detach(v);
        }
        self.lun.sessions.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Export {
    /// The session `name` (a target name, with or without a write key). Blocking.
    fn open(name: &str) -> Result<Export, String> {
        let lun = super::lookup(name).ok_or("no such disk")?;
        let view = match super::attach(name, LOCAL) {
            None => None, // a plain target: read-only
            Some(v) => Some(v?),
        };
        let (layers, ov) = view
            .as_ref()
            .map_or((Vec::new(), None), |v| (v.layers.clone(), v.ov.clone()));
        lun.sessions.fetch_add(1, Ordering::Relaxed);
        let e = Export {
            lun,
            layers,
            ov,
            view,
        };
        // A name with the job's key is asked for writing: a read-only session would only fail at Windows' first write.
        if games::split_key(name).1.is_some() && e.ov.is_none() {
            return Err(
                "not writable: another session holds the update, or the key is not this job's"
                    .into(),
            );
        }
        Ok(e)
    }

    fn size(&self) -> u64 {
        self.lun.size
    }

    fn flags(&self) -> u16 {
        transmission_flags(self.ov.is_some())
    }

    fn read(&self, off: u64, len: usize) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; len];
        let below = |o: u64, b: &mut [u8]| games::read_chain(&self.layers, &self.lun, o, b);
        match &self.ov {
            // The update session reads what it wrote over the disk, as an iSCSI writer does (conn.rs).
            Some(ov) => ov.read_at(&below, off, &mut buf)?,
            None => below(off, &mut buf)?,
        }
        Ok(buf)
    }

    fn write(&self, off: u64, data: &[u8]) -> Result<(), String> {
        let ov = self.ov.as_ref().ok_or("read-only")?;
        ov.write_at(
            &|o, b| games::read_chain(&self.layers, &self.lun, o, b),
            off,
            data,
        )
    }

    fn flush(&self) -> Result<(), String> {
        match &self.ov {
            Some(ov) => ov.flush(),
            None => Ok(()),
        }
    }
}

/// Opens the export in a blocking thread.
async fn open(name: String) -> Result<Export, String> {
    tokio::task::spawn_blocking(move || Export::open(&name))
        .await
        .map_err(|e| e.to_string())?
}

async fn option_reply<S: AsyncWrite + Unpin>(
    s: &mut S,
    opt: u32,
    kind: u32,
    data: &[u8],
) -> std::io::Result<()> {
    let mut b = Vec::with_capacity(20 + data.len());
    b.extend(REP_MAGIC.to_be_bytes());
    b.extend(opt.to_be_bytes());
    b.extend(kind.to_be_bytes());
    b.extend((data.len() as u32).to_be_bytes());
    b.extend(data);
    s.write_all(&b).await
}

/// The export a client asks for in NBD_OPT_GO's data: u32 length, the name, u16 count, that many u16 requests.
pub(crate) fn go_name(data: &[u8]) -> Option<&str> {
    let n = u32::from_be_bytes(data.get(..4)?.try_into().ok()?) as usize;
    let name = data.get(4..4usize.checked_add(n)?)?;
    // The request list must be there whole.
    let rest = data.get(4 + n..)?;
    let count = u16::from_be_bytes(rest.get(..2)?.try_into().ok()?) as usize;
    (rest.len() == 2 + 2 * count).then_some(())?;
    std::str::from_utf8(name).ok().filter(|n| !n.is_empty())
}

/// The handshake: Some(export) once the client has chosen one, None when it left or asked for nothing we have.
async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
) -> std::io::Result<Option<Export>> {
    let mut hello = Vec::with_capacity(18);
    hello.extend(NBDMAGIC);
    hello.extend(IHAVEOPT.to_be_bytes());
    hello.extend((FIXED_NEWSTYLE | NO_ZEROES).to_be_bytes());
    s.write_all(&hello).await?;
    let flags = s.read_u32().await?;
    if flags & FIXED_NEWSTYLE as u32 == 0 {
        return Ok(None);
    }
    let no_zeroes = flags & NO_ZEROES as u32 != 0;
    loop {
        if s.read_u64().await? != IHAVEOPT {
            return Ok(None);
        }
        let opt = s.read_u32().await?;
        let len = s.read_u32().await? as usize;
        if len > 4096 {
            return Ok(None);
        }
        let mut data = vec![0u8; len];
        s.read_exact(&mut data).await?;
        match opt {
            OPT_EXPORT_NAME => {
                let name = String::from_utf8_lossy(&data).into_owned();
                return match open(name.clone()).await {
                    Ok(e) => {
                        let mut b = Vec::with_capacity(134);
                        b.extend(e.size().to_be_bytes());
                        b.extend(e.flags().to_be_bytes());
                        if !no_zeroes {
                            b.extend([0u8; 124]);
                        }
                        s.write_all(&b).await?;
                        Ok(Some(e))
                    }
                    Err(why) => {
                        tracing::info!("nbd: {}: {why}", games::split_key(&name).0);
                        Ok(None) // this option has no way to say why: the connection ends
                    }
                };
            }
            OPT_GO => {
                let Some(name) = go_name(&data) else {
                    option_reply(s, opt, REP_ERR_UNKNOWN, b"no such export").await?;
                    continue;
                };
                match open(name.to_string()).await {
                    Ok(e) => {
                        let mut info = Vec::with_capacity(12);
                        info.extend(INFO_EXPORT.to_be_bytes());
                        info.extend(e.size().to_be_bytes());
                        info.extend(e.flags().to_be_bytes());
                        option_reply(s, opt, REP_INFO, &info).await?;
                        option_reply(s, opt, REP_ACK, &[]).await?;
                        return Ok(Some(e));
                    }
                    Err(why) => {
                        tracing::info!("nbd: {}: {why}", games::split_key(name).0);
                        option_reply(s, opt, REP_ERR_POLICY, why.as_bytes()).await?;
                    }
                }
            }
            OPT_ABORT => {
                option_reply(s, opt, REP_ACK, &[]).await?;
                return Ok(None);
            }
            _ => option_reply(s, opt, REP_ERR_UNSUP, &[]).await?,
        }
    }
}

struct Reply {
    handle: u64,
    error: u32,
    data: Vec<u8>,
}

/// `request` bytes at `off` are inside a disk of `size`.
pub(crate) fn in_range(off: u64, len: u32, size: u64) -> bool {
    off.checked_add(len as u64).is_some_and(|end| end <= size)
}

/// Budget units (of 64 KB) a request of `len` bytes holds while it is served.
pub(crate) fn units(len: u32) -> u32 {
    len.div_ceil(UNIT).clamp(1, BUDGET as u32)
}

/// An error of the overlay as an errno: no room is "no space", anything else an I/O error.
pub(crate) fn errno_of(e: &str) -> u32 {
    if e.starts_with(NO_ROOM) { ENOSPC } else { EIO }
}

/// The request phase of a connection whose export is chosen.
async fn transmit<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(s: S, exp: Export) {
    let exp = Arc::new(exp);
    let (mut r, mut w) = tokio::io::split(s);
    let (tx, mut rx) = mpsc::channel::<Reply>(64);
    let writer = tokio::spawn(async move {
        while let Some(rep) = rx.recv().await {
            let mut h = [0u8; 16];
            h[..4].copy_from_slice(&REPLY_MAGIC.to_be_bytes());
            h[4..8].copy_from_slice(&rep.error.to_be_bytes());
            h[8..].copy_from_slice(&rep.handle.to_be_bytes());
            if w.write_all(&h).await.is_err() || w.write_all(&rep.data).await.is_err() {
                break;
            }
        }
    });
    let budget = Arc::new(Semaphore::new(BUDGET));
    let reject = |handle: u64, error: u32| {
        let tx = tx.clone();
        async move {
            let _ = tx
                .send(Reply {
                    handle,
                    error,
                    data: Vec::new(),
                })
                .await;
        }
    };
    let mut h = [0u8; 28];
    while r.read_exact(&mut h).await.is_ok() {
        if u32::from_be_bytes(h[..4].try_into().unwrap()) != REQ_MAGIC {
            break;
        }
        let flags = u16::from_be_bytes(h[4..6].try_into().unwrap());
        let kind = u16::from_be_bytes(h[6..8].try_into().unwrap());
        let handle = u64::from_be_bytes(h[8..16].try_into().unwrap());
        let off = u64::from_be_bytes(h[16..24].try_into().unwrap());
        let len = u32::from_be_bytes(h[24..28].try_into().unwrap());
        match kind {
            CMD_READ => {
                if len > MAX_LEN || !in_range(off, len, exp.size()) {
                    reject(handle, EINVAL).await;
                    continue;
                }
                let Ok(permit) = budget.clone().acquire_many_owned(units(len)).await else {
                    break;
                };
                let (e, tx) = (exp.clone(), tx.clone());
                tokio::spawn(async move {
                    let res = tokio::task::spawn_blocking(move || e.read(off, len as usize)).await;
                    let rep = match res {
                        Ok(Ok(data)) => Reply {
                            handle,
                            error: 0,
                            data,
                        },
                        other => {
                            if let Ok(Err(why)) = other {
                                tracing::warn!("nbd: read @{off}+{len}: {why}");
                            }
                            Reply {
                                handle,
                                error: EIO,
                                data: Vec::new(),
                            }
                        }
                    };
                    let _ = tx.send(rep).await;
                    drop(permit);
                });
            }
            CMD_WRITE => {
                // The data follows the header: it is read whatever the verdict, or the stream loses its framing.
                if len > MAX_LEN {
                    break;
                }
                let Ok(permit) = budget.clone().acquire_many_owned(units(len)).await else {
                    break;
                };
                let mut data = vec![0u8; len as usize];
                if r.read_exact(&mut data).await.is_err() {
                    break;
                }
                if exp.ov.is_none() {
                    reject(handle, EPERM).await;
                    continue;
                }
                if !in_range(off, len, exp.size()) {
                    reject(handle, ENOSPC).await;
                    continue;
                }
                let (e, tx) = (exp.clone(), tx.clone());
                tokio::spawn(async move {
                    let res = tokio::task::spawn_blocking(move || {
                        e.write(off, &data)?;
                        if flags & CMD_FLAG_FUA != 0 {
                            e.flush()?;
                        }
                        Ok::<(), String>(())
                    })
                    .await;
                    let error = match res {
                        Ok(Ok(())) => 0,
                        Ok(Err(why)) => {
                            tracing::warn!("nbd: write @{off}+{len}: {why}");
                            errno_of(&why)
                        }
                        Err(_) => EIO,
                    };
                    let _ = tx
                        .send(Reply {
                            handle,
                            error,
                            data: Vec::new(),
                        })
                        .await;
                    drop(permit);
                });
            }
            CMD_FLUSH => {
                let (e, tx) = (exp.clone(), tx.clone());
                tokio::spawn(async move {
                    let res = tokio::task::spawn_blocking(move || e.flush()).await;
                    let error = match res {
                        Ok(Ok(())) => 0,
                        _ => EIO,
                    };
                    let _ = tx
                        .send(Reply {
                            handle,
                            error,
                            data: Vec::new(),
                        })
                        .await;
                });
            }
            CMD_TRIM => reject(handle, 0).await, // nothing to give back: the overlay keeps what was written
            CMD_DISC => break,
            _ => reject(handle, EINVAL).await,
        }
    }
    drop(tx);
    let _ = writer.await;
}

/// One client of the socket, from its handshake to its disconnect.
pub async fn serve<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(mut s: S) {
    let exp = match tokio::time::timeout(Duration::from_secs(HANDSHAKE_S), handshake(&mut s)).await
    {
        Ok(Ok(Some(e))) => e,
        _ => return,
    };
    transmit(s, exp).await;
}

/// The socket: made fresh, for root only.
pub fn listen() -> std::io::Result<tokio::net::UnixListener> {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::remove_file(SOCK);
    let l = tokio::net::UnixListener::bind(SOCK)?;
    std::fs::set_permissions(SOCK, std::fs::Permissions::from_mode(0o600))?;
    Ok(l)
}

#[cfg(test)]
#[path = "../../tests/unit/iscsid/nbd.rs"]
mod tests;
