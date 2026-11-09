// vmmaint.rs — "Maintain in the browser" (Diskless page): a Windows golden in a virtual machine on this server, with
// games disks attached, its screen in the browser (noVNC, static/novnc/ + static/vm-console.js) and internet through
// QEMU's NAT — Windows / app updates and games updates without taking a PC out of the room.
// - The VM writes the golden's maintenance layer the way a maintenance machine does: while the VM holds the golden
//   the daemon lets 127.0.0.1 write it (diskless.rs configs); this server logs in over iSCSI and hands QEMU the disk.
//   An owner can keep the Windows changes for Save / Discard (Goldens table); otherwise they are discarded when the VM
//   stops, so staff update games but never change the golden.
// - Each games disk picked: its update session, the same way (games.rs configs): Save / Discard it afterwards as for
//   an update machine. Windows finds it by its disk serial (broom-diskless.ps1, maintenance role → broom-games.ps1
//   -Lines), formats it if new and mounts its games.vhdx under its letter.
// - QEMU runs in its own systemd unit (broom-vm-<golden>): restarting Broom (an update) leaves the VM running and the
//   next start takes it over. Its screen: QEMU's VNC on a Unix socket only root can open, reached through Broom's
//   signed-in WebSocket /api/vm/console. Shut down = the ACPI power button; Turn off = pulling the plug.
// One VM at a time.
// Why: in a lounge every PC is in use during opening hours, and updating the golden or a games disk from a real PC
// means taking one out of the room. A VM on the server does the same work (games launchers, Windows / app updates)
// with nothing but a browser, and staff can be allowed to update games without being able to change Windows (the
// golden's changes are kept only when an owner ticks it). Some commercial diskless systems also let an image be edited
// in a VM on the server; this one reuses Broom's own pieces (iSCSI engine, the golden's startup script, noVNC).
use axum::{
    Json, Router,
    extract::{
        Path as UrlPath, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use crate::SharedState;
use crate::api::{ApiError, bad, ise};
use crate::auth::{Role, Who};

pub fn routes() -> Router<SharedState> {
    Router::new()
        .route("/api/vm", get(status))
        .route("/api/vm/start", post(start))
        .route("/api/vm/stop", post(stop))
        .route("/api/vm/console", get(console))
        .route("/vm-console", get(page))
        .route("/vm-console.js", get(page_js))
        .route("/novnc/{*path}", get(novnc))
}

/// The session (config): the one running now, or the last one (its outcome stays shown).
const KEY: &str = "vm_session";
/// The VM's size: half of an 8-thread server, enough RAM for Windows Update + a game installer.
const CPUS: u32 = 4;
const MEM_MB: u32 = 8192;
/// Games disks attached at most (AHCI ports 1-5; port 0 is the golden).
const MAX_GAMES: usize = 5;

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub(crate) struct GamesDisk {
    pub name: String,
    pub letter: String,
    /// The disk serial QEMU gives it (Windows finds the disk by it).
    pub serial: String,
    /// Its update target (newest version), logged in on this server.
    pub target: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub(crate) struct Session {
    pub golden: String,
    /// The golden's update target (newest version), logged in on this server.
    pub golden_target: String,
    #[serde(default)]
    pub games: Vec<GamesDisk>,
    /// Keep the Windows changes for the owner's Save (else discarded when the VM stops).
    pub keep: bool,
    pub by: String,
    pub started: u64,
    /// starting | running | stopping | stopped | failed
    pub state: String,
    #[serde(default)]
    pub msg: String,
    #[serde(default)]
    pub ended: u64,
    /// QEMU's process when there is no systemd (else its unit).
    #[serde(default)]
    pub pid: Option<u32>,
}

impl Session {
    /// QEMU may be running (or the disks still attached).
    pub(crate) fn active(&self) -> bool {
        matches!(self.state.as_str(), "starting" | "running" | "stopping")
    }
}

/// What the VM holds right now: its golden and games disks (diskless.rs / games.rs let 127.0.0.1 write them).
#[derive(Clone, Debug, Default)]
struct Owns {
    golden: String,
    games: Vec<String>,
}
static OWNS: parking_lot::Mutex<Option<Owns>> = parking_lot::Mutex::new(None);
/// Start / finish one at a time.
static LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

pub(crate) fn owns_golden(name: &str) -> bool {
    OWNS.lock().as_ref().is_some_and(|o| o.golden == name)
}

pub(crate) fn owns_games(name: &str) -> bool {
    OWNS.lock()
        .as_ref()
        .is_some_and(|o| o.games.iter().any(|g| g == name))
}

pub(crate) fn current(st: &SharedState) -> Option<Session> {
    serde_json::from_str(&st.db.get_config(KEY, "")).ok()
}

fn put(st: &SharedState, s: &Session) {
    if let Err(e) = st
        .db
        .set_config(KEY, &serde_json::to_string(s).unwrap_or_default())
    {
        tracing::warn!("vm: state not kept: {e}");
    }
}

fn unit(golden: &str) -> String {
    format!("broom-vm-{golden}")
}

/// <writeback>/.vm/<golden>: its UEFI variables (kept: boot entries Windows writes), sockets, QEMU's log.
fn work_dir(st: &SharedState, golden: &str) -> Result<PathBuf, String> {
    let d = crate::diskless::dir_of(st, "writeback")?
        .join(".vm")
        .join(golden);
    std::fs::create_dir_all(&d).map_err(|e| format!("{}: {e}", d.display()))?;
    Ok(d)
}

/// A fixed MAC per golden (Windows keeps one network adapter for the VM, not a new one each time).
pub(crate) fn mac_of(golden: &str) -> String {
    let h = blake3::hash(golden.as_bytes());
    let b = h.as_bytes();
    format!("52:54:00:{:02x}:{:02x}:{:02x}", b[0], b[1], b[2])
}

/// QEMU's arguments: q35 + UEFI, the golden on AHCI port 0 (Windows has storahci at boot, as in onboard.rs), each games
/// disk on the next port with its serial, an e1000e (Windows has its driver) on QEMU's NAT, a USB tablet (the
/// mouse follows the browser's pointer), standard VGA, the screen on a VNC Unix socket, QMP for the power button.
pub(crate) fn qemu_args(
    golden: &str,
    disk: &str,
    games: &[(String, String)],
    (code, vars): (&str, &str),
    (qmp, vnc): (&str, &str),
) -> Vec<String> {
    let mut a: Vec<String> = [
        "-name",
        &format!("{},process={}", unit(golden), unit(golden)),
        "-machine",
        "q35,accel=kvm",
        // The server's own CPU model + the Hyper-V enlightenments Windows uses as a guest (cheaper timers and
        // interrupts than an emulated CPU), so updates and launchers run at a usable speed.
        "-cpu",
        "host,hv_relaxed,hv_vapic,hv_spinlocks=0x1fff,hv_time",
        "-smp",
        &CPUS.to_string(),
        "-m",
        &MEM_MB.to_string(),
        // Windows keeps the hardware clock in local time; a UTC clock would make it start hours off until it syncs.
        "-rtc",
        "base=localtime",
        "-drive",
        &format!("if=pflash,format=raw,readonly=on,file={code}"),
        "-drive",
        &format!("if=pflash,format=raw,file={vars}"),
        // AHCI, not virtio: the golden has Windows' inbox storahci as a boot driver, no virtio driver (the same disk
        // boots real PCs over iSCSI); it stays the golden the PCs boot, with nothing VM-specific installed into it.
        "-device",
        "ahci,id=sata",
        "-drive",
        &format!("file={disk},format=raw,if=none,id=d0,cache=none,aio=threads"),
        "-device",
        "ide-hd,drive=d0,bus=sata.0,bootindex=1",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    for (i, (dev, serial)) in games.iter().enumerate() {
        a.extend([
            "-drive".into(),
            format!("file={dev},format=raw,if=none,id=g{i},cache=none,aio=threads"),
            "-device".into(),
            format!("ide-hd,drive=g{i},bus=sata.{},serial={serial}", i + 1),
        ]);
    }
    a.extend(
        [
            // QEMU's own NAT: internet for updates without a bridge on the server's LANs, and nothing on the lounge
            // network can reach the VM. e1000e: a card Windows has an inbox driver for.
            "-netdev",
            "user,id=n0",
            "-device",
            &format!("e1000e,netdev=n0,mac={}", mac_of(golden)),
            "-device",
            "qemu-xhci,id=usb",
            // A tablet reports absolute positions, so the mouse in the VM follows the browser's pointer exactly.
            "-device",
            "usb-tablet,bus=usb.0",
            "-vga",
            "std",
            "-audio",
            "none",
            "-display",
            "none",
            // VNC on a Unix socket only (no TCP port): the only way in is Broom's signed-in WebSocket.
            "-vnc",
            &format!("unix:{vnc}"),
            "-qmp",
            &format!("unix:{qmp},server=on,wait=off"),
        ]
        .iter()
        .map(|s| s.to_string()),
    );
    a
}

fn systemd() -> bool {
    Path::new("/run/systemd/system").is_dir()
}

/// QEMU of this session still running.
fn alive(s: &Session) -> bool {
    if systemd() && s.pid.is_none() {
        let o = Command::new("systemctl")
            .args(["show", "-p", "ActiveState", "--value", &unit(&s.golden)])
            .output();
        let v = o
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default();
        return matches!(
            v.as_str(),
            "active" | "activating" | "deactivating" | "reloading"
        );
    }
    s.pid.is_some_and(|p| {
        std::fs::read(format!("/proc/{p}/cmdline"))
            .is_ok_and(|c| String::from_utf8_lossy(&c).contains(&unit(&s.golden)))
    })
}

/// Start QEMU outside bootrom-mgmt.service (whose restart kills its cgroup): its own unit, or its own session.
/// → Some(pid) without systemd.
fn launch(golden: &str, args: &[String], log: &Path) -> Result<Option<u32>, String> {
    let qemu = crate::onboard::which("qemu-system-x86_64").ok_or("no qemu-system-x86_64")?;
    if systemd() {
        let u = unit(golden);
        let _ = Command::new("systemctl")
            .args(["reset-failed", &u])
            .output();
        let o = Command::new("systemd-run")
            .args([
                &format!("--unit={u}"),
                "--collect",
                // mixed: stopping the unit sends SIGTERM to QEMU only (it exits and closes its disks — for Windows
                // that is pulling the plug, which is why Shut down uses the ACPI button over QMP instead), SIGKILL to
                // whatever is left after the timeout.
                "-p",
                "KillMode=mixed",
                "-p",
                "TimeoutStopSec=10",
                "-p",
                &format!("StandardOutput=append:{}", log.display()),
                "-p",
                &format!("StandardError=append:{}", log.display()),
            ])
            .arg(&qemu)
            .args(args)
            .output()
            .map_err(|e| format!("systemd-run: {e}"))?;
        if !o.status.success() {
            return Err(format!(
                "systemd-run {u}: {}",
                String::from_utf8_lossy(&o.stderr).trim()
            ));
        }
        return Ok(None);
    }
    use std::os::unix::process::CommandExt;
    let f = std::fs::File::create(log).map_err(|e| e.to_string())?;
    let mut c = Command::new(&qemu);
    c.args(args)
        .stdin(std::process::Stdio::null())
        .stdout(f.try_clone().map_err(|e| e.to_string())?)
        .stderr(f);
    // SAFETY: setsid is async-signal-safe and touches no memory of the parent.
    unsafe {
        c.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    let child = c.spawn().map_err(|e| format!("qemu: {e}"))?;
    Ok(Some(child.id()))
}

/// One QMP command → its "return" (events skipped).
fn qmp(sock: &Path, cmd: &serde_json::Value) -> Result<serde_json::Value, String> {
    let s = std::os::unix::net::UnixStream::connect(sock).map_err(|e| format!("QMP: {e}"))?;
    s.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let mut w = s.try_clone().map_err(|e| e.to_string())?;
    let mut r = BufReader::new(s);
    let mut line = String::new();
    let mut next =
        |r: &mut BufReader<std::os::unix::net::UnixStream>| -> Result<serde_json::Value, String> {
            loop {
                line.clear();
                if r.read_line(&mut line).map_err(|e| format!("QMP: {e}"))? == 0 {
                    return Err("QMP: closed".into());
                }
                let v: serde_json::Value =
                    serde_json::from_str(&line).map_err(|e| format!("QMP: {e}"))?;
                if v.get("event").is_none() {
                    return Ok(v);
                }
            }
        };
    next(&mut r)?; // greeting
    for c in [
        serde_json::json!({"execute": "qmp_capabilities"}),
        cmd.clone(),
    ] {
        writeln!(w, "{c}").map_err(|e| format!("QMP: {e}"))?;
        let v = next(&mut r)?;
        if let Some(e) = v.get("error") {
            return Err(format!("QMP: {}", e["desc"].as_str().unwrap_or("error")));
        }
        if c == *cmd {
            return Ok(v["return"].clone());
        }
    }
    Err("QMP: no answer".into())
}

/// The games disk's target name (games.rs serves it as `<base>:games-<name>`).
fn games_iqn(st: &SharedState, name: &str) -> String {
    format!(
        "{}:games-{name}",
        st.db.get_config("iqn_base", "iqn.2026-01.local.broom")
    )
}

/// A step that may meet the daemon still counting a client that just left: tried again for up to ~20 s.
fn retry_connected<T>(f: &dyn Fn() -> Result<T, String>) -> Result<T, String> {
    for _ in 0..40 {
        match f() {
            Err(e) if e.contains("still connected") => {
                std::thread::sleep(Duration::from_millis(500))
            }
            r => return r,
        }
    }
    f()
}

/// What the VM asks for: checked, its targets named. Blocking (daemon status).
fn plan(
    st: &SharedState,
    golden: &str,
    games: &[String],
    keep: bool,
    by: &str,
) -> Result<Session, String> {
    let g = crate::diskless::goldens(st)
        .into_iter()
        .find(|x| x.name == golden)
        .ok_or_else(|| format!("golden {golden} not found"))?;
    if g.os != "windows" {
        return Err("only a Windows golden runs in the VM".into());
    }
    if g.maint.is_some() {
        return Err(format!(
            "{golden} has a maintenance machine — turn maintenance off (Save or Discard its work) first"
        ));
    }
    if crate::onboard::busy(st, golden) || crate::onboard::vm_owns(golden) {
        return Err(format!(
            "Add hardware is using {golden} — wait for it to finish"
        ));
    }
    let info = crate::diskless::served(golden)
        .ok_or_else(|| format!("{golden} is not served (see the Diskless page)"))?;
    if info.disk.update_connected {
        return Err(format!(
            "{golden}'s maintenance machine is connected — shut it down first"
        ));
    }
    if !keep && info.disk.update_bytes > 0 {
        return Err(format!(
            "{golden} has unsaved maintenance work — Save or Discard it first (Goldens)"
        ));
    }
    if games.len() > MAX_GAMES {
        return Err(format!("at most {MAX_GAMES} games disks"));
    }
    let disks = crate::games::disks(st);
    let status = crate::iscsi::games_status().unwrap_or_default();
    let mut list = Vec::new();
    for (i, name) in games.iter().enumerate() {
        let d = disks
            .iter()
            .find(|d| d.name == *name)
            .ok_or_else(|| format!("games disk {name} not found"))?;
        let s = status
            .iter()
            .find(|x| x.name == *name)
            .ok_or_else(|| format!("games disk {name} is not served (Games page)"))?;
        if s.update_connected {
            return Err(format!(
                "games disk {name}: its update machine is connected — shut it down first"
            ));
        }
        list.push(GamesDisk {
            name: name.clone(),
            letter: d.letter.clone(),
            serial: format!("BROOMG{}", i + 1),
            target: format!("{}.g{}", games_iqn(st, name), s.ver),
        });
    }
    Ok(Session {
        golden: golden.to_string(),
        golden_target: format!("{}.g{}", crate::diskless::iqn(st, golden), info.disk.ver),
        games: list,
        keep,
        by: by.to_string(),
        started: crate::now_secs(),
        state: "starting".into(),
        msg: "attaching the disks".into(),
        ended: 0,
        pid: None,
    })
}

/// Start the VM. Blocking (iSCSI logins, QEMU start).
pub(crate) fn begin(
    st: &SharedState,
    golden: &str,
    games: &[String],
    keep: bool,
    by: &str,
) -> Result<Session, String> {
    let _l = LOCK.lock();
    if let Some(s) = current(st).filter(Session::active) {
        return Err(format!(
            "the VM of {} is running (one at a time) — shut it down first",
            s.golden
        ));
    }
    crate::onboard::preflight()?;
    let mut s = plan(st, golden, games, keep, by)?;
    put(st, &s);
    *OWNS.lock() = Some(Owns {
        golden: s.golden.clone(),
        games: s.games.iter().map(|g| g.name.clone()).collect(),
    });
    let r = (|| -> Result<Option<u32>, String> {
        crate::diskless::sync(st)?;
        if !s.games.is_empty() {
            crate::games::sync(st)?;
        }
        let disk = crate::onboard::login(&s.golden_target)?;
        let mut gdev = Vec::new();
        for g in &s.games {
            gdev.push((
                crate::onboard::login(&g.target)?
                    .to_string_lossy()
                    .to_string(),
                g.serial.clone(),
            ));
        }
        // Writable, or Windows would fail on its first write: the daemon must have taken this server as the writer.
        if !crate::diskless::served(&s.golden).is_some_and(|i| i.disk.update_connected) {
            return Err(format!("{}: the server did not get it writable", s.golden));
        }
        let st_games = crate::iscsi::games_status().unwrap_or_default();
        for g in &s.games {
            if !st_games
                .iter()
                .any(|x| x.name == g.name && x.update_connected)
            {
                return Err(format!(
                    "games disk {}: the server did not get it writable",
                    g.name
                ));
            }
        }
        let work = work_dir(st, &s.golden)?;
        let (code, vars_t) = crate::onboard::ovmf().ok_or("no OVMF")?;
        let vars = work.join("vars.fd");
        if !vars.exists() {
            std::fs::copy(&vars_t, &vars).map_err(|e| format!("OVMF vars: {e}"))?;
        }
        let (qmp_s, vnc_s) = (work.join("qmp.sock"), work.join("vnc.sock"));
        let _ = std::fs::remove_file(&qmp_s);
        let _ = std::fs::remove_file(&vnc_s);
        let args = qemu_args(
            &s.golden,
            &disk.to_string_lossy(),
            &gdev,
            (&code.to_string_lossy(), &vars.to_string_lossy()),
            (&qmp_s.to_string_lossy(), &vnc_s.to_string_lossy()),
        );
        let pid = launch(&s.golden, &args, &work.join("qemu.log"))?;
        let t0 = Instant::now();
        while !vnc_s.exists() {
            if t0.elapsed() > Duration::from_secs(20) {
                let tail = std::fs::read_to_string(work.join("qemu.log")).unwrap_or_default();
                return Err(format!(
                    "QEMU did not start: {}",
                    tail.trim().lines().last().unwrap_or("see qemu.log")
                ));
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        Ok(pid)
    })();
    match r {
        Ok(pid) => {
            s.pid = pid;
            s.state = "running".into();
            s.msg = "running".into();
            put(st, &s);
            tracing::warn!(
                "vm: {} started by {} (games disks: {}; Windows changes {})",
                s.golden,
                s.by,
                if s.games.is_empty() {
                    "none".to_string()
                } else {
                    s.games
                        .iter()
                        .map(|g| g.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                },
                if s.keep {
                    "kept"
                } else {
                    "discarded at the end"
                }
            );
            watch(st.clone());
            Ok(s)
        }
        Err(e) => {
            s.state = "stopping".into();
            put(st, &s);
            stop_qemu(&s);
            drop(_l);
            finish(st, Some(format!("not started: {e}")));
            Err(e)
        }
    }
}

/// Pull the plug (QEMU killed).
fn stop_qemu(s: &Session) {
    if let Some(p) = s.pid {
        // SAFETY: kill(2) on QEMU's own pid (checked by its command line in alive()).
        if alive(s) {
            unsafe { libc::kill(p as i32, libc::SIGTERM) };
        }
    } else if systemd() {
        let _ = Command::new("systemctl")
            .args(["stop", &unit(&s.golden)])
            .output();
    }
}

/// The VM is gone: disks handed back, the golden's changes discarded unless kept, outcome recorded. Blocking.
fn finish(st: &SharedState, why: Option<String>) {
    let _l = LOCK.lock();
    let Some(mut s) = current(st).filter(Session::active) else {
        *OWNS.lock() = None;
        return;
    };
    for g in &s.games {
        crate::onboard::logout(&g.target);
    }
    crate::onboard::logout(&s.golden_target);
    *OWNS.lock() = None;
    let _ = crate::diskless::sync(st);
    if !s.games.is_empty() {
        let _ = crate::games::sync(st);
    }
    let mut notes: Vec<String> = why.into_iter().collect();
    if s.keep {
        notes.push(format!(
            "Windows changes kept in {}: Save or Discard it (Goldens)",
            s.golden
        ));
    } else {
        let name = s.golden.clone();
        match retry_connected(&|| crate::iscsi::golden_discard(&name)) {
            Ok(()) => notes.push("Windows changes discarded".into()),
            Err(e) => notes.push(format!(
                "Windows changes NOT discarded ({e}) — Discard {} on the Goldens table",
                s.golden
            )),
        }
    }
    if !s.games.is_empty() {
        notes.push(format!(
            "games disk(s) {}: Save or Discard the update",
            s.games
                .iter()
                .map(|g| g.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    s.state =
        if s.state == "starting" || notes.first().is_some_and(|n| n.starts_with("not started")) {
            "failed".into()
        } else {
            "stopped".into()
        };
    s.ended = crate::now_secs();
    s.msg = notes.join("; ");
    put(st, &s);
    tracing::warn!("vm: {} stopped — {}", s.golden, s.msg);
}

/// Watch QEMU until it ends, then finish().
fn watch(st: SharedState) {
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_secs(2));
            match current(&st).filter(Session::active) {
                Some(s) if alive(&s) => continue,
                Some(_) => {
                    finish(&st, None);
                    return;
                }
                None => return,
            }
        }
    });
}

/// At start (before the first sync of the goldens / games disks): a VM left running by the previous process is
/// taken over (its disks stay writable for it); one that ended meanwhile is finished.
pub fn restore(st: &SharedState) {
    let Some(s) = current(st).filter(Session::active) else {
        return;
    };
    *OWNS.lock() = Some(Owns {
        golden: s.golden.clone(),
        games: s.games.iter().map(|g| g.name.clone()).collect(),
    });
    if alive(&s) {
        tracing::info!("vm: {} still running — taken over", s.golden);
        watch(st.clone());
    } else {
        let st = st.clone();
        std::thread::spawn(move || {
            finish(&st, Some("the VM ended while Broom was restarting".into()))
        });
    }
}

/// /api/diskless/client asked from this server itself (the VM reaches it through QEMU's NAT, so its requests come
/// from one of this server's own addresses) while the VM runs: it is a maintenance machine, and here are its games
/// disks for broom-games.ps1 ("<name> serial:<serial> <letter> 1").
pub(crate) fn client_answer(st: &SharedState, peer: IpAddr) -> Option<serde_json::Value> {
    let s = current(st).filter(|s| s.state == "running")?;
    if !is_own(peer, &crate::tls::local_ipv4s()) {
        return None;
    }
    Some(serde_json::json!({
        "role": "maintenance",
        "vm": true,
        "golden": s.golden,
        "host": "",
        "games": games_lines(&s.games),
    }))
}

/// `peer` is this server: loopback or one of its own addresses (`own`).
pub(crate) fn is_own(peer: IpAddr, own: &[String]) -> bool {
    peer.is_loopback() || own.contains(&peer.to_string())
}

pub(crate) fn games_lines(games: &[GamesDisk]) -> String {
    games
        .iter()
        .map(|g| format!("{} serial:{} {} 1\n", g.name, g.serial, g.letter))
        .collect()
}

// ---------- web ----------

/// GET /api/vm → {session, goldens: [Windows goldens], games: [disks], cpus, mem_mb, problem}
async fn status(State(st): State<SharedState>) -> Json<serde_json::Value> {
    let (games_st, problem) = tokio::task::spawn_blocking(|| {
        (
            crate::iscsi::games_status().unwrap_or_default(),
            crate::onboard::preflight().err(),
        )
    })
    .await
    .unwrap_or_default();
    let goldens: Vec<serde_json::Value> = crate::diskless::goldens(&st)
        .into_iter()
        .filter(|g| g.os == "windows")
        .map(|g| serde_json::json!({"name": g.name, "groups": g.groups}))
        .collect();
    let games: Vec<serde_json::Value> = crate::games::disks(&st)
        .into_iter()
        .map(|d| {
            let s = games_st.iter().find(|x| x.name == d.name);
            serde_json::json!({
                "name": d.name, "letter": d.letter, "groups": d.groups,
                "served": s.is_some(),
                "update_bytes": s.map_or(0, |x| x.update_bytes),
                "update_connected": s.is_some_and(|x| x.update_connected),
            })
        })
        .collect();
    Json(serde_json::json!({
        "session": current(&st),
        "goldens": goldens,
        "games": games,
        "cpus": CPUS,
        "mem_mb": MEM_MB,
        "problem": problem,
    }))
}

#[derive(Deserialize)]
struct StartBody {
    golden: String,
    #[serde(default)]
    games: Vec<String>,
    /// Keep the Windows changes (owner only).
    #[serde(default)]
    keep: bool,
}

/// POST /api/vm/start {golden, games: [names], keep} (staff: games only, keep = false).
async fn start(
    State(st): State<SharedState>,
    axum::Extension(w): axum::Extension<Who>,
    Json(b): Json<StartBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if b.keep && w.role != Role::Owner {
        return Err((
            StatusCode::FORBIDDEN,
            "keeping Windows changes is for an owner — staff update the games disks only".into(),
        ));
    }
    if !crate::diskless::valid_name(&b.golden) {
        return Err(bad("golden: its name"));
    }
    let mut games = b.games.clone();
    games.dedup();
    let s = tokio::task::spawn_blocking(move || begin(&st, &b.golden, &games, b.keep, &w.name))
        .await
        .map_err(ise)?
        .map_err(|e| (StatusCode::CONFLICT, e))?;
    Ok(Json(serde_json::json!({"ok": true, "session": s})))
}

#[derive(Deserialize)]
struct StopBody {
    /// Pull the plug instead of pressing the power button.
    #[serde(default)]
    force: bool,
}

/// POST /api/vm/stop {force} — the power button (Windows shuts down), or force: turned off at once.
async fn stop(
    State(st): State<SharedState>,
    axum::Extension(w): axum::Extension<Who>,
    Json(b): Json<StopBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let s = current(&st)
        .filter(|s| s.state == "running" || s.state == "stopping")
        .ok_or((StatusCode::CONFLICT, "no VM is running".to_string()))?;
    let st2 = st.clone();
    let msg = tokio::task::spawn_blocking(move || -> Result<String, String> {
        if b.force {
            stop_qemu(&s);
            Ok("turned off".into())
        } else {
            let work = work_dir(&st2, &s.golden)?;
            let mut s2 = s.clone();
            s2.state = "stopping".into();
            s2.msg = "Windows is shutting down".into();
            put(&st2, &s2);
            if let Err(e) = qmp(
                &work.join("qmp.sock"),
                &serde_json::json!({"execute": "system_powerdown"}),
            ) {
                put(&st2, &s);
                return Err(e);
            }
            Ok("power button pressed — Windows shuts down".into())
        }
    })
    .await
    .map_err(ise)?
    .map_err(|e| (StatusCode::CONFLICT, e))?;
    tracing::info!(
        "vm: {} — {msg} ({})",
        current(&st).map(|s| s.golden).unwrap_or_default(),
        w.name
    );
    Ok(Json(serde_json::json!({"ok": true, "msg": msg})))
}

/// GET /api/vm/console (WebSocket, signed in) — the VM's screen: RFB bytes both ways between noVNC and QEMU's VNC
/// socket. The session is checked again every 30 s.
async fn console(
    ws: WebSocketUpgrade,
    State(st): State<SharedState>,
    headers: HeaderMap,
) -> Response {
    if !crate::vnc::same_origin(&headers) {
        return (StatusCode::FORBIDDEN, "cross-site request").into_response();
    }
    let Some(s) = current(&st).filter(|s| s.state == "running" || s.state == "stopping") else {
        return (StatusCode::CONFLICT, "no VM is running").into_response();
    };
    let sock = match work_dir(&st, &s.golden) {
        Ok(w) => w.join("vnc.sock"),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    };
    let gone = crate::auth::until_invalid(st, crate::auth::session_token(&headers));
    ws.protocols(["binary"])
        .max_message_size(1 << 20)
        .on_upgrade(move |w| pump(w, sock, gone))
}

async fn pump(ws: WebSocket, sock: PathBuf, gone: impl std::future::Future<Output = ()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let Ok(u) = tokio::net::UnixStream::connect(&sock).await else {
        return;
    };
    let (mut ur, mut uw) = u.into_split();
    let (mut tx, mut rx) = ws.split();
    let down = async {
        let mut buf = vec![0u8; 1 << 16];
        loop {
            match ur.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx
                        .send(Message::Binary(buf[..n].to_vec().into()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
        let _ = tx.send(Message::Close(None)).await;
    };
    let up = async {
        while let Some(Ok(m)) = rx.next().await {
            match m {
                Message::Binary(b) => {
                    if uw.write_all(&b).await.is_err() {
                        break;
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
    };
    tokio::select! {
        _ = down => {}
        _ = up => {}
        _ = gone => {}
    }
}

/// GET /vm-console — the screen page (signed in).
async fn page() -> Html<&'static str> {
    Html(crate::assets::text("static/vm-console.html"))
}

async fn page_js() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        crate::assets::text("static/vm-console.js"),
    )
}

/// GET /novnc/<path> — noVNC's modules (only the files listed in assets.rs).
async fn novnc(UrlPath(path): UrlPath<String>) -> Response {
    let name = format!("static/novnc/{path}");
    if path.contains("..") || !path.ends_with(".js") || !crate::assets::has(&name) {
        return StatusCode::NOT_FOUND.into_response();
    }
    (
        [
            (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        crate::assets::bytes(&name),
    )
        .into_response()
}

#[cfg(test)]
#[path = "../tests/unit/vmmaint.rs"]
mod tests;
