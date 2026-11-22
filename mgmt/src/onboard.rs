// onboard.rs — "Add hardware" for Windows goldens: a PC whose network card the golden has never seen gets it installed
// into the golden, so it (and every identical PC) can boot the golden diskless.
//
// Why: Windows booting from iSCSI brings up only a network card whose *device* it already knows (its exact Plug and
// Play instance ID, e.g. PCI\VEN_8086&DEV_10D3&…\5&2490727a&0&9008F0). A driver in the driver store, even marked as a
// boot driver, is not enough (tested 30 Oct 2026: a never-seen card hung at the Windows spinner). So the device itself
// has to exist in the golden: created and installed the way Plug and Play does it when it meets the card, with that
// instance ID. Doing it in a VM on the server means the golden is changed once, by Broom, and saved as a normal new
// version (Discard if anything fails) — no PC has to install Windows or leave the room. Commercial diskless systems
// offer a similar "add new hardware" step; this is Broom's own implementation of the idea.
//
// Instance IDs follow the slot, not the box (two VMs with the same card in the same PCI slot get the same ID), so one
// run per board model / slot layout should cover a room of identical PCs (to be confirmed on real hardware).
//
// How (one job at a time):
//  1. An owner starts a job (Diskless page): golden + the machine that has the new card.
//  2. That machine's next network boot gets "Add this PC's network card" as its default menu entry: iPXE boots Windows
//     PE with wimboot (files taken from the golden's Windows installer ISO in the library; wimboot is Microsoft-signed,
//     so this works under Secure Boot too) plus broom-report.exe (winpe/broom-report.c), which sends Broom what Windows
//     sees (pnputil: instance IDs, hardware IDs, compatible IDs of every network card; wmic: their MACs) and shows the
//     progress.
//  3. Broom attaches the golden's newest version writable to itself (iSCSI over 127.0.0.1: the golden's "update
//     machine" is the loopback address while the job runs — the network cannot send from it), puts broom-onboard.ps1
//     in place of the golden's broom-diskless.ps1 (its startup task runs it as SYSTEM) with the job next to it, and boots
//     the golden in a small VM on this server (QEMU/KVM, AHCI disk, no network). The script creates each card's device
//     with that exact instance ID, lets Windows install the best driver from the driver store, marks the driver as a
//     network-boot driver, writes its result and powers off.
//  4. Broom puts the original script back and saves the work as the golden's next version (Discard on any failure —
//     the golden stays as it was), records the hardware, and the PC restarts into the golden.
// Needs on the server: qemu-system-x86_64 + OVMF, open-iscsi (iscsiadm), ntfs-3g, /dev/kvm (nested KVM when Broom
// itself runs in a VM). The golden needs broom-diskless.ps1 installed (its startup task).
use axum::{
    Json, Router,
    body::Body,
    extract::{Path, Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path as FsPath, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::SharedState;
use crate::api::{ApiError, bad, ise, ok};
use crate::db::Machine;
use crate::diskless::{self, MenuEntry};
use crate::machines::{machine_by_id, who};

/// Config key of the current / last job (JSON Job).
const JOB_KEY: &str = "onboard_job";
/// Config key of the hardware each golden has had installed (JSON map golden → [Hw]).
const HW_KEY: &str = "diskless_hw";
/// One VM boot may take this long (Windows on new hardware, nested KVM: ~1–3 min seen).
const VM_TIMEOUT: Duration = Duration::from_secs(15 * 60);
/// VM boots before giving up (Windows may restart once for its own device setup before the startup task runs).
const VM_TRIES: usize = 3;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct Nic {
    /// Plug and Play device instance ID, e.g. `PCI\VEN_8086&DEV_10D3&SUBSYS_00008086&REV_00\5&2490727a&0&9008F0`.
    pub instance: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub hwids: Vec<String>,
    #[serde(default)]
    pub compat: Vec<String>,
    /// pnputil's status line in Windows PE (Started / Problem …).
    #[serde(default)]
    pub status: String,
    /// Its MAC (12 hex digits) when Windows PE had a driver for it (wmic); "" = not known.
    #[serde(default)]
    pub mac: String,
    /// pnputil's class name: Net, or Unknown for a card Windows PE has no driver for (then its class code says it is a
    /// network controller).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub class: String,
}

/// A network controller by its IDs (PCI class code 02xx: Ethernet, other network controllers).
fn is_network(n: &Nic) -> bool {
    n.class.is_empty()
        || n.class.eq_ignore_ascii_case("Net")
        || n.hwids
            .iter()
            .chain(n.compat.iter())
            .any(|h| h.to_ascii_uppercase().contains("CC_02"))
}

/// Card `n` is the one iPXE booted with (`boot_card` = `PCI\VEN_xxxx&DEV_yyyy`).
fn is_boot_card(n: &Nic, boot_card: &str) -> bool {
    let b = boot_card.to_ascii_uppercase();
    !b.is_empty()
        && n.hwids
            .iter()
            .chain(n.compat.iter())
            .any(|h| h.to_ascii_uppercase().starts_with(&b))
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct Job {
    pub golden: String,
    /// Machine id (Devices page) whose network card is added.
    pub machine: i64,
    pub mac: String,
    /// Proves the Windows PE reporter is the one Broom booted for this job (it has no account).
    #[serde(default)]
    pub token: String,
    /// waiting (for the PC's Windows PE) | installing | done | failed | cancelled
    pub state: String,
    #[serde(default)]
    pub msg: String,
    #[serde(default)]
    pub started: u64,
    #[serde(default)]
    pub updated: u64,
    #[serde(default)]
    pub nics: Vec<Nic>,
    /// What the VM's script reported per card.
    #[serde(default)]
    pub results: Vec<serde_json::Value>,
    /// The golden version saved by this job.
    #[serde(default)]
    pub ver: Option<u64>,
    /// Steps, newest last (shown on the Diskless page).
    #[serde(default)]
    pub log: Vec<String>,
    /// The card the PC network-booted with, as iPXE saw it (`PCI\VEN_xxxx&DEV_yyyy`; "" = not known): before Windows PE,
    /// so Broom knows it even when Windows PE has no driver for it.
    #[serde(default)]
    pub boot_card: String,
    /// Unix time the PC fetched Windows PE (0 = not yet): a report long after that = no network in Windows PE.
    #[serde(default)]
    pub winpe_at: u64,
}

/// iPXE's `${net0/busid}` → `PCI\VEN_xxxx&DEV_yyyy`. iPXE prints it as hex bytes, colon-separated or not: bus type
/// (1 = PCI), vendor (2 bytes), device (2 bytes). Anything else (another bus, an empty setting) → None.
pub(crate) fn busid_card(busid: &str) -> Option<String> {
    let h: String = busid.chars().filter(|c| *c != ':').collect();
    if h.len() != 10 || !h.chars().all(|c| c.is_ascii_hexdigit()) || !h.starts_with("01") {
        return None;
    }
    Some(format!(
        "PCI\\VEN_{}&DEV_{}",
        h[2..6].to_ascii_uppercase(),
        h[6..10].to_ascii_uppercase()
    ))
}

/// How long after Windows PE was fetched a missing report means "no network in Windows PE" (it reports in ~30 s).
const NO_REPORT_S: u64 = 4 * 60;

/// A hint for a job still waiting: the PC started Windows PE long ago and never reported.
pub(crate) fn waiting_hint(j: &Job, now: u64) -> Option<String> {
    if j.state != "waiting" || j.winpe_at == 0 || now.saturating_sub(j.winpe_at) < NO_REPORT_S {
        return None;
    }
    let card = if j.boot_card.is_empty() {
        "its network card".to_string()
    } else {
        format!("its network card ({})", j.boot_card)
    };
    Some(format!(
        "Windows PE started {} min ago and has not reported: it likely has no driver for {card}. Add the card's driver \
         under Drivers (an extracted driver folder, zipped), then press Retry and network-boot the PC again.",
        now.saturating_sub(j.winpe_at) / 60
    ))
}

/// A network card a golden has had installed.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct Hw {
    pub instance: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub hwids: Vec<String>,
    #[serde(default)]
    pub service: String,
    #[serde(default)]
    pub inf: String,
    /// The golden version it was saved in.
    pub ver: u64,
    #[serde(default)]
    pub added: u64,
}

pub fn routes() -> Router<SharedState> {
    Router::new()
        .route("/api/onboard", get(status))
        .route("/api/onboard/start", post(start))
        .route("/api/onboard/cancel", post(cancel))
        .route("/api/onboard/retry", post(retry))
        .route("/api/diskless/refresh", post(refresh))
        // Public: the PC itself (Windows PE, by the job's token; iPXE, by its IP + MAC).
        .route("/api/onboard/report", post(report))
        .route("/api/onboard/state", get(state_q))
        .route("/boot/onboard", get(boot))
        .route("/boot/onboard/{file}", get(file))
}

// ---------- state ----------

pub(crate) fn job(st: &SharedState) -> Option<Job> {
    serde_json::from_str(&st.db.get_config(JOB_KEY, "")).ok()
}

fn put(st: &SharedState, j: &Job) {
    if let Ok(s) = serde_json::to_string(j) {
        let _ = st.db.set_config(JOB_KEY, &s);
    }
}

/// Change the current job (if `token` is still its token: a cancelled / replaced job is left alone).
fn update(st: &SharedState, token: &str, f: impl FnOnce(&mut Job)) -> Option<Job> {
    let mut j = job(st).filter(|j| j.token == token)?;
    f(&mut j);
    j.updated = crate::now_secs();
    put(st, &j);
    Some(j)
}

/// Progress line: the job's message and log, and the server log.
fn say(st: &SharedState, token: &str, msg: &str) {
    // ASCII: the PC's Windows PE console shows it in its own code page.
    let msg: String = msg
        .chars()
        .map(|c| if c.is_ascii() { c } else { '-' })
        .collect();
    let msg = msg.as_str();
    tracing::info!("add hardware: {msg}");
    update(st, token, |j| {
        j.msg = msg.to_string();
        j.log.push(format!("{} {msg}", hhmm()));
        let n = j.log.len();
        if n > 60 {
            j.log.drain(..n - 60);
        }
    });
}

fn hhmm() -> String {
    let s = crate::now_secs() % 86_400;
    format!("{:02}:{:02}:{:02} UTC", s / 3600, s / 60 % 60, s % 60)
}

pub(crate) fn active(j: &Job) -> bool {
    j.state == "waiting" || j.state == "installing"
}

/// The golden an Add hardware job is waiting or running for (its VM is, or will be, the one VM of this server).
pub(crate) fn running(st: &SharedState) -> Option<String> {
    job(st).filter(active).map(|j| j.golden)
}

/// A job is waiting or running on golden `name` (its maintenance is blocked meanwhile).
pub(crate) fn busy(st: &SharedState, name: &str) -> bool {
    job(st).is_some_and(|j| active(&j) && j.golden == name)
}

/// Golden whose update session belongs to this server right now (the onboarding VM, the script refresh), and that
/// job's write key: the daemon lets 127.0.0.1 write it only through the target name carrying the key (`local_target`).
static VM_GOLDEN: parking_lot::Mutex<Option<(String, String)>> = parking_lot::Mutex::new(None);

pub(crate) fn vm_owns(name: &str) -> bool {
    VM_GOLDEN.lock().as_ref().is_some_and(|(g, _)| g == name)
}

/// The write key of the job holding golden `name` (None = no job of this server holds it).
pub(crate) fn vm_key(name: &str) -> Option<String> {
    VM_GOLDEN
        .lock()
        .as_ref()
        .filter(|(g, _)| g == name)
        .map(|(_, k)| k.clone())
}

/// A new write key for one job of this server on a golden or games disk (never sent anywhere: it only appears in
/// the target name this server logs in to over its own loopback).
pub(crate) fn new_write_key() -> String {
    crate::auth::random_token()
}

/// The target this server logs in to for writing: version target `target` ("<iqn>.g<k>") with the job's key.
pub(crate) fn local_target(target: &str, key: &str) -> String {
    format!("{target}.u{key}")
}

/// The VM's QEMU process (cancel kills it).
static VM_PID: parking_lot::Mutex<Option<u32>> = parking_lot::Mutex::new(None);

pub(crate) fn hardware(st: &SharedState) -> HashMap<String, Vec<Hw>> {
    serde_json::from_str(&st.db.get_config(HW_KEY, "{}")).unwrap_or_default()
}

fn add_hardware(st: &SharedState, golden: &str, list: Vec<Hw>) {
    let _ = crate::db::edit_json(&*st.db, HW_KEY, |m: &mut HashMap<String, Vec<Hw>>| {
        let v = m.entry(golden.to_string()).or_default();
        for h in list {
            v.retain(|x| !x.instance.eq_ignore_ascii_case(&h.instance));
            v.push(h);
        }
        Ok::<(), String>(())
    });
}

/// Golden `name` deleted: its hardware list goes too.
pub(crate) fn forget_golden(st: &SharedState, name: &str) {
    let _ = crate::db::edit_json(&*st.db, HW_KEY, |m: &mut HashMap<String, Vec<Hw>>| {
        m.remove(name);
        Ok::<(), String>(())
    });
}

fn token() -> String {
    crate::auth::random_token()
}

// ---------- the boot menu + Windows PE ----------

/// Machine `m`'s first boot-menu entry while a job waits for it.
pub(crate) fn menu_entry(st: &SharedState, m: &Machine) -> Option<MenuEntry> {
    let j = job(st)?;
    (j.state == "waiting" && j.machine == m.id).then(|| MenuEntry {
        text: format!("Add this PC's network card to {} (Windows PE)", j.golden),
        // busid: the card iPXE booted with (vendor + device), known before Windows PE (busid_card).
        chain: format!("/boot/onboard?golden={}&busid=${{net0/busid}}", j.golden),
        default: true,
    })
}

/// Windows PE files of the golden's installer ISO: <ISO place>/.winpe/<iso>/ with boot.wim, boot.sdi, bootmgr.efi,
/// BCD — taken out of the ISO once (ISO 9660 names: Broom's own and xorriso-built ISOs have them; Microsoft's own ISOs
/// keep their files in UDF only → copy those four files into that folder by hand). Blocking.
pub(crate) fn winpe_dir(st: &SharedState, iso: &str) -> Result<PathBuf, String> {
    let lib = diskless::dir_of(st, "iso")?;
    let dir = lib.join(".winpe").join(iso);
    let want = WINPE_FILES;
    if want.iter().all(|(_, n)| dir.join(n).is_file()) {
        return Ok(dir);
    }
    let src = lib.join(iso);
    if !src.is_file() {
        return Err(format!("ISO {iso} is not in the library folder"));
    }
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    for (from, to) in want {
        let dst = dir.join(to);
        if dst.is_file() {
            continue;
        }
        let found =
            crate::iso9660::extract(&src, from, &dst, 8 << 30).map_err(|e| e.to_string())?;
        if !found {
            return Err(format!(
                "{iso}: no {from} in its ISO 9660 part (a Microsoft ISO keeps it in UDF) — copy boot.wim, boot.sdi, \
                 bootmgr.efi and the UEFI BCD into {}",
                dir.display()
            ));
        }
    }
    tracing::info!(
        "add hardware: Windows PE taken from {iso} into {}",
        dir.display()
    );
    Ok(dir)
}

/// (path in a Windows installer ISO, name in the Windows PE folder).
pub(crate) const WINPE_FILES: [(&str, &str); 4] = [
    ("sources/boot.wim", "boot.wim"),
    ("boot/boot.sdi", "boot.sdi"),
    ("bootmgr.efi", "bootmgr.efi"),
    ("efi/microsoft/boot/bcd", "BCD"),
];

/// startnet.cmd of the Windows PE (injected by wimboot into X:\Windows\System32): network, then the reporter with
/// this server, the job's token and the address iPXE had (fallback when Windows PE gets no DHCP lease).
pub(crate) fn startnet(srv: &str, token: &str, ip: &str, mask: &str, gw: &str) -> String {
    format!(
        "@echo off\r\nwpeinit\r\ncls\r\necho.\r\nbroom-report.exe http://{srv} {token} {ip} {mask} {gw}\r\n"
    )
}

/// The iPXE script booting Windows PE for job `token` (image index 1 of boot.wim = plain Windows PE); `drivers` = the
/// library's network-card drivers go along (broom-drivers.tar, drivers::winpe_bundle).
pub(crate) fn wimboot_script(golden: &str, token: &str, drivers: bool) -> String {
    let f = |n: &str| format!("/boot/onboard/{n}?t={token}");
    let drv = if drivers {
        format!(
            "initrd --name broom-drivers.tar {} broom-drivers.tar || goto failed\n",
            f("broom-drivers.tar")
        )
    } else {
        String::new()
    };
    format!(
        "#!ipxe\necho Adding this PC's network card to {golden}: starting Windows PE...\n\
         kernel {} index=1 || goto failed\n\
         initrd --name bootmgr.efi {} bootmgr.efi || goto failed\n\
         initrd --name BCD {} BCD || goto failed\n\
         initrd --name boot.sdi {} boot.sdi || goto failed\n\
         initrd --name boot.wim {} boot.wim || goto failed\n\
         initrd --name broom-report.exe {} broom-report.exe || goto failed\n\
         {drv}initrd --name startnet.cmd {}&ip=${{net0/ip}}&mask=${{net0/netmask}}&gw=${{net0/gateway}} startnet.cmd || goto failed\n\
         boot || goto failed\n\
         :failed\necho Could not start Windows PE\nsleep 10\nchain /boot.ipxe?mac=${{net0/mac}}&ip=${{net0/ip}}\n",
        f("wimboot"),
        f("bootmgr.efi"),
        f("BCD"),
        f("boot.sdi"),
        f("boot.wim"),
        f("broom-report.exe"),
        f("startnet.cmd"),
    )
}

/// An IPv4 address or "" (values from iPXE's URL go into a script).
fn ipv4(s: Option<&String>) -> String {
    s.and_then(|v| v.parse::<std::net::Ipv4Addr>().ok())
        .map(|a| a.to_string())
        .unwrap_or_default()
}

/// Network cards in pnputil's `/enum-devices /class Net /ids` text (English Windows PE): the physical ones only (on a
/// PCI or USB bus — not ROOT\, SWD\ miniports).
pub(crate) fn parse_pnputil(text: &str) -> Vec<Nic> {
    let mut out: Vec<Nic> = Vec::new();
    let mut cur: Option<Nic> = None;
    let mut list: Option<&'static str> = None; // "hw" | "compat": continuation lines go there
    let push = |cur: &mut Option<Nic>, out: &mut Vec<Nic>| {
        if let Some(n) = cur.take()
            && is_physical(&n.instance)
            && !out
                .iter()
                .any(|x| x.instance.eq_ignore_ascii_case(&n.instance))
        {
            out.push(n);
        }
    };
    for raw in text.lines() {
        let line = raw.trim_end();
        if line.trim().is_empty() {
            list = None;
            continue;
        }
        let (key, val) = match line.split_once(':') {
            // "Key:   value" — a key starts at column 0; continuation lines are indented.
            Some((k, v)) if !line.starts_with(char::is_whitespace) && !k.contains('\\') => {
                (Some(k.trim()), v.trim())
            }
            _ => (None, line.trim()),
        };
        match key {
            Some("Instance ID") => {
                push(&mut cur, &mut out);
                cur = Some(Nic {
                    instance: val.to_string(),
                    ..Default::default()
                });
                list = None;
            }
            Some(k) => {
                list = None;
                let Some(n) = cur.as_mut() else { continue };
                match k {
                    "Device Description" => n.name = val.to_string(),
                    "Class Name" => n.class = val.to_string(),
                    "Status" => n.status = val.to_string(),
                    "Hardware IDs" => {
                        list = Some("hw");
                        if !val.is_empty() {
                            n.hwids.push(val.to_string());
                        }
                    }
                    "Compatible IDs" => {
                        list = Some("compat");
                        if !val.is_empty() {
                            n.compat.push(val.to_string());
                        }
                    }
                    _ => {}
                }
            }
            None => {
                if let (Some(n), Some(l)) = (cur.as_mut(), list) {
                    let v = if l == "hw" {
                        &mut n.hwids
                    } else {
                        &mut n.compat
                    };
                    v.push(val.to_string());
                }
            }
        }
    }
    push(&mut cur, &mut out);
    for n in out.iter_mut() {
        n.hwids.retain(|h| valid_id(h));
        n.compat.retain(|h| valid_id(h));
        n.name = n
            .name
            .chars()
            .filter(|c| !c.is_control())
            .take(120)
            .collect();
        n.status = n
            .status
            .chars()
            .filter(|c| !c.is_control())
            .take(80)
            .collect();
    }
    // Network cards only: the Net class, or (a card Windows PE has no driver for, listed among the problem devices) a
    // network-controller class code.
    out.retain(|n| !n.hwids.is_empty() && valid_id(&n.instance) && is_network(n));
    for n in out.iter_mut() {
        n.class = n
            .class
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .take(32)
            .collect();
    }
    out
}

/// The report: pnputil's text, then (after "=== wmic nic ===") `wmic nic get MACAddress,PNPDeviceID` — the cards with
/// their MAC where Windows PE had a driver.
pub(crate) fn parse_report(text: &str) -> Vec<Nic> {
    let text = text.split("=== secure boot ===").next().unwrap_or(text);
    let (pnp, wmic) = text.split_once("=== wmic nic ===").unwrap_or((text, ""));
    let mut nics = parse_pnputil(pnp);
    for (mac, inst) in parse_wmic(wmic) {
        if let Some(n) = nics
            .iter_mut()
            .find(|n| n.instance.eq_ignore_ascii_case(&inst))
        {
            n.mac = mac;
        }
    }
    nics
}

/// (mac12, PNPDeviceID) rows of `wmic nic get MACAddress,PNPDeviceID` (columns: MAC first when there is one).
pub(crate) fn parse_wmic(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|l| {
            let mut w = l.split_whitespace();
            let (a, b) = (w.next()?, w.next()?);
            let mac = crate::iscsid::golden::mac12(a)?;
            (a.contains(':') || a.contains('-')).then_some((mac, b.to_string()))
        })
        .filter(|(_, i)| valid_id(i))
        .collect()
}

/// Whether the VM's per-card results are good enough to save: the card the PC booted from (`mac`) must be in;
/// another card that failed (no driver for it in the golden, e.g. Wi-Fi) is only reported. Err = why not.
pub(crate) fn judge(
    nics: &[Nic],
    results: &[serde_json::Value],
    mac: &str,
    boot_card: &str,
) -> Result<String, String> {
    let ok = |inst: &str| {
        results.iter().any(|r| {
            r["ok"].as_bool() == Some(true)
                && r["instance"]
                    .as_str()
                    .is_some_and(|i| i.eq_ignore_ascii_case(inst))
        })
    };
    let mac = crate::iscsid::golden::mac12(mac).unwrap_or_default();
    let installed: Vec<&Nic> = nics.iter().filter(|n| ok(&n.instance)).collect();
    if installed.is_empty() {
        return Err("no network card could be installed".into());
    }
    // The card this PC boots from: by its MAC (Windows PE had a driver), else by what iPXE saw (vendor + device).
    let boot = nics
        .iter()
        .find(|n| !mac.is_empty() && n.mac == mac)
        .or_else(|| nics.iter().find(|n| is_boot_card(n, boot_card)));
    if let Some(b) = boot
        && !ok(&b.instance)
    {
        return Err(format!(
            "the card this PC boots from ({}) could not be installed",
            b.name
        ));
    }
    let skipped: Vec<&str> = nics
        .iter()
        .filter(|n| !ok(&n.instance))
        .map(|n| n.name.as_str())
        .collect();
    Ok(if skipped.is_empty() {
        format!("{} card(s) installed", installed.len())
    } else {
        format!(
            "{} card(s) installed; not installed (no driver for it in the golden): {}",
            installed.len(),
            skipped.join(", ")
        )
    })
}

/// Secure Boot as Windows PE saw it (`reg query …\SecureBoot\State /v UEFISecureBootEnabled`): Some(on) / None.
pub(crate) fn secure_boot(text: &str) -> Option<bool> {
    let (_, sb) = text.split_once("=== secure boot ===")?;
    let line = sb.lines().find(|l| l.contains("UEFISecureBootEnabled"))?;
    let v = line.split_whitespace().last()?;
    Some(v == "0x1")
}

fn is_physical(instance: &str) -> bool {
    let up = instance.to_ascii_uppercase();
    up.starts_with("PCI\\") || up.starts_with("USB\\")
}

/// A Plug and Play ID as Windows writes them (it goes into a JSON job the VM's script reads, and into the registry).
fn valid_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 200
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "\\&_-.#{}".contains(c))
}

/// broom-report.exe, the program Windows PE runs to report the PC's cards: built from winpe/broom-report.c — by CI
/// into a release's assets, or by `mgmt/winpe/build.sh` for a local build, which puts it at
/// `<Broom's folder>/winpe/broom-report.exe`. None = this build has none (Add hardware says how to get it).
pub(crate) fn reporter() -> Option<Vec<u8>> {
    if let Some(b) = crate::assets::optional("scripts/broom-report.exe") {
        return Some(b.to_vec());
    }
    std::fs::read(reporter_path())
        .ok()
        .filter(|b| b.starts_with(b"MZ"))
}

fn reporter_path() -> PathBuf {
    crate::home().join("winpe/broom-report.exe")
}

/// Why Add hardware cannot run on this build (no reporter), if so.
pub(crate) fn reporter_missing() -> Option<String> {
    reporter().is_none().then(|| {
        format!(
            "this is a local build without broom-report.exe — build it (mgmt/winpe/build.sh, needs gcc-mingw-w64-x86-64) \
             and copy it to {}, or use a release",
            reporter_path().display()
        )
    })
}

// ---------- the VM side ----------

/// Tools the job needs on this server; Err lists what is missing.
pub(crate) fn preflight() -> Result<(), String> {
    let pkgs = crate::pkgmgr::missing();
    let mut miss: Vec<String> = pkgs.iter().map(|p| p.what().to_string()).collect();
    if !FsPath::new("/dev/kvm").exists() {
        miss.push("/dev/kvm (KVM; a VM needs nested virtualisation and CPU type host)".into());
    }
    if miss.is_empty() {
        return Ok(());
    }
    // What a person can do about the missing programs (the Install button, or the command); /dev/kvm is not one.
    let fix = if pkgs.is_empty() {
        String::new()
    } else {
        format!(" — {}", crate::pkgmgr::advice(&pkgs))
    };
    Err(format!("this server lacks {}{fix}", miss.join(", ")))
}

// ---------- confining QEMU ----------
// Both VMs of this server (this one, and the maintenance VM in the browser, vmmaint.rs) run a golden — Windows with
// whatever was installed into it, the maintenance one with internet and a person typing — inside QEMU started by
// Broom, which is root. A flaw in QEMU's device emulation must not hand the guest a root process on the server:
// - QEMU drops to an unprivileged user as soon as it has opened what it needs (KVM, the disks, its sockets): from
//   then on it cannot open the server's files, other disks, or signal other processes;
// - QEMU's seccomp filter (-sandbox): no obsolete system calls, no new processes, no scheduling / resource changes.
// The maintenance VM's own unit adds systemd's file-system and capability limits (vmmaint::launch).
// Its network is NOT narrowed: it reaches the internet and the LANs the server reaches, through QEMU's NAT.

/// The user QEMU runs as once started: nobody (uid:gid, the same number on Debian, Ubuntu, Fedora…).
pub(crate) const QEMU_USER: &str = "65534:65534";

/// QEMU's version from the first line of `qemu-system-x86_64 --version` ("QEMU emulator version 8.2.2 (…)").
pub(crate) fn parse_qemu_version(text: &str) -> Option<(u32, u32)> {
    let v = text.split("version ").nth(1)?;
    let mut n = v
        .split(|c: char| !c.is_ascii_digit())
        .filter(|p| !p.is_empty())
        .map(|p| p.parse::<u32>().ok());
    Some((n.next()??, n.next()??))
}

/// The installed QEMU's version (None = not found / not understood).
pub(crate) fn qemu_version() -> Option<(u32, u32)> {
    let o = Command::new(qemu()?).arg("--version").output().ok()?;
    parse_qemu_version(&String::from_utf8_lossy(&o.stdout))
}

/// Memory of the Add hardware VM, MB.
const VM_MB: u64 = 4096;

/// A file's path inside a QEMU option (`-drive file=…,format=…`): QEMU splits options at commas, a comma that is
/// part of the path is written twice. The folders are the owner's choice (Diskless page: where things are kept).
pub(crate) fn qpath(path: impl std::fmt::Display) -> String {
    path.to_string().replace(',', ",,")
}

/// The arguments that confine QEMU (see above), for QEMU `version`: the option that drops the user is `-runas`
/// up to 9.0 and `-run-with user=` from 9.1 on (which deprecated `-runas`). The filter must allow the one change
/// of user at start (elevateprivileges=allow); as nobody there is nothing left to elevate to.
pub(crate) fn confine_args(version: Option<(u32, u32)>) -> Vec<String> {
    let mut a: Vec<String> = if version.is_some_and(|v| v >= (9, 1)) {
        vec!["-run-with".into(), format!("user={QEMU_USER}")]
    } else {
        vec!["-runas".into(), QEMU_USER.into()]
    };
    a.extend([
        "-sandbox".to_string(),
        "on,obsolete=deny,elevateprivileges=allow,spawn=deny,resourcecontrol=deny".to_string(),
    ]);
    a
}

/// QEMU: `qemu-system-x86_64`, or `qemu-kvm` where the distribution (RHEL and its kin) puts it in libexec.
pub(crate) fn qemu() -> Option<PathBuf> {
    which("qemu-system-x86_64").or_else(|| {
        let p = PathBuf::from("/usr/libexec/qemu-kvm");
        p.is_file().then_some(p)
    })
}

pub(crate) fn which(t: &str) -> Option<PathBuf> {
    [
        "/usr/bin",
        "/usr/sbin",
        "/bin",
        "/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
    ]
    .iter()
    .map(|d| FsPath::new(d).join(t))
    .find(|p| p.is_file())
}

/// (code, vars template) of a non-Secure-Boot OVMF.
pub(crate) fn ovmf() -> Option<(PathBuf, PathBuf)> {
    [
        (
            "/usr/share/OVMF/OVMF_CODE_4M.fd",
            "/usr/share/OVMF/OVMF_VARS_4M.fd",
        ),
        (
            "/usr/share/OVMF/OVMF_CODE.fd",
            "/usr/share/OVMF/OVMF_VARS.fd",
        ),
        (
            "/usr/share/edk2/x64/OVMF_CODE.4m.fd",
            "/usr/share/edk2/x64/OVMF_VARS.4m.fd",
        ),
        (
            "/usr/share/edk2/ovmf/OVMF_CODE.fd",
            "/usr/share/edk2/ovmf/OVMF_VARS.fd",
        ),
    ]
    .iter()
    .map(|(c, v)| (PathBuf::from(c), PathBuf::from(v)))
    .find(|(c, v)| c.is_file() && v.is_file())
}

/// QEMU's arguments: the golden as an AHCI disk (Windows has storahci at boot), no network, no screen (QMP socket for
/// a screenshot when debugging), off = exit.
pub(crate) fn qemu_args(disk: &str, code: &str, vars: &str, qmp: &str) -> Vec<String> {
    [
        "-name",
        "broom-onboard",
        "-machine",
        "q35,accel=kvm",
        "-cpu",
        "host",
        "-smp",
        "4",
        "-m",
        &VM_MB.to_string(),
        "-drive",
        &format!("if=pflash,format=raw,readonly=on,file={}", qpath(code)),
        "-drive",
        &format!("if=pflash,format=raw,file={}", qpath(vars)),
        "-drive",
        &format!(
            "file={},format=raw,if=none,id=d0,cache=none,aio=threads",
            qpath(disk)
        ),
        "-device",
        "ahci,id=sata",
        "-device",
        "ide-hd,drive=d0,bus=sata.0,bootindex=1",
        "-nic",
        "none",
        "-display",
        "none",
        "-vga",
        "std",
        "-qmp",
        &format!("unix:{qmp},server,nowait"),
        "-no-reboot",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// Run a command to its end (at most `t`); stdout+stderr on success.
pub(crate) fn sh(cmd: &str, args: &[&str], t: Duration) -> Result<String, String> {
    let mut c = Command::new(cmd)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{cmd}: {e}"))?;
    let t0 = Instant::now();
    loop {
        match c.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if t0.elapsed() > t => {
                let _ = c.kill();
                let _ = c.wait();
                return Err(format!("{cmd} {}: timed out", args.join(" ")));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            Err(e) => return Err(format!("{cmd}: {e}")),
        }
    }
    let o = c.wait_with_output().map_err(|e| e.to_string())?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    if o.status.success() {
        Ok(text)
    } else {
        Err(format!(
            "{cmd} {}: {}",
            args.join(" "),
            text.trim().lines().last().unwrap_or("failed")
        ))
    }
}

const PORTAL: &str = "127.0.0.1:3260";

/// The golden's writable target attached to this server: its block device.
pub(crate) fn login(target: &str) -> Result<PathBuf, String> {
    login_as_named(target).map_err(|e| hide_key(&e, target))
}

/// `text` without the write key of `target` ("<iqn>.g<k>.u<key>", local_target): what a failed login says ends up in
/// the job's messages and the log, which every account reads.
pub(crate) fn hide_key(text: &str, target: &str) -> String {
    match crate::iscsid::games::split_key(target).1 {
        Some(key) => text.replace(key, "(key)"),
        None => text.to_string(),
    }
}

fn login_as_named(target: &str) -> Result<PathBuf, String> {
    let t = Duration::from_secs(30);
    let _ = sh(
        "iscsiadm",
        &["-m", "node", "-o", "new", "-T", target, "-p", PORTAL],
        t,
    );
    sh(
        "iscsiadm",
        &["-m", "node", "-T", target, "-p", PORTAL, "--login"],
        t,
    )?;
    let dev = PathBuf::from(format!(
        "/dev/disk/by-path/ip-{PORTAL}-iscsi-{target}-lun-0"
    ));
    for _ in 0..100 {
        if dev.exists() {
            let _ = sh("udevadm", &["settle", "-t", "10"], Duration::from_secs(15));
            if let Some(why) = taken(FsPath::new("/sys/class/block"), &dev) {
                logout(target);
                return Err(format!("{target}: {why}"));
            }
            return Ok(dev);
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    Err(format!("{target}: no disk appeared after the iSCSI login"))
}

/// Why the freshly attached disk `dev` cannot be used as it is: another layer of this server sits on it. That is
/// the multipath service, once it has seen the disk twice at the same time (two logins of one golden) and noted its
/// ID: from then on it takes the disk at every login, its partitions appear on the multipath device only, and what
/// is written past it is not safe. `sys` = /sys/class/block.
pub(crate) fn taken(sys: &FsPath, dev: &FsPath) -> Option<String> {
    let real = std::fs::canonicalize(dev).ok()?;
    let name = real.file_name()?.to_str()?;
    let holders: Vec<String> = std::fs::read_dir(sys.join(name).join("holders"))
        .ok()?
        .flatten()
        .filter_map(|e| e.file_name().to_str().map(String::from))
        .collect();
    (!holders.is_empty()).then(|| {
        format!(
            "this server's multipath service has taken the disk ({name} is under {}): Broom needs it as a plain \
             disk. Keep multipath off Broom's own disks — /etc/multipath/conf.d/broom.conf with \
             `blacklist {{ device {{ vendor \"BROOM\" product \".*\" }} }}`, then `multipath -w <its ID>` for an ID \
             already in /etc/multipath/wwids and `multipathd reconfigure` — and try again",
            holders.join(", ")
        )
    })
}

pub(crate) fn logout(target: &str) {
    let t = Duration::from_secs(30);
    let _ = sh(
        "iscsiadm",
        &["-m", "node", "-T", target, "-p", PORTAL, "--logout"],
        t,
    );
    let _ = sh(
        "iscsiadm",
        &["-m", "node", "-o", "delete", "-T", target, "-p", PORTAL],
        t,
    );
}

// ---------- files inside a mounted golden ----------
// A golden is written by whatever ran in it (its maintenance session, with internet), and an NTFS volume can hold
// symbolic links to anywhere — ntfs-3g shows them as Linux links, and "../../.." climbs out of the mount. This server
// reads, writes and deletes there as root, so nothing inside a mounted golden is ever reached through a link: every
// part of a path is checked (`ci_path`), and files are opened with O_NOFOLLOW (`g_read`, `g_write`). The volume is
// mounted by this server alone while it works on it, so what was checked cannot change underneath.

/// `rel` under `root` (a mounted golden), its parts matched without regard to case (NTFS names) — None when a part
/// is missing or is a symbolic link (logged: a golden has no business holding one on these paths).
pub(crate) fn ci_path(root: &FsPath, rel: &str) -> Option<PathBuf> {
    let mut cur = root.to_path_buf();
    for part in rel.split('/').filter(|p| !p.is_empty()) {
        let exact = cur.join(part);
        let next = if std::fs::symlink_metadata(&exact).is_ok() {
            exact
        } else {
            std::fs::read_dir(&cur)
                .ok()?
                .flatten()
                .find(|e| {
                    e.file_name()
                        .to_str()
                        .is_some_and(|n| n.eq_ignore_ascii_case(part))
                })?
                .path()
        };
        if is_link(&next) {
            tracing::warn!(
                "golden: {} is a symbolic link - not followed",
                next.strip_prefix(root).unwrap_or(&next).display()
            );
            return None;
        }
        cur = next;
    }
    Some(cur)
}

/// `p` itself is a symbolic link (not what it points to).
fn is_link(p: &FsPath) -> bool {
    std::fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_symlink())
}

/// `name` in folder `dir` of a mounted golden (`dir` from `ci_path`), for a file or folder this server makes there:
/// refused when something of that name is there as a symbolic link.
pub(crate) fn g_child(dir: &FsPath, name: &str) -> Result<PathBuf, String> {
    let p = dir.join(name);
    if is_link(&p) {
        return Err(format!(
            "{name} in the golden is a symbolic link - not touched"
        ));
    }
    Ok(p)
}

/// The largest file of a golden read into memory (scripts, driver .inf / .cat files: kilobytes to a few megabytes).
const G_READ_MAX: u64 = 64 << 20;

/// A file of a mounted golden, read without following a link at its name: what is inside a golden is whatever its
/// Windows wrote there.
pub(crate) fn g_read(p: &FsPath) -> Result<Vec<u8>, String> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let mut v = Vec::new();
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(p)
        .and_then(|f| f.take(G_READ_MAX + 1).read_to_end(&mut v))
        .map_err(|e| format!("{}: {e}", p.display()))?;
    if v.len() as u64 > G_READ_MAX {
        return Err(format!(
            "{}: larger than {} MB — not a file this server reads whole",
            p.display(),
            G_READ_MAX >> 20
        ));
    }
    Ok(v)
}

/// A file of a mounted golden written (made or replaced) without following a link at its name.
pub(crate) fn g_write(p: &FsPath, data: &[u8]) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(p)
        .and_then(|mut f| f.write_all(data))
        .map_err(|e| format!("{}: {e}", p.display()))
}

struct Mount {
    dir: PathBuf,
}

impl Mount {
    fn new(part: &FsPath, dir: &FsPath, rw: bool) -> Result<Mount, String> {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let p = part.to_string_lossy();
        let d = dir.to_string_lossy();
        // Nothing in a golden is run, trusted as a device or as a set-uid program on this server.
        let opts = if rw {
            "nosuid,nodev,noexec"
        } else {
            "ro,nosuid,nodev,noexec"
        };
        sh(
            "ntfs-3g",
            &["-o", opts, p.as_ref(), d.as_ref()],
            Duration::from_secs(60),
        )?;
        Ok(Mount {
            dir: dir.to_path_buf(),
        })
    }
}

impl Drop for Mount {
    fn drop(&mut self) {
        let d = self.dir.to_string_lossy().to_string();
        for _ in 0..10 {
            if sh("umount", &[&d], Duration::from_secs(60)).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        tracing::error!("add hardware: could not unmount {d}");
    }
}

/// The Windows partition of `dev`: the NTFS one with Windows\System32\config\SYSTEM.
fn windows_part(dev: &FsPath, mnt: &FsPath) -> Result<PathBuf, String> {
    let real = std::fs::canonicalize(dev).map_err(|e| e.to_string())?;
    let base = real
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_string();
    let mut parts: Vec<PathBuf> = std::fs::read_dir("/sys/class/block")
        .map_err(|e| e.to_string())?
        .flatten()
        .filter_map(|e| e.file_name().to_str().map(String::from))
        .filter(|n| n.starts_with(&base) && n.len() > base.len())
        .map(|n| PathBuf::from("/dev").join(n))
        .collect();
    parts.sort();
    for p in parts {
        let Ok(m) = Mount::new(&p, mnt, false) else {
            continue;
        };
        if ci_path(&m.dir, "Windows/System32/config/SYSTEM").is_some_and(|f| f.is_file()) {
            return Ok(p);
        }
    }
    Err("no Windows partition on the golden".into())
}

/// The VM's work folder: <writeback place>/.onboard
fn work_dir(st: &SharedState) -> Result<PathBuf, String> {
    let d = diskless::dir_of(st, "writeback")?.join(".onboard");
    std::fs::create_dir_all(&d).map_err(|e| e.to_string())?;
    Ok(d)
}

/// Boot the golden in the VM once; Ok(()) when QEMU ended by itself (the guest powered off or restarted).
fn run_vm(st: &SharedState, token: &str, disk: &FsPath, work: &FsPath) -> Result<(), String> {
    crate::sysmon::room_for_vm(VM_MB, crate::sysmon::meminfo("MemAvailable:"))?;
    let (code, vars_t) = ovmf().ok_or("no OVMF")?;
    let vars = work.join("vars.fd");
    std::fs::copy(&vars_t, &vars).map_err(|e| format!("OVMF vars: {e}"))?;
    let qmp = work.join("qmp.sock");
    let _ = std::fs::remove_file(&qmp);
    let mut args = qemu_args(
        &disk.to_string_lossy(),
        &code.to_string_lossy(),
        &vars.to_string_lossy(),
        &qmp.to_string_lossy(),
    );
    args.extend(confine_args(qemu_version()));
    let log = std::fs::File::create(work.join("qemu.log")).map_err(|e| e.to_string())?;
    let mut c = Command::new(qemu().ok_or("no qemu-system-x86_64")?)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(log.try_clone().map_err(|e| e.to_string())?)
        .stderr(log)
        .spawn()
        .map_err(|e| format!("qemu: {e}"))?;
    *VM_PID.lock() = Some(c.id());
    let t0 = Instant::now();
    let r = loop {
        match c.try_wait() {
            Ok(Some(s)) => {
                break if s.success() {
                    Ok(())
                } else {
                    Err(format!("QEMU stopped: {s}"))
                };
            }
            Ok(None) if t0.elapsed() > VM_TIMEOUT => {
                let _ = c.kill();
                let _ = c.wait();
                break Err(format!(
                    "the VM did not finish in {} min",
                    VM_TIMEOUT.as_secs() / 60
                ));
            }
            Ok(None) => {
                if job(st).is_none_or(|j| j.token != token || j.state != "installing") {
                    let _ = c.kill();
                    let _ = c.wait();
                    break Err("cancelled".into());
                }
                std::thread::sleep(Duration::from_millis(500))
            }
            Err(e) => break Err(e.to_string()),
        }
    };
    *VM_PID.lock() = None;
    r
}

/// The whole VM step for the current job → (status line, results). The golden's update session holds all its writes:
/// on Err the caller discards them, so the golden stays as it was. Blocking.
fn install(
    st: &SharedState,
    j: &Job,
    key: &str,
) -> Result<(String, Vec<serde_json::Value>), String> {
    let t = &j.token;
    let info = diskless::served(&j.golden).ok_or("the golden is not served")?;
    if info.disk.update_bytes > 0 || info.disk.update_connected {
        return Err("the golden has unsaved maintenance work - Save or Discard it first".into());
    }
    let target = local_target(
        &format!("{}.g{}", diskless::iqn(st, &j.golden), info.disk.ver),
        key,
    );
    let work = work_dir(st)?;
    let mnt = work.join("mnt");
    say(
        st,
        t,
        &format!(
            "attaching {} version g{} to the server",
            j.golden, info.disk.ver
        ),
    );
    let dev = login(&target)?;
    // From here every exit logs out (the caller hands the update session back).
    let r = (|| {
        let part = windows_part(&dev, &mnt)?;
        // 1. The script + job into the golden (its startup task runs broom-diskless.ps1).
        let orig;
        {
            let m = Mount::new(&part, &mnt, true)?;
            let dir = ci_path(&m.dir, "Windows/Setup/Scripts")
                .filter(|d| d.is_dir())
                .ok_or("the golden has no C:\\Windows\\Setup\\Scripts — run broom-diskless.ps1 on it first (Diskless page)")?;
            let ps = ci_path(&dir, "broom-diskless.ps1")
                .filter(|f| f.is_file())
                .ok_or("the golden has no broom-diskless.ps1 (its startup task) — run it on the golden first")?;
            orig = g_read(&ps)?;
            std::fs::write(work.join("broom-diskless.ps1.orig"), &orig)
                .map_err(|e| e.to_string())?;
            for f in ["broom-onboard-result.json", "broom-onboard.log"] {
                let _ = std::fs::remove_file(dir.join(f));
            }
            // The library's drivers for these cards (by vendor + device) next to the script: it adds them to the
            // golden's driver store before installing the cards.
            let nets = crate::drivers::net_drivers(st);
            let ids: Vec<String> = j
                .nics
                .iter()
                .flat_map(|n| n.hwids.iter().chain(n.compat.iter()).cloned())
                .chain((!j.boot_card.is_empty()).then(|| j.boot_card.clone()))
                .collect();
            let drv_dir = g_child(&dir, "broom-drv")?;
            let _ = std::fs::remove_dir_all(&drv_dir);
            if std::fs::symlink_metadata(&drv_dir).is_ok() {
                return Err("an old broom-drv folder in the golden could not be removed".into());
            }
            let mut drv = Vec::new();
            for d in crate::drivers::matching(&nets, &ids) {
                crate::drivers::unpack(d, &drv_dir.join(&d.name))?;
                drv.push(format!("broom-drv\\{}", d.name));
            }
            if !drv.is_empty() {
                say(
                    st,
                    t,
                    &format!(
                        "driver package(s) from the library for these cards: {}",
                        drv.join(", ").replace("broom-drv\\", "")
                    ),
                );
            }
            let job_json =
                serde_json::json!({ "golden": j.golden, "nics": j.nics, "drivers": drv });
            g_write(
                &g_child(&dir, "broom-onboard.json")?,
                job_json.to_string().as_bytes(),
            )?;
            g_write(
                &ps,
                crate::assets::text("scripts/broom-onboard.ps1").as_bytes(),
            )?;
        }
        // 2. Boot it until the script has written its result.
        let mut result = None;
        for n in 1..=VM_TRIES {
            say(
                st,
                t,
                &format!(
                    "booting {} in the onboarding VM (try {n} of {VM_TRIES}, 2-5 min)",
                    j.golden
                ),
            );
            run_vm(st, t, &dev, &work)?;
            let m = Mount::new(&part, &mnt, false)?;
            if let Some(f) = ci_path(&m.dir, "Windows/Setup/Scripts/broom-onboard-result.json")
                .filter(|f| f.is_file())
            {
                let txt = String::from_utf8(g_read(&f)?).map_err(|e| e.to_string())?;
                let log = ci_path(&m.dir, "Windows/Setup/Scripts/broom-onboard.log")
                    .and_then(|f| g_read(&f).ok())
                    .map(|b| String::from_utf8_lossy(&b).into_owned())
                    .unwrap_or_default();
                let _ = std::fs::write(work.join("broom-onboard.log"), &log);
                result = Some(txt);
                break;
            }
            say(
                st,
                t,
                "the VM stopped before the script finished (Windows may restart once on new hardware)",
            );
        }
        let txt = result.ok_or("the script in the VM never finished (see broom-onboard.log / qemu.log in the work folder)")?;
        let v: serde_json::Value = serde_json::from_str(txt.trim_start_matches('\u{feff}'))
            .map_err(|e| format!("result unreadable: {e}"))?;
        // 3. The golden's own script back; the job files out.
        {
            let m = Mount::new(&part, &mnt, true)?;
            let dir = ci_path(&m.dir, "Windows/Setup/Scripts").ok_or("Scripts folder gone")?;
            let ps = ci_path(&dir, "broom-diskless.ps1").ok_or("broom-diskless.ps1 gone")?;
            g_write(&ps, &orig)?;
            if let Ok(d) = g_child(&dir, "broom-drv") {
                let _ = std::fs::remove_dir_all(d);
            }
            for f in [
                "broom-onboard.json",
                "broom-onboard-result.json",
                "broom-onboard.log",
            ] {
                let _ = std::fs::remove_file(dir.join(f));
            }
        }
        let results: Vec<serde_json::Value> = v["nics"].as_array().cloned().unwrap_or_default();
        if v["ok"].as_bool() != Some(true) {
            return Err(format!(
                "the VM's script: {}",
                v["msg"].as_str().unwrap_or("")
            ));
        }
        let msg = judge(&j.nics, &results, &j.mac, &j.boot_card)?;
        Ok((msg, results))
    })();
    logout(&target);
    r
}

/// The job's worker thread: install → Save (or Discard), hardware recorded.
fn worker(st: SharedState, token: String) {
    let Some(j) = job(&st).filter(|j| j.token == token) else {
        return;
    };
    let name = j.golden.clone();
    let key = new_write_key();
    *VM_GOLDEN.lock() = Some((name.clone(), key.clone()));
    let r = diskless::sync(&st).and_then(|()| install(&st, &j, &key));
    *VM_GOLDEN.lock() = None;
    let _ = diskless::sync(&st);
    let save = |f: &dyn Fn() -> Result<String, String>| -> Result<String, String> {
        for _ in 0..40 {
            match f() {
                Err(e) if e.contains("still connected") => {
                    std::thread::sleep(Duration::from_millis(500))
                }
                r => return r,
            }
        }
        f()
    };
    match r {
        Ok((msg, results)) => match save(&|| crate::iscsi::golden_save(&name)) {
            Ok(s) => {
                let ver = diskless::served(&name).map(|i| i.disk.ver);
                let hw: Vec<Hw> = j
                    .nics
                    .iter()
                    .filter(|n| {
                        results.iter().any(|r| {
                            r["ok"].as_bool() == Some(true)
                                && r["instance"]
                                    .as_str()
                                    .is_some_and(|i| i.eq_ignore_ascii_case(&n.instance))
                        })
                    })
                    .map(|n| {
                        let r = results.iter().find(|r| {
                            r["instance"]
                                .as_str()
                                .is_some_and(|i| i.eq_ignore_ascii_case(&n.instance))
                        });
                        let s = |k: &str| r.and_then(|r| r[k].as_str()).unwrap_or("").to_string();
                        Hw {
                            instance: n.instance.clone(),
                            name: n.name.clone(),
                            hwids: n.hwids.clone(),
                            service: s("service"),
                            inf: s("inf"),
                            ver: ver.unwrap_or(0),
                            added: crate::now_secs(),
                        }
                    })
                    .collect();
                add_hardware(&st, &name, hw);
                say(
                    &st,
                    &token,
                    &format!(
                        "{msg} - saved as {name} version g{} ({s}){}",
                        ver.unwrap_or(0),
                        diskless::held(&st, &name)
                    ),
                );
                update(&st, &token, |j| {
                    j.state = "done".into();
                    j.ver = ver;
                    j.results = results;
                });
            }
            Err(e) => {
                let _ = save(&|| crate::iscsi::golden_discard(&name).map(|()| String::new()));
                fail(&st, &token, &format!("{msg}, but Save failed: {e}"));
            }
        },
        Err(e) => {
            let d = save(&|| crate::iscsi::golden_discard(&name).map(|()| String::new()));
            let tail = match d {
                Ok(_) => "the golden is unchanged",
                Err(_) => "its work could not be discarded — Discard it on the Diskless page",
            };
            fail(&st, &token, &format!("{e} - {tail}"));
        }
    }
}

/// A golden step that may meet the daemon still counting a client that just left: tried again for up to ~20 s.
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

// ---------- Update Broom's script in a golden ----------

/// Broom's current broom-diskless.ps1 into golden `name`'s C:\Windows\Setup\Scripts (what its startup task runs), and
/// no machine's agent folder (C:\ProgramData\Broom) left in it. Ok(true) = something changed. Blocking.
fn write_script(st: &SharedState, name: &str, ver: u64, key: &str) -> Result<bool, String> {
    let target = local_target(&format!("{}.g{ver}", diskless::iqn(st, name)), key);
    let mnt = work_dir(st)?.join("mnt-refresh");
    let dev = login(&target)?;
    let r = (|| {
        let part = windows_part(&dev, &mnt)?;
        let m = Mount::new(&part, &mnt, true)?;
        let ps = ci_path(&m.dir, "Windows/Setup/Scripts/broom-diskless.ps1")
            .filter(|f| f.is_file())
            .ok_or("the golden has no C:\\Windows\\Setup\\Scripts\\broom-diskless.ps1 (its startup task) — install it on the golden once from its maintenance machine (Diskless page)")?;
        let new = diskless::script_text(st);
        let mut changed = false;
        if g_read(&ps).ok().as_deref() != Some(new.as_bytes()) {
            g_write(&ps, new.as_bytes())?;
            changed = true;
        }
        if let Some(d) = ci_path(&m.dir, "ProgramData/Broom").filter(|d| d.is_dir()) {
            std::fs::remove_dir_all(&d).map_err(|e| format!("{}: {e}", d.display()))?;
            changed = true;
        }
        Ok(changed)
    })();
    logout(&target);
    r
}

/// The whole "update script" step for golden `name`: its newest version attached to this server (no VM), the script
/// written, then saved as the next version (nothing changed: the session discarded). Same conditions as Add hardware:
/// a Windows golden, no maintenance machine, no unsaved work, no job running. Blocking.
fn refresh_script(st: &SharedState, name: &str) -> Result<String, String> {
    for t in ["iscsiadm", "ntfs-3g"] {
        if which(t).is_none() {
            return Err(format!("{t} is not installed on this server"));
        }
    }
    if let Some(j) = job(st).filter(active) {
        return Err(format!(
            "an Add hardware job is {} for {} — wait for it or cancel it",
            j.state, j.golden
        ));
    }
    let g = diskless::goldens(st)
        .into_iter()
        .find(|g| g.name == name)
        .ok_or_else(|| format!("no golden {name}"))?;
    if g.os != "windows" {
        return Err("the startup script is for Windows goldens".into());
    }
    if g.maint.is_some() {
        return Err(format!(
            "{name} has a maintenance machine — turn maintenance off (Save or Discard its work) first"
        ));
    }
    let info = diskless::served(name).ok_or("the golden is not served")?;
    if info.disk.ver == 0 {
        return Err("the golden has no saved version yet".into());
    }
    if info.disk.update_bytes > 0 || info.disk.update_connected {
        return Err("the golden has unsaved work — Save or Discard it first".into());
    }
    {
        let mut v = VM_GOLDEN.lock();
        if let Some((o, _)) = v.as_ref() {
            return Err(format!("{o} is being updated on the server right now"));
        }
        *v = Some((name.to_string(), new_write_key()));
    }
    let key = vm_key(name).unwrap_or_default();
    let r = diskless::sync(st).and_then(|()| write_script(st, name, info.disk.ver, &key));
    *VM_GOLDEN.lock() = None;
    let _ = diskless::sync(st);
    let discard = || retry_connected(&|| crate::iscsi::golden_discard(name));
    match r {
        Ok(true) => match retry_connected(&|| crate::iscsi::golden_save(name)) {
            Ok(_) => {
                let ver = diskless::served(name).map_or(0, |i| i.disk.ver);
                tracing::info!("golden {name}: Broom's startup script updated → g{ver}");
                Ok(format!(
                    "Broom's current startup script is in {name}: saved as version g{ver} (every machine sets itself up again at its next boot)"
                ))
            }
            Err(e) => {
                let _ = discard();
                Err(format!(
                    "written, but Save failed: {e} — the golden is unchanged"
                ))
            }
        },
        Ok(false) => {
            let _ = discard();
            Ok(format!(
                "{name} already has Broom's current startup script — nothing changed"
            ))
        }
        Err(e) => {
            let tail = match discard() {
                Ok(()) => "the golden is unchanged",
                Err(_) => "its work could not be discarded — Discard it on the Diskless page",
            };
            Err(format!("{e} - {tail}"))
        }
    }
}

#[derive(Deserialize)]
struct RefreshBody {
    name: String,
}

/// POST /api/diskless/refresh {name} — Broom's current startup script written into a Windows golden as its next
/// version, without booting it (goldens set up before the script fetched the server's version by itself).
async fn refresh(
    State(st): State<SharedState>,
    Json(b): Json<RefreshBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let msg = tokio::task::spawn_blocking(move || refresh_script(&st, &b.name))
        .await
        .map_err(ise)?
        .map_err(|e| (StatusCode::CONFLICT, e))?;
    Ok(Json(serde_json::json!({"ok": true, "status": msg})))
}

fn fail(st: &SharedState, token: &str, msg: &str) {
    tracing::warn!("add hardware failed: {msg}");
    say(st, token, msg);
    update(st, token, |j| j.state = "failed".into());
}

// ---------- API ----------

/// GET /api/onboard — the job (token hidden) and each golden's hardware.
async fn status(State(st): State<SharedState>) -> Result<Json<serde_json::Value>, ApiError> {
    let j = job(&st).map(|mut j| {
        j.token.clear();
        j
    });
    let pre = preflight().err().or_else(reporter_missing);
    let hint = j.as_ref().and_then(|j| waiting_hint(j, crate::now_secs()));
    Ok(Json(
        serde_json::json!({ "job": j, "hardware": hardware(&st), "missing": pre, "hint": hint }),
    ))
}

#[derive(Deserialize)]
struct StartBody {
    golden: String,
    machine: i64,
}

/// POST /api/onboard/start {golden, machine} — that machine's next network boot reports its network card(s).
async fn start(
    State(st): State<SharedState>,
    Json(b): Json<StartBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let st2 = st.clone();
    let j = tokio::task::spawn_blocking(move || -> Result<Job, ApiError> {
        let st = st2;
        if let Some(j) = job(&st).filter(active) {
            return Err((
                StatusCode::CONFLICT,
                format!("a job is already {} for {} — cancel it first", j.state, j.golden),
            ));
        }
        if let Some((g, _)) = VM_GOLDEN.lock().as_ref() {
            return Err((
                StatusCode::CONFLICT,
                format!("{g} is being updated on the server right now — try again in a minute"),
            ));
        }
        if crate::vmmaint::owns_golden(&b.golden) {
            return Err((
                StatusCode::CONFLICT,
                format!("{} is running in the VM (Maintain in the browser) — shut it down first", b.golden),
            ));
        }
        // One VM at a time on a server, of either kind: Add hardware ends in a VM of its own.
        if let Some(g) = crate::vmmaint::running(&st) {
            return Err((
                StatusCode::CONFLICT,
                format!("the VM of {g} is running (Maintain in the browser; one VM at a time) — shut it down first"),
            ));
        }
        preflight().map_err(|e| (StatusCode::CONFLICT, e))?;
        if let Some(e) = reporter_missing() {
            return Err((StatusCode::CONFLICT, e));
        }
        let g = diskless::goldens(&st)
            .into_iter()
            .find(|g| g.name == b.golden)
            .ok_or_else(|| bad(format!("no golden {}", b.golden)))?;
        if g.os != "windows" {
            return Err(bad("adding hardware is for Windows goldens"));
        }
        if g.maint.is_some() {
            return Err((
                StatusCode::CONFLICT,
                format!("{} has a maintenance machine — turn maintenance off (Save or Discard its work) first", g.name),
            ));
        }
        let info = diskless::served(&g.name).ok_or((StatusCode::CONFLICT, "the golden is not served".to_string()))?;
        if info.disk.ver == 0 {
            return Err(bad("the golden has no saved version yet"));
        }
        if info.disk.update_bytes > 0 {
            return Err((StatusCode::CONFLICT, "the golden has unsaved work — Save or Discard it first".into()));
        }
        let iso = g
            .iso
            .clone()
            .ok_or_else(|| bad("the golden has no installer ISO: Windows PE comes from it"))?;
        // Windows PE out of the ISO now (once): a missing file shows here, not on the PC's screen.
        winpe_dir(&st, &iso).map_err(|e| (StatusCode::CONFLICT, e))?;
        let m = machine_by_id(&st, b.machine)?;
        let now = crate::now_secs();
        let j = Job {
            golden: g.name.clone(),
            machine: m.id,
            mac: m.mac.clone(),
            token: token(),
            state: "waiting".into(),
            msg: format!("waiting for {} to boot from the network", who(&m)),
            started: now,
            updated: now,
            log: vec![format!("{} started: {} on {}", hhmm(), who(&m), g.name)],
            ..Default::default()
        };
        put(&st, &j);
        tracing::info!("add hardware: {} → golden {} (waiting for its network boot)", who(&m), g.name);
        Ok(j)
    })
    .await
    .map_err(ise)??;
    Ok(Json(serde_json::json!({"ok": true, "status": j.msg})))
}

/// POST /api/onboard/cancel — stop the job (a running VM is killed; its work discarded).
async fn cancel(State(st): State<SharedState>) -> Result<Json<serde_json::Value>, ApiError> {
    let Some(j) = job(&st).filter(active) else {
        return Ok(ok());
    };
    say(&st, &j.token, "cancelled by an admin");
    update(&st, &j.token, |j| j.state = "cancelled".into());
    if let Some(pid) = *VM_PID.lock() {
        // SAFETY: plain kill(2) on QEMU's pid (our child, still running: VM_PID is cleared when it is reaped).
        unsafe {
            libc::kill(pid as i32, libc::SIGKILL);
        }
    }
    Ok(ok())
}

/// POST /api/onboard/retry — run the VM step again with the cards the PC reported (a failed or cancelled job; the PC
/// does not need to boot Windows PE again).
async fn retry(State(st): State<SharedState>) -> Result<Json<serde_json::Value>, ApiError> {
    let j = job(&st).ok_or_else(|| bad("no job"))?;
    if active(&j) {
        return Err((StatusCode::CONFLICT, format!("the job is {}", j.state)));
    }
    if j.nics.is_empty() {
        return Err(bad(
            "the PC has not reported its cards yet - start a new job",
        ));
    }
    if diskless::goldens(&st)
        .iter()
        .any(|g| g.name == j.golden && g.maint.is_some())
    {
        return Err((
            StatusCode::CONFLICT,
            "the golden has a maintenance machine now".into(),
        ));
    }
    let token = j.token.clone();
    update(&st, &token, |j| {
        j.state = "installing".into();
        j.results.clear();
        j.ver = None;
    });
    say(&st, &token, "retry by an admin");
    let st2 = st.clone();
    std::thread::spawn(move || worker(st2, token));
    Ok(Json(
        serde_json::json!({"ok": true, "status": "running again"}),
    ))
}

/// The job a Windows PE request is for: the job's token (compared in constant time) AND sent by the job's machine —
/// the token travels in plain-HTTP URLs on the LAN, so alone it proves nothing: the kernel must see that machine's
/// network card behind the sender (ARP), as for every other step of its boot.
fn by_token(st: &SharedState, q: &HashMap<String, String>, peer: &str) -> Option<Job> {
    let t = q.get("t")?;
    let j = job(st).filter(|j| token_matches(&j.token, t))?;
    if !from_job_machine(&j.mac, crate::license::arp_mac(peer).as_deref()) {
        tracing::warn!(
            "add hardware: {peer} used the job's token but is not the job's machine ({}) - refused",
            j.mac
        );
        return None;
    }
    Some(j)
}

/// `given` is the job's token (never an empty one).
pub(crate) fn token_matches(token: &str, given: &str) -> bool {
    !token.is_empty() && crate::auth::same(token, given)
}

/// The sender's MAC as the kernel sees it (`seen`) is the job machine's.
pub(crate) fn from_job_machine(job_mac: &str, seen: Option<&str>) -> bool {
    let want = crate::iscsid::golden::mac12(job_mac);
    want.is_some() && seen.and_then(crate::iscsid::golden::mac12) == want
}

/// POST /api/onboard/report?t= (public: Windows PE) — pnputil's text; starts the VM step.
async fn report(
    State(st): State<SharedState>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    Query(q): Query<HashMap<String, String>>,
    body: String,
) -> Result<String, ApiError> {
    let peer = peer.ip().to_canonical().to_string();
    let j = by_token(&st, &q, &peer).ok_or((
        StatusCode::NOT_FOUND,
        "no such job for this PC (the report must come through the network card it booted from)"
            .to_string(),
    ))?;
    if j.state != "waiting" {
        return Err((StatusCode::CONFLICT, format!("the job is {}", j.state)));
    }
    let nics = parse_report(&body);
    if nics.is_empty() {
        tracing::warn!(
            "add hardware: report without a network card on a PCI/USB bus:\n{}",
            body.chars().take(4000).collect::<String>()
        );
        return Err(bad("no network card on a PCI or USB bus in the report"));
    }
    let names: Vec<String> = nics
        .iter()
        .map(|n| format!("{} [{}]", n.name, n.instance))
        .collect();
    let token = j.token.clone();
    let sb = match secure_boot(&body) {
        Some(true) => " (Secure Boot on)",
        Some(false) => " (Secure Boot off)",
        None => "",
    };
    say(&st, &token, &format!("reported{sb}: {}", names.join(", ")));
    // The card the PC network-booted with (iPXE) must be among them: Windows PE without a driver for it, and no
    // network-class problem device either, would leave the golden without the card that matters.
    if !j.boot_card.is_empty() && !nics.iter().any(|n| is_boot_card(n, &j.boot_card)) {
        let e = format!(
            "Windows PE did not list the card this PC network-boots with ({}) - add its driver under Drivers, then Retry",
            j.boot_card
        );
        update(&st, &token, |j| j.nics = nics.clone());
        fail(&st, &token, &e);
        return Ok(e);
    }
    // Every card already in this golden (a PC like one done before): nothing to install, no new version.
    let known = hardware(&st).remove(&j.golden).unwrap_or_default();
    let have = |n: &Nic| {
        known
            .iter()
            .any(|h| h.instance.eq_ignore_ascii_case(&n.instance))
    };
    if nics.iter().all(have) {
        update(&st, &token, |j| {
            j.nics = nics.clone();
            j.state = "done".into();
        });
        say(
            &st,
            &token,
            &format!("already in {}: nothing to install", j.golden),
        );
        return Ok(format!("{} card(s), already in {}", nics.len(), j.golden));
    }
    update(&st, &token, |j| {
        j.nics = nics.clone();
        j.state = "installing".into();
    });
    let (st2, t2) = (st.clone(), token.clone());
    std::thread::spawn(move || worker(st2, t2));
    Ok(format!("{} card(s): {}", nics.len(), names.join(", ")))
}

/// GET /api/onboard/state?t= (public: Windows PE) — {state, msg}; an unknown token answers state "".
async fn state_q(
    State(st): State<SharedState>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    Query(q): Query<HashMap<String, String>>,
) -> Json<serde_json::Value> {
    match by_token(&st, &q, &peer.ip().to_canonical().to_string()) {
        Some(j) => Json(serde_json::json!({"state": j.state, "msg": j.msg})),
        None => Json(serde_json::json!({"state": "", "msg": "no such job"})),
    }
}

/// The waiting job's machine, asking from its own IP + MAC (iPXE).
fn job_machine(st: &SharedState, peer: &str) -> Result<(Job, Machine), String> {
    let j = job(st)
        .filter(|j| j.state == "waiting")
        .ok_or("no hardware job is waiting")?;
    let m = st
        .db
        .machines()
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|m| m.id == j.machine)
        .ok_or("the job's machine is gone")?;
    diskless::allowed_peer(&m, diskless::ip_of(st, &m).as_deref(), peer, || {
        crate::license::arp_mac(peer)
    })?;
    Ok((j, m))
}

/// GET /boot/onboard?golden=&mac=&ip= (public: iPXE) — Windows PE for the waiting job's machine.
async fn boot(
    State(st): State<SharedState>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let peer = peer.ip().to_canonical().to_string();
    let st2 = st.clone();
    let r = tokio::task::spawn_blocking(move || -> Result<String, String> {
        let (j, m) = job_machine(&st2, &peer)?;
        let g = diskless::goldens(&st2)
            .into_iter()
            .find(|g| g.name == j.golden)
            .ok_or("the golden is gone")?;
        winpe_dir(&st2, g.iso.as_deref().ok_or("the golden has no ISO")?)?;
        let card = q
            .get("busid")
            .and_then(|b| busid_card(b))
            .unwrap_or_default();
        let drivers = match crate::drivers::winpe_bundle(&st2) {
            Ok(b) => b.is_some(),
            Err(e) => {
                tracing::warn!("add hardware: network-card drivers not added to Windows PE: {e}");
                false
            }
        };
        update(&st2, &j.token, |j| j.boot_card = card.clone());
        let what = if card.is_empty() {
            String::new()
        } else {
            format!(" (network card {card})")
        };
        let with = if drivers {
            " with the library's network-card drivers"
        } else {
            ""
        };
        say(
            &st2,
            &j.token,
            &format!("{} boots Windows PE{with}{what}", who(&m)),
        );
        Ok(wimboot_script(&j.golden, &j.token, drivers))
    })
    .await
    .unwrap_or_else(|e| Err(e.to_string()));
    let body = match r {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("add hardware: boot refused: {e}");
            let e: String = e
                .chars()
                .filter(|c| c.is_ascii() && *c != '$' && *c != '\n')
                .collect();
            format!(
                "#!ipxe\necho {e}\nsleep 5\nchain /boot.ipxe?mac=${{net0/mac}}&ip=${{net0/ip}}\n"
            )
        }
    };
    ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], body).into_response()
}

/// GET /boot/onboard/{file}?t= (public: iPXE) — wimboot, the Windows PE files, startnet.cmd, broom-report.exe.
async fn file(
    State(st): State<SharedState>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    Path(name): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    req: axum::extract::Request,
) -> Result<Response, ApiError> {
    let peer = peer.ip().to_canonical().to_string();
    let (st2, n2, q2) = (st.clone(), name.clone(), q.clone());
    let (j, path) =
        tokio::task::spawn_blocking(move || -> Result<(Job, Option<PathBuf>), ApiError> {
            let (j, _) = job_machine(&st2, &peer).map_err(|e| (StatusCode::FORBIDDEN, e))?;
            if !q2.get("t").is_some_and(|t| token_matches(&j.token, t)) {
                return Err((StatusCode::FORBIDDEN, "wrong job".into()));
            }
            let iso = diskless::goldens(&st2)
                .into_iter()
                .find(|g| g.name == j.golden)
                .and_then(|g| g.iso)
                .ok_or((StatusCode::NOT_FOUND, "no ISO".to_string()))?;
            let path = WINPE_FILES
                .iter()
                .find(|(_, n)| *n == n2)
                .map(|(_, n)| winpe_dir(&st2, &iso).map(|d| d.join(n)))
                .transpose()
                .map_err(|e| (StatusCode::CONFLICT, e))?;
            Ok((j, path))
        })
        .await
        .map_err(ise)??;
    if let Some(p) = path {
        if name == "boot.wim" && j.winpe_at == 0 {
            let st2 = st.clone();
            let t = j.token.clone();
            tokio::task::spawn_blocking(move || {
                update(&st2, &t, |j| j.winpe_at = crate::now_secs())
            });
        }
        let res = tower_http::services::ServeFile::new(p)
            .try_call(req)
            .await
            .map_err(ise)?
            .map(Body::new);
        return Ok(res);
    }
    let text = |ct: &'static str, body: Vec<u8>| -> Response {
        ([(header::CONTENT_TYPE, ct)], body).into_response()
    };
    match name.as_str() {
        "wimboot" => Ok(text(
            "application/octet-stream",
            crate::assets::bytes("ipxe/wimboot").to_vec(),
        )),
        "broom-report.exe" => Ok(text(
            "application/octet-stream",
            reporter().ok_or((
                StatusCode::NOT_FOUND,
                "no broom-report.exe in this build".to_string(),
            ))?,
        )),
        "broom-drivers.tar" => {
            let b = tokio::task::spawn_blocking(move || crate::drivers::winpe_bundle(&st))
                .await
                .map_err(ise)?
                .map_err(ise)?
                .ok_or((
                    StatusCode::NOT_FOUND,
                    "no network-card driver in the library".to_string(),
                ))?;
            Ok(text("application/x-tar", b.as_ref().clone()))
        }
        "startnet.cmd" => {
            let srv = st.db.get_config("dhcp_server_ip", "");
            let cmd = startnet(
                &ipv4(Some(&srv)),
                &j.token,
                &ipv4(q.get("ip")),
                &ipv4(q.get("mask")),
                &ipv4(q.get("gw")),
            );
            Ok(text("text/plain", cmd.into_bytes()))
        }
        _ => Err((StatusCode::NOT_FOUND, "no such file".into())),
    }
}

#[cfg(test)]
#[path = "../tests/unit/onboard.rs"]
mod tests;
