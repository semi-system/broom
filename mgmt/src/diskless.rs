// diskless.rs — diskless goldens: whole-disk images (Windows by default, or Linux) that machines with no local disk boot
// straight from over iSCSI (the daemon side is iscsid/golden.rs).
//
// A golden starts blank. Its maintenance machine boots an installer from the ISO library with the golden attached,
// installs the OS, drivers and software onto it, then boots the golden itself to configure it; Save makes that work the
// golden's next version (every machine picks it up at its next boot), Discard throws it away. Each machine of the
// golden's groups (fixed IP required: its disk answers only that IP and MAC) gets its own layers on the writeback
// volume: base = its first-boot setup, kept while the version stays; session = everything else, wiped every boot.
//
// Why this design:
// - Broom's own mode boots Windows from each PC's SSD (a VHDX chain the stage lays out). A PC without an SSD needs its
//   whole disk from the server, the way commercial diskless systems work; this adds that mode next to the SSD one, on
//   Broom's own iSCSI engine (iscsid), so nothing else has to run on the server.
// - One golden for a room: an update is installed once and every machine gets it at its next boot. Layers are sparse
//   files of 64 KB blocks, so a machine costs only what it writes; no per-PC copy of the image.
// - Session layer wiped at every boot: each customer starts on a clean PC, as with the SSD mode.
// - Base layer per machine: what a machine must do once (its own computer name, its Remote agent key) is kept while the
//   golden version stays, instead of being redone at every boot; a new version builds it again (first boot + restart).
// - Fixed IP + MAC: a machine's disk is served only to its IP with its MAC behind it (ARP), so another PC on the LAN
//   cannot open (or reset) it by asking for its target name, and the PC needs no secret of its own.
// - Versions are kept and a group can be held on one (pins.rs): a new golden is checked on a test PC before the lounge
//   gets it, and going back is one click.
//
// Where things live — each on a volume chosen on the Diskless page ("" = broom's own folder):
//   golden_volume     <vol>/goldens/<name>/golden.img (+ its versions' layers)
//   writeback_volume  <vol>/diskless/<name>/<mac>/   (the machines' layers)
//   iso_volume        <vol>/isos/<file>.iso           (the installer library)
// Lists in the config table: diskless_goldens, isos (JSON).
use axum::{
    Json, Router,
    body::Body,
    extract::{Path, Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::SharedState;
use crate::api::{ApiError, bad, ise, ok};
use crate::db::Machine;
use crate::iscsid::golden;
use crate::machines::{clean_groups, for_group, machine_by_id, who};

pub fn routes() -> Router<SharedState> {
    Router::new()
        .route("/api/diskless", get(status))
        .route("/api/diskless/golden", post(upsert))
        .route("/api/diskless/golden/delete", post(delete))
        .route("/api/diskless/maint", post(set_maint))
        .route("/api/diskless/save", post(save))
        .route("/api/diskless/discard", post(discard))
        .route("/api/diskless/volume", post(set_volume))
        .route("/api/diskless/iso/upload-start", post(iso_start))
        .route(
            "/api/diskless/iso/upload-chunk",
            put(iso_chunk).layer(axum::extract::DefaultBodyLimit::max(
                crate::images::CHUNK_MAX,
            )),
        )
        .route("/api/diskless/iso/upload-done", post(iso_done))
        .route("/api/diskless/iso/os", post(iso_os))
        .route("/api/diskless/iso/delete", post(iso_delete))
        // Public (the machines themselves, by their IP + MAC): broom-diskless.ps1 / .sh inside the golden.
        .route("/broom-diskless.ps1", get(script))
        .route("/broom-diskless.sh", get(script_sh))
        .route("/api/diskless/client", get(client))
        .route("/api/diskless/client/base-done", post(base_done))
        .route("/api/diskless/client/agent-key", get(agent_key))
        // Public, for a golden's maintenance machine only: an Ubuntu installer it boots from the server.
        .route("/boot/iso/{golden}/{file}", get(iso_file))
        .route("/boot/nocloud/{golden}/{file}", get(nocloud))
}

pub const OSES: [&str; 2] = ["windows", "linux"];

fn default_os() -> String {
    "windows".into()
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Golden {
    pub name: String,
    #[serde(default = "default_os")]
    pub os: String,
    pub size_gb: u64,
    /// Installer ISO (file name in the library) its maintenance machine boots to install the OS.
    #[serde(default)]
    pub iso: Option<String>,
    /// Groups whose machines boot it diskless; empty = none.
    #[serde(default)]
    pub groups: Vec<String>,
    /// Its maintenance machine (machine id).
    #[serde(default)]
    pub maint: Option<i64>,
    #[serde(default)]
    pub ram: bool,
    /// Groups held on a version (group → version; a group not listed gets the newest): pins.rs.
    #[serde(default)]
    pub pins: std::collections::BTreeMap<String, u64>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Iso {
    /// File name in the library.
    pub name: String,
    #[serde(default = "default_os")]
    pub os: String,
    pub size: u64,
    /// Unix seconds.
    #[serde(default)]
    pub added: u64,
}

pub(crate) fn goldens(st: &SharedState) -> Vec<Golden> {
    serde_json::from_str(&st.db.get_config("diskless_goldens", "[]")).unwrap_or_default()
}

fn edit<R>(
    st: &SharedState,
    f: impl FnOnce(&mut Vec<Golden>) -> Result<R, ApiError>,
) -> Result<R, ApiError> {
    crate::db::edit_json(&*st.db, "diskless_goldens", f).map_err(ise)?
}

pub(crate) fn isos(st: &SharedState) -> Vec<Iso> {
    serde_json::from_str(&st.db.get_config("isos", "[]")).unwrap_or_default()
}

fn edit_isos<R>(
    st: &SharedState,
    f: impl FnOnce(&mut Vec<Iso>) -> Result<R, ApiError>,
) -> Result<R, ApiError> {
    crate::db::edit_json(&*st.db, "isos", f).map_err(ise)?
}

fn not_found(name: &str) -> ApiError {
    (StatusCode::NOT_FOUND, format!("golden {name} not found"))
}

/// 1-24 lower-case letters / digits / '-' (part of a target name and of folder names).
pub(crate) fn valid_name(n: &str) -> bool {
    (1..=24).contains(&n.len())
        && n.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !n.starts_with('-')
}

/// A plain file name ending in .iso: letters, digits, '.', '_', '-' (it is joined onto the library folder).
pub(crate) fn valid_iso(n: &str) -> bool {
    (5..=128).contains(&n.len())
        && n.to_ascii_lowercase().ends_with(".iso")
        && !n.starts_with('.')
        && n.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

fn os_ok(os: &str) -> Result<String, ApiError> {
    let os = os.trim().to_ascii_lowercase();
    if OSES.contains(&os.as_str()) {
        Ok(os)
    } else {
        Err(bad("os: windows or linux"))
    }
}

// ---------- where things live ----------

/// The three places, with their sub-folder on a volume.
pub(crate) const PLACES: [(&str, &str); 3] = [
    ("golden", "goldens"),
    ("writeback", "diskless"),
    ("iso", "isos"),
];

fn sub_of(kind: &str) -> Option<&'static str> {
    PLACES.iter().find(|(k, _)| *k == kind).map(|(_, s)| *s)
}

/// Volume id chosen for `kind` ("" = broom's own folder).
fn volume_of(st: &SharedState, kind: &str) -> String {
    st.db.get_config(&format!("{kind}_volume"), "")
}

/// Folder of `kind` ("golden" | "writeback" | "iso").
pub(crate) fn dir_of(st: &SharedState, kind: &str) -> Result<PathBuf, String> {
    let sub = sub_of(kind).ok_or_else(|| format!("unknown place {kind}"))?;
    match volume_of(st, kind).as_str() {
        "" => Ok(crate::home().join(sub)),
        id => crate::volumes::folder_on(st, id, sub),
    }
}

fn golden_img(st: &SharedState, name: &str) -> Result<PathBuf, String> {
    Ok(dir_of(st, "golden")?.join(name).join("golden.img"))
}

/// The golden's target name prefix: "<iqn_base>:golden-<name>"; version k = ".g<k>", machine = ".m<mac>".
pub(crate) fn iqn(st: &SharedState, name: &str) -> String {
    let base = st.db.get_config("iqn_base", "iqn.2026-01.local.broom");
    format!("{base}:golden-{name}")
}

/// Machine `m`'s own target on golden `name`.
pub(crate) fn machine_target(st: &SharedState, name: &str, m: &Machine) -> Option<String> {
    golden::machine_iqn(&iqn(st, name), &m.mac)
}

/// The machines that boot golden `g` diskless: in one of its groups, with a fixed IP (their disk answers only it).
pub(crate) fn machines_of<'a>(g: &Golden, all: &'a [Machine]) -> Vec<&'a Machine> {
    all.iter()
        .filter(|m| !g.groups.is_empty() && for_group(&g.groups, m.grp.as_deref()))
        .filter(|m| m.ip.as_deref().is_some_and(|ip| !ip.is_empty()))
        .collect()
}

/// IP of a machine: its fixed IP, else its DHCP lease.
pub(crate) fn ip_of(st: &SharedState, m: &Machine) -> Option<String> {
    m.ip.clone().filter(|i| !i.is_empty()).or_else(|| {
        st.db
            .leases()
            .ok()?
            .into_iter()
            .find(|l| l.mac.eq_ignore_ascii_case(&m.mac))
            .and_then(|l| l.ip)
    })
}

fn configs(st: &SharedState) -> Result<Vec<golden::Config>, String> {
    let wb = dir_of(st, "writeback")?;
    let all = st.db.machines().map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for g in goldens(st) {
        let path = golden_img(st, &g.name)?;
        if !path.exists() {
            continue;
        }
        let maint = g.maint.and_then(|id| all.iter().find(|m| m.id == id));
        // "Add hardware" (onboard.rs) running: its VM on this server writes the golden, through 127.0.0.1 (no LAN
        // host can send from the loopback address).
        // Same for the maintenance VM (vmmaint.rs, Maintain in the browser).
        let (update_ip, update_mac) =
            if crate::onboard::vm_owns(&g.name) || crate::vmmaint::owns_golden(&g.name) {
                (Some("127.0.0.1".to_string()), None)
            } else {
                (
                    maint.and_then(|m| ip_of(st, m)),
                    maint.map(|m| m.mac.to_lowercase()),
                )
            };
        out.push(golden::Config {
            disk: crate::iscsid::games::Config {
                name: g.name.clone(),
                iqn: iqn(st, &g.name),
                path: path.to_string_lossy().into(),
                update_ip,
                update_mac,
                ram: g.ram,
                reserve: crate::publish::ram_reserve(st),
                retain: true,
                min_free_pct: crate::pins::min_free_pct(st),
                keep_from: crate::pins::keep_from(&g.pins),
            },
            dir: wb.join(&g.name).to_string_lossy().into(),
            machines: machines_of(&g, &all)
                .into_iter()
                .map(|m| golden::Machine {
                    mac: m.mac.clone(),
                    ip: m.ip.clone().unwrap_or_default(),
                })
                .collect(),
            games: false,
        });
    }
    // Games disks for the diskless Windows machines: each its own copy (golden.rs Config.games), its writes kept on
    // the server until its next PXE boot. Their layers: <writeback>/.games-<disk>/<mac>/.
    let dl = diskless_windows_machines(st, &all);
    for (c, groups) in crate::games::with_groups(st) {
        let machines: Vec<golden::Machine> = dl
            .iter()
            .filter(|m| for_group(&groups, m.grp.as_deref()))
            .map(|m| golden::Machine {
                mac: m.mac.clone(),
                ip: m.ip.clone().unwrap_or_default(),
            })
            .collect();
        if machines.is_empty() {
            continue;
        }
        out.push(golden::Config {
            dir: wb
                .join(format!(".games-{}", c.name))
                .to_string_lossy()
                .into(),
            disk: c,
            machines,
            games: true,
        });
    }
    Ok(out)
}

/// The machines that boot a Windows golden diskless (each once).
pub(crate) fn diskless_windows_machines<'a>(
    st: &SharedState,
    all: &'a [Machine],
) -> Vec<&'a Machine> {
    let mut out: Vec<&Machine> = Vec::new();
    for g in goldens(st).iter().filter(|g| g.os == "windows") {
        for m in machines_of(g, all) {
            if !out.iter().any(|x| x.id == m.id) {
                out.push(m);
            }
        }
    }
    out
}

/// Why the goldens are not served (last sync); None = fine.
static LAST_ERR: parking_lot::Mutex<Option<String>> = parking_lot::Mutex::new(None);

/// Push the goldens to the iSCSI daemon (at start, on change, every minute: a maintenance machine's lease may move).
/// Blocking.
pub fn sync(st: &SharedState) -> Result<(), String> {
    let r = configs(st).and_then(|list| {
        if list.is_empty() && crate::iscsi::diskless_status().is_none() {
            Ok(()) // nothing to serve, no daemon to tell
        } else {
            crate::iscsi::diskless_set(list)
        }
    });
    let mut last = LAST_ERR.lock();
    match &r {
        Err(e) if last.as_deref() != Some(e.as_str()) => {
            tracing::warn!("diskless goldens not served: {e}")
        }
        Ok(()) if last.is_some() => tracing::info!("diskless goldens served again"),
        _ => {}
    }
    *last = r.as_ref().err().cloned();
    r
}

async fn sync_now(st: SharedState) -> Result<(), ApiError> {
    tokio::task::spawn_blocking(move || sync(&st))
        .await
        .map_err(ise)?
        .map_err(|e| (StatusCode::CONFLICT, e))
}

/// Every golden's pins through `f` (pins.rs), as one step.
pub(crate) fn edit_pins(
    st: &SharedState,
    f: &dyn Fn(&Golden) -> std::collections::BTreeMap<String, u64>,
) -> Result<(), ApiError> {
    edit(st, |list| {
        for g in list.iter_mut() {
            g.pins = f(g);
        }
        Ok(())
    })
}

/// Groups page: every golden's groups through `f` (name, groups → new groups), as one step. No group = no machine.
pub(crate) fn edit_groups(
    st: &SharedState,
    f: &dyn Fn(&str, &[String]) -> Vec<String>,
) -> Result<(), ApiError> {
    edit(st, |list| {
        for g in list.iter_mut() {
            g.groups = f(&g.name, &g.groups);
        }
        Ok(())
    })
}

/// Machine `m` was deleted: no longer any golden's maintenance machine, its layers of every golden deleted. Blocking.
pub(crate) fn forget_machine(st: &SharedState, m: &Machine) {
    let all = goldens(st);
    let _ = edit(st, |list| {
        for g in list.iter_mut().filter(|g| g.maint == Some(m.id)) {
            g.maint = None;
        }
        Ok(())
    });
    if all.is_empty() {
        return;
    }
    for (c, _) in crate::games::with_groups(st) {
        let _ = crate::iscsi::diskless_games_forget(&c.name, &m.mac);
    }
    let _ = sync(st);
    for g in &all {
        if let Err(e) = crate::iscsi::diskless_forget(&g.name, &m.mac) {
            tracing::warn!("golden {}: layers of {} not deleted: {e}", g.name, who(m));
        }
    }
}

// ---------- each machine's base layer (its own first-boot setup) ----------

/// Per machine and golden (config `diskless:<golden>:<mac>`): the first-boot setup Windows reported done, and what the
/// base was built with — a new name or licence makes it be set up again.
#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
pub(crate) struct BaseState {
    /// The golden version whose first boot finished its setup (broom-diskless.ps1): kept as the base at the next boot.
    #[serde(default)]
    pub pending: Option<u64>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub lic: i64,
    /// Fingerprint of the machine's agent key the base was built with (agentauth.rs; Windows goldens): the key lives
    /// in the base, so a new key — or a base from before agents came to diskless machines — means building it again.
    #[serde(default)]
    pub akey: String,
}

fn base_key(golden: &str, mac: &str) -> String {
    format!(
        "diskless:{golden}:{}",
        golden::mac12(mac).unwrap_or_default()
    )
}

fn base_state(st: &SharedState, golden: &str, mac: &str) -> BaseState {
    serde_json::from_str(&st.db.get_config(&base_key(golden, mac), "{}")).unwrap_or_default()
}

fn set_base_state(st: &SharedState, golden: &str, mac: &str, b: &BaseState) {
    let _ = st
        .db
        .set_config(&base_key(golden, mac), &serde_json::to_string(b).unwrap());
}

/// This boot's plan for a machine's layers: (promote the last session to its base, drop its base). Promote when its
/// first boot on the version it was on reported its setup done; drop the base when the machine's name, licence or
/// agent key changed since the base was built (the golden version changing drops it anyway, in the daemon).
pub(crate) fn base_plan(
    s: &BaseState,
    session_ver: Option<u64>,
    has_base: bool,
    host: Option<&str>,
    lic: i64,
    akey: &str,
) -> (bool, bool) {
    let promote = s.pending.is_some() && s.pending == session_ver;
    let drop =
        !promote && has_base && (s.host.as_deref() != host || s.lic != lic || s.akey != akey);
    (promote, drop)
}

// ---------- boot (boot.rs) ----------

/// A boot menu entry: its text, the URL it chains to (mac / ip appended), and whether it is the default.
pub(crate) struct MenuEntry {
    pub text: String,
    pub chain: String,
    pub default: bool,
}

/// Target name of library ISO `iso` served as a DVD-ROM: "<iqn_base>:iso-<name>" (lower-case letters / digits / '-').
pub(crate) fn iso_iqn(st: &SharedState, iso: &str) -> String {
    let base = st.db.get_config("iqn_base", "iqn.2026-01.local.broom");
    let n: String = iso
        .trim_end_matches(".iso")
        .trim_end_matches(".ISO")
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    format!("{base}:iso-{n}")
}

/// The golden's state in the daemon (None = not served).
pub(crate) fn served(name: &str) -> Option<golden::Info> {
    crate::iscsi::diskless_status()
        .unwrap_or_default()
        .into_iter()
        .find(|i| !i.games && i.disk.name == name)
}

/// Machine `mac`'s own copy of games disk `name` as the daemon serves it (None = not served to it).
pub(crate) fn games_served(name: &str, mac: &str) -> Option<golden::MachineInfo> {
    let mac = golden::mac12(mac)?;
    crate::iscsi::diskless_status()?
        .into_iter()
        .find(|i| i.games && i.disk.name == name)?
        .machines
        .into_iter()
        .find(|m| m.mac == mac)
}

/// Nothing written to it yet: no version saved, no maintenance work — a blank disk to install onto.
fn blank(i: &golden::Info) -> bool {
    i.disk.ver == 0 && i.disk.layers == 0 && i.disk.update_bytes == 0
}

/// Machine `m`'s entries: Install / Maintain for each golden it maintains (Install is the default while the golden is
/// blank, Maintain once the installer wrote to it — the installer's own restarts go on by themselves), then each golden
/// it boots diskless (the first is the default unless it maintains one). Blocking (asks the daemon).
pub(crate) fn menu_entries(st: &SharedState, m: &Machine) -> Vec<MenuEntry> {
    let (mut maint, mut diskless): (Vec<MenuEntry>, Vec<MenuEntry>) = (Vec::new(), Vec::new());
    // "Add hardware" waiting for this machine: Windows PE first (it is why the admin started the job).
    maint.extend(crate::onboard::menu_entry(st, m));
    let all = st.db.machines().unwrap_or_default();
    for g in goldens(st) {
        let Some(info) = served(&g.name) else {
            continue;
        };
        if g.maint == Some(m.id) {
            let out = &mut maint;
            let fresh = blank(&info);
            if let Some(iso) = &g.iso {
                out.push(MenuEntry {
                    // The ISO last: a long name is cut at the menu's edge.
                    text: format!("Install {} (maintenance) from {iso}", g.name),
                    chain: format!("/boot/maint?golden={}&do=install", g.name),
                    default: fresh,
                });
            }
            out.push(MenuEntry {
                text: format!("Maintain {} (maintenance, saved with Save)", g.name),
                chain: format!("/boot/maint?golden={}&do=boot", g.name),
                default: !fresh || g.iso.is_none(),
            });
        } else if machines_of(&g, &all).iter().any(|x| x.id == m.id) {
            diskless.push(MenuEntry {
                text: format!("{} (diskless)", g.name),
                chain: format!("/boot/diskless?golden={}", g.name),
                default: true,
            });
        }
    }
    ordered(maint, diskless)
}

/// Maintenance entries first (its work is why it is on), then diskless ones; one default at most: the first marked.
pub(crate) fn ordered(mut maint: Vec<MenuEntry>, mut diskless: Vec<MenuEntry>) -> Vec<MenuEntry> {
    maint.append(&mut diskless);
    let mut seen = false;
    for e in maint.iter_mut().filter(|e| e.default) {
        if seen {
            e.default = false;
        }
        seen = true;
    }
    maint
}

/// The request comes from machine `m` itself: from its IP, with its MAC behind it (ARP) — these boot URLs are open
/// and reset its session / close its sessions, so another PC must not trigger them for it.
fn from_machine(m: &Machine, ip: Option<&str>, peer: &str) -> Result<(), String> {
    allowed_peer(m, ip, peer, || crate::license::arp_mac(peer))
}

pub(crate) fn allowed_peer(
    m: &Machine,
    ip: Option<&str>,
    peer: &str,
    arp: impl FnOnce() -> Option<String>,
) -> Result<(), String> {
    if ip != Some(peer) {
        return Err(format!(
            "{} must boot from its own IP ({}), not {peer}",
            who(m),
            ip.unwrap_or("none")
        ));
    }
    let seen = arp().and_then(|a| golden::mac12(&a));
    if seen.is_none() || seen != golden::mac12(&m.mac) {
        return Err(format!("{peer} is not {}'s network card", who(m)));
    }
    Ok(())
}

fn iscsi_uri(st: &SharedState, iqn: &str) -> String {
    format!("iscsi:{}::::{iqn}", st.db.get_config("dhcp_server_ip", ""))
}

/// iPXE line put before a Windows disk boot from `client` (its IP): the iBFT gets no gateway when the server is on the
/// client's subnet. Windows booted from iSCSI turns the iBFT's gateway into a host route to its disk's server through
/// that gateway (Microsoft's design: a gateway on the boot NIC is taken as needed to reach the target), also when the
/// server is on the same subnet. Every disk read then goes through the router, and a router with connection tracking
/// drops Windows' new connections to the server, since the server's replies come straight back (seen with a router
/// doing that: the startup script never reached the server, no agent, no games disk). Without a gateway Windows talks
/// to the server directly and gets the router from its own DHCP later, once its disk is connected.
/// See lists.ipxe.org/pipermail/ipxe-devel/2011-February/000286.html.
pub(crate) fn ibft_gateway_line(os: &str, server: &str, client: &str) -> &'static str {
    if os == "windows" && crate::tls::on_subnet_of(server, client) {
        "set net0/gateway 0.0.0.0\n"
    } else {
        ""
    }
}

/// The router each machine (MAC, lower case) was given by the LAN's DHCP, when its last boot left it out of the iBFT
/// (ibft_gateway_line): Windows then has no default route, and its startup script adds this one once Windows runs
/// (GET /api/diskless/client "gateway"; not kept: a route of that boot only).
static ROUTERS: parking_lot::Mutex<std::collections::BTreeMap<String, String>> =
    parking_lot::Mutex::new(std::collections::BTreeMap::new());

/// Remember (or forget) machine `mac`'s router for its startup script: kept only when this boot's script left the
/// gateway out (`line` non-empty) and iPXE reported a valid IPv4 router from the LAN's DHCP.
pub(crate) fn note_router(mac: &str, line: &str, router: Option<&str>) {
    let mac = mac.to_lowercase();
    let r = router.map(str::trim).filter(|r| {
        r.parse::<std::net::Ipv4Addr>()
            .is_ok_and(|ip| !ip.is_unspecified())
    });
    match (line.is_empty(), r) {
        (false, Some(r)) => {
            ROUTERS.lock().insert(mac, r.to_string());
        }
        _ => {
            ROUTERS.lock().remove(&mac);
        }
    }
}

/// Machine `mac`'s router for its startup script (note_router), if its boot left it out of the iBFT.
pub(crate) fn router_of(mac: &str) -> Option<String> {
    ROUTERS.lock().get(&mac.to_lowercase()).cloned()
}

/// EFI loaders a Linux golden is booted from, the first one found: its distribution's shim. Booting such a disk from
/// its default \EFI\BOOT\BOOTX64.EFI runs shim's fallback instead, which adds a firmware boot entry for the disk and
/// restarts the PC — at every boot, since the disk is gone without the network boot (seen with Ubuntu 26.04).
pub(crate) const LINUX_LOADERS: [&str; 8] = [
    r"\EFI\ubuntu\shimx64.efi",
    r"\EFI\debian\shimx64.efi",
    r"\EFI\fedora\shimx64.efi",
    r"\EFI\redhat\shimx64.efi",
    r"\EFI\rocky\shimx64.efi",
    r"\EFI\almalinux\shimx64.efi",
    r"\EFI\centos\shimx64.efi",
    r"\EFI\opensuse\shim.efi",
];

/// iPXE lines booting disk `uri` as drive 0x80 (the iBFT tells the OS where its disk is): Windows from the disk's
/// default loader; Linux from its distribution's loader (LINUX_LOADERS, each `sanboot` fails fast when the file is not
/// there), else the default one.
pub(crate) fn san_boot(os: &str, uri: &str) -> String {
    if os != "linux" {
        return format!("sanboot --drive 0x80 {uri} || goto failed");
    }
    let tries: Vec<String> = LINUX_LOADERS
        .iter()
        .map(|f| format!("sanboot --drive 0x80 --filename {f}"))
        .collect();
    format!(
        "sanhook --drive 0x80 {uri} || goto failed\n{} || sanboot --drive 0x80 || goto failed",
        tries.join(" || ")
    )
}

/// Ubuntu's installers (casper) boot their live system from a medium they can find: not a DVD over iSCSI, as their
/// initramfs does not log in to iSCSI. Broom boots such an ISO's kernel + initrd itself; the live system then fetches
/// the whole ISO over HTTP (url=, into RAM: the machine needs ~4 GB more than the ISO) and its autoinstall seed
/// (ds=nocloud): log in to the golden (iBFT) before the disks are probed, make the installed system's initramfs log
/// in to its disk the same way, and install broom-diskless.sh. Every installer screen still asks as usual.
/// Extracted once per ISO into `<library>/.boot/<iso>/`. Ok(None) = not such an ISO (it boots as a DVD).
pub(crate) fn casper_files(
    st: &SharedState,
    iso: &str,
) -> Result<Option<(PathBuf, PathBuf)>, String> {
    let lib = dir_of(st, "iso")?;
    let src = lib.join(iso);
    let dir = lib.join(".boot").join(iso);
    let (k, i) = (dir.join("vmlinuz"), dir.join("initrd"));
    if k.is_file() && i.is_file() {
        return Ok(Some((k, i)));
    }
    if crate::iso9660::find(&src, "casper/vmlinuz")
        .ok()
        .flatten()
        .is_none()
    {
        return Ok(None);
    }
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    for (from, to) in [("casper/vmlinuz", &k), ("casper/initrd", &i)] {
        if !crate::iso9660::extract(&src, from, to, 1 << 30).map_err(|e| e.to_string())? {
            return Ok(None);
        }
    }
    tracing::info!(
        "ISO library: {iso} boots as an Ubuntu installer (kernel + initrd taken from it)"
    );
    Ok(Some((k, i)))
}

/// iPXE body: the golden attached as drive 0x80, Ubuntu's installer booted from the ISO's own kernel + initrd.
pub(crate) fn casper_script(name: &str, disk: &str, srv: &str) -> String {
    let http = format!("http://{srv}");
    format!(
        "sanhook --drive 0x80 {disk} || goto failed\n\
         kernel /boot/iso/{name}/vmlinuz initrd=initrd ip=dhcp url={http}/boot/iso/{name}/installer.iso \
         cloud-config-url=/dev/null ds=nocloud;s={http}/boot/nocloud/{name}/ --- || goto failed\n\
         initrd --name initrd /boot/iso/{name}/initrd || goto failed\n\
         boot || goto failed"
    )
}

/// The autoinstall seed of a golden's Ubuntu install (user-data). Interactive: only adds steps around the screens.
pub(crate) fn nocloud_user_data(srv: &str) -> String {
    format!(
        "#cloud-config\n\
         autoinstall:\n\
         \x20 version: 1\n\
         \x20 interactive-sections: [\"*\"]\n\
         \x20 early-commands:\n\
         \x20   - modprobe iscsi_ibft\n\
         \x20   - iscsistart -b\n\
         \x20 late-commands:\n\
         \x20   - \"curtin in-target --target=/target -- sh -c 'curl -fsS http://{srv}/broom-diskless.sh | sh'\"\n"
    )
}

/// An iPXE script that boots `body`, else says why and goes back to the menu.
/// Drives 0x80 / 0x81 are let go first and on failure: a drive left hooked by a failed try (an installer DVD whose
/// "press a key" passed unanswered, an unreachable disk) makes every later try in the same iPXE fail with "Address
/// already in use" (seen live) until the PC restarts.
fn boot_script(body: &str, what: &str) -> String {
    const UNHOOK: &str = "sanunhook --drive 0x80 ||\nsanunhook --drive 0x81 ||\n";
    format!(
        "#!ipxe\n{UNHOOK}{body}\n:failed\n{UNHOOK}echo Could not boot {what} from the server\nsleep 5\n\
         chain /boot.ipxe?mac=${{net0/mac}}&ip=${{net0/ip}}\n"
    )
}

/// Diskless machine `m` is booting: its copy of every games disk of its group starts over from the disk's newest
/// version. A failure leaves that disk off this boot (logged). Blocking.
fn prepare_games(st: &SharedState, m: &Machine) {
    for (c, groups) in crate::games::with_groups(st) {
        if !for_group(&groups, m.grp.as_deref()) {
            continue;
        }
        let pin = crate::games::disks(st)
            .into_iter()
            .find(|d| d.name == c.name)
            .and_then(|d| crate::pins::pin_for(&d.pins, m.grp.as_deref()));
        let mut r = Err(String::new());
        for i in 0..30 {
            r = crate::iscsi::diskless_games_prepare(&c.name, &m.mac, pin);
            match &r {
                Err(e) if e.contains("still connected") && i < 29 => {
                    std::thread::sleep(std::time::Duration::from_millis(200))
                }
                _ => break,
            }
        }
        match r {
            Ok(p) => tracing::info!("games disk {}: {}'s own copy on g{}", c.name, who(m), p.ver),
            Err(e) => tracing::warn!("games disk {}: {}'s copy not prepared: {e}", c.name, who(m)),
        }
    }
}

/// Machine `m` boots golden `name` diskless: its earlier sessions closed, its session layer reset (its base kept while
/// the golden version stays), then iPXE boots its own target (the iBFT tells Windows / Linux where its disk is).
/// Blocking.
pub(crate) fn boot_diskless(
    st: &SharedState,
    name: &str,
    m: &Machine,
    peer: &str,
    router: Option<&str>,
) -> Result<String, String> {
    from_machine(m, m.ip.as_deref(), peer)?;
    let g = goldens(st)
        .into_iter()
        .find(|g| g.name == name)
        .ok_or_else(|| format!("no golden {name}"))?;
    let all = st.db.machines().map_err(|e| e.to_string())?;
    if !machines_of(&g, &all).iter().any(|x| x.id == m.id) {
        return Err(format!(
            "golden {name} is not for this machine (its groups, a fixed IP)"
        ));
    }
    if let Some(ip) = m.ip.as_deref() {
        let _ = crate::iscsi::kick_peer(ip); // its previous boot's sessions (it is in its boot menu now)
    }
    let mine = served(name).and_then(|i| {
        let mac = golden::mac12(&m.mac)?;
        i.machines.into_iter().find(|x| x.mac == mac)
    });
    let bs = base_state(st, name, &m.mac);
    // Windows: the Remote agent's key goes into the base (made now if the machine has none); Linux has no agent.
    let akey = if g.os == "windows" {
        crate::agentauth::ensure(st, &m.mac)?
    } else {
        bs.akey.clone()
    };
    let (promote, drop_base) = base_plan(
        &bs,
        mine.as_ref().and_then(|x| x.session_ver),
        mine.as_ref().is_some_and(|x| x.base_ver.is_some()),
        m.hostname.as_deref(),
        m.license_gen,
        &akey,
    );
    let mut p = None;
    for i in 0..30 {
        match crate::iscsi::diskless_prepare(
            name,
            &m.mac,
            promote,
            drop_base,
            crate::pins::pin_for(&g.pins, m.grp.as_deref()),
        ) {
            Ok(x) => {
                p = Some(x);
                break;
            }
            Err(e) if e.contains("still connected") && i < 29 => {
                std::thread::sleep(std::time::Duration::from_millis(200))
            }
            Err(e) => return Err(e),
        }
    }
    let p = p.ok_or("still connected")?;
    // Its own copy of each games disk it gets (Windows): the newest version again, last boot's writes dropped.
    if g.os == "windows" {
        prepare_games(st, m);
    }
    if bs.pending.is_some() || drop_base {
        // Promoted (or not: an older version's setup) — either way that report is used up; a dropped base starts over.
        let keep = BaseState {
            pending: None,
            ..if drop_base { BaseState::default() } else { bs }
        };
        set_base_state(st, name, &m.mac, &keep);
    }
    if promote {
        tracing::info!("golden {name}: {}'s first boot kept as its base", who(m));
    }
    let t = machine_target(st, name, m).ok_or("bad MAC")?;
    tracing::info!(
        "golden {name}: {} boots diskless on g{}{}",
        who(m),
        p.ver,
        if p.first {
            " (first boot on this version)"
        } else {
            ""
        }
    );
    let gw = ibft_gateway_line(&g.os, &st.db.get_config("dhcp_server_ip", ""), peer);
    note_router(&m.mac, gw, router);
    Ok(boot_script(
        &format!(
            "echo Booting {name} from the server (diskless)...\n{gw}{}",
            san_boot(&g.os, &iscsi_uri(st, &t))
        ),
        name,
    ))
}

/// Maintenance machine `m` works on golden `name`: `install` = the golden attached (blank disk) and the golden's
/// installer ISO booted as a DVD; `boot` = the golden itself. Both writable for it only (the daemon checks its IP + MAC);
/// Save makes the work the golden's next version. Blocking.
pub(crate) fn boot_maint(
    st: &SharedState,
    name: &str,
    what: &str,
    m: &Machine,
    peer: &str,
    router: Option<&str>,
) -> Result<String, String> {
    from_machine(m, ip_of(st, m).as_deref(), peer)?;
    let g = goldens(st)
        .into_iter()
        .find(|g| g.name == name)
        .ok_or_else(|| format!("no golden {name}"))?;
    if g.maint != Some(m.id) {
        return Err(format!(
            "{} is not the maintenance machine of {name}",
            who(m)
        ));
    }
    let info = served(name).ok_or_else(|| format!("golden {name} is not served"))?;
    let disk = iscsi_uri(st, &format!("{}.g{}", iqn(st, name), info.disk.ver));
    let gw = ibft_gateway_line(&g.os, &st.db.get_config("dhcp_server_ip", ""), peer);
    note_router(&m.mac, gw, router);
    if let Some(ip) = ip_of(st, m) {
        let _ = crate::iscsi::kick_peer(&ip); // its previous boot's sessions: their writes are flushed
    }
    match what {
        "install" => {
            let iso = g
                .iso
                .clone()
                .ok_or("no installer ISO chosen for this golden")?;
            let path = dir_of(st, "iso")?.join(&iso);
            if !path.is_file() {
                return Err(format!("ISO {iso} is not in the library folder"));
            }
            if g.os == "linux" && casper_files(st, &iso)?.is_some() {
                tracing::info!(
                    "golden {name}: {} installs from {iso} (Ubuntu installer)",
                    who(m)
                );
                return Ok(boot_script(
                    &format!(
                        "echo Installing onto {name} from {iso}: the installer loads it from the server first\n{}",
                        casper_script(name, &disk, &st.db.get_config("dhcp_server_ip", ""))
                    ),
                    &iso,
                ));
            }
            let t = iso_iqn(st, &iso);
            crate::iscsi::export_cd(&t, &path.to_string_lossy())?;
            tracing::info!("golden {name}: {} installs from {iso}", who(m));
            Ok(boot_script(
                &format!(
                    "echo Installing onto {name} from {iso}\n\
                     echo If the installer asks to press a key to boot from CD/DVD, press one now.\n\
                     {gw}sanhook --drive 0x80 {disk} || goto failed\n\
                     sanboot --drive 0x81 {} || goto failed",
                    iscsi_uri(st, &t)
                ),
                &iso,
            ))
        }
        "boot" => {
            tracing::info!("golden {name}: {} boots it for maintenance", who(m));
            Ok(boot_script(
                &format!(
                    "echo Booting {name} for maintenance (writable)...\n{gw}{}",
                    san_boot(&g.os, &disk)
                ),
                name,
            ))
        }
        _ => Err("do: install or boot".into()),
    }
}

// ---------- the machine itself (broom-diskless.ps1) ----------

/// broom-diskless.ps1 with this server's address: what a golden gets installed (and runs at every start).
pub(crate) fn script_text(st: &SharedState) -> String {
    let srv = st.db.get_config("dhcp_server_ip", "");
    crate::assets::text("scripts/broom-diskless.ps1").replace("__SERVER__", &srv)
}

/// GET /broom-diskless.ps1 — the script installed on a golden (irm … | iex), with this server's address.
async fn script(
    State(st): State<SharedState>,
) -> ([(axum::http::HeaderName, &'static str); 1], String) {
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; charset=utf-8",
        )],
        script_text(&st),
    )
}

/// GET /broom-diskless.sh — the same for Linux goldens (curl … | sudo sh; Broom's Ubuntu installs run it themselves).
async fn script_sh(
    State(st): State<SharedState>,
) -> ([(axum::http::HeaderName, &'static str); 1], String) {
    let srv = st.db.get_config("dhcp_server_ip", "");
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; charset=utf-8",
        )],
        crate::assets::text("scripts/broom-diskless.sh").replace("__SERVER__", &srv),
    )
}

/// The golden `name` whose maintenance machine is asking (its IP + MAC), for the installer files it boots.
fn maint_asking(st: &SharedState, name: &str, peer: &str) -> Result<Golden, ApiError> {
    let g = goldens(st)
        .into_iter()
        .find(|g| g.name == name)
        .ok_or_else(|| not_found(name))?;
    let m = g.maint.and_then(|id| machine_by_id(st, id).ok()).ok_or((
        StatusCode::FORBIDDEN,
        format!("golden {name} has no maintenance machine"),
    ))?;
    from_machine(&m, ip_of(st, &m).as_deref(), peer).map_err(|e| (StatusCode::FORBIDDEN, e))?;
    Ok(g)
}

/// GET /boot/iso/{golden}/{vmlinuz|initrd|installer.iso} — the golden's installer (casper_files), for its maintenance
/// machine only.
async fn iso_file(
    State(st): State<SharedState>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    Path((name, file)): Path<(String, String)>,
    req: axum::extract::Request,
) -> Result<Response, ApiError> {
    let peer = peer.ip().to_canonical().to_string();
    let st2 = st.clone();
    let path = tokio::task::spawn_blocking(move || -> Result<PathBuf, ApiError> {
        let g = maint_asking(&st2, &name, &peer)?;
        let iso = g.iso.ok_or_else(|| bad("no installer ISO chosen"))?;
        let (k, i) = casper_files(&st2, &iso)
            .map_err(ise)?
            .ok_or_else(|| bad("not an Ubuntu installer ISO"))?;
        match file.as_str() {
            "vmlinuz" => Ok(k),
            "initrd" => Ok(i),
            "installer.iso" => Ok(dir_of(&st2, "iso").map_err(ise)?.join(&iso)),
            _ => Err((StatusCode::NOT_FOUND, "no such file".into())),
        }
    })
    .await
    .map_err(ise)??;
    let res = tower_http::services::ServeFile::new(path)
        .try_call(req)
        .await
        .map_err(ise)?
        .map(Body::new);
    Ok(res)
}

/// GET /boot/nocloud/{golden}/{meta-data|user-data|vendor-data} — the autoinstall seed of the golden's Ubuntu install
/// (nocloud_user_data), for its maintenance machine only.
async fn nocloud(
    State(st): State<SharedState>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    Path((name, file)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let peer = peer.ip().to_canonical().to_string();
    let st2 = st.clone();
    let n = name.clone();
    tokio::task::spawn_blocking(move || maint_asking(&st2, &n, &peer))
        .await
        .map_err(ise)??;
    let body = match file.as_str() {
        "meta-data" => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            format!("instance-id: broom-{name}-{now}\n")
        }
        "user-data" => nocloud_user_data(&st.db.get_config("dhcp_server_ip", "")),
        "vendor-data" => String::new(),
        _ => return Err((StatusCode::NOT_FOUND, "no such file".into())),
    };
    Ok(([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], body).into_response())
}

/// The registered machine asking, by the connection's IP with its MAC behind it, and the golden it runs now.
fn asking(
    st: &SharedState,
    peer: &str,
) -> Result<(Machine, Option<(String, golden::MachineInfo)>), ApiError> {
    let m = crate::machines::machine_at(st, peer).ok_or((
        StatusCode::NOT_FOUND,
        "not a registered machine".to_string(),
    ))?;
    from_machine(&m, m.ip.as_deref(), peer).map_err(|e| (StatusCode::FORBIDDEN, e))?;
    let mac = golden::mac12(&m.mac).unwrap_or_default();
    let all = st.db.machines().map_err(ise)?;
    let on = goldens(st)
        .into_iter()
        .filter(|g| machines_of(g, &all).iter().any(|x| x.id == m.id))
        .find_map(|g| {
            let i = served(&g.name)?;
            let x = i
                .machines
                .into_iter()
                .find(|x| x.mac == mac && x.connected)?;
            Some((g.name, x))
        });
    Ok((m, on))
}

/// GET /api/diskless/client[?fmt=env] (public) — what the asking machine is: role diskless (with its golden version,
/// whether this boot is its first on that version, its name) / maintenance / none. fmt=env: KEY=value lines for
/// broom-diskless.sh.
async fn client(
    State(st): State<SharedState>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Result<Response, ApiError> {
    // The maintenance VM on this server (vmmaint.rs): reaches us through QEMU's NAT, from our own address.
    if let Some(v) = crate::vmmaint::client_answer(&st, peer.ip().to_canonical()) {
        return Ok(Json(v).into_response());
    }
    let peer = peer.ip().to_canonical().to_string();
    let st2 = st.clone();
    let (m, on) = tokio::task::spawn_blocking(move || asking(&st2, &peer))
        .await
        .map_err(ise)??;
    let v = if let Some((g, x)) = on {
        let first = x.base_ver.is_none() || x.base_ver != x.session_ver;
        serde_json::json!({
            "role": "diskless", "golden": g, "ver": x.session_ver, "first": first, "host": m.hostname,
            "gateway": router_of(&m.mac),
        })
    } else {
        let role = if goldens(&st).iter().any(|g| g.maint == Some(m.id)) {
            "maintenance"
        } else {
            "none"
        };
        serde_json::json!({"role": role, "host": m.hostname, "gateway": router_of(&m.mac)})
    };
    if q.get("fmt").map(String::as_str) == Some("env") {
        return Ok((
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            client_env(&v),
        )
            .into_response());
    }
    Ok(Json(v).into_response())
}

/// `client`'s answer as KEY=value lines a shell reads with sed (values cut to letters, digits, '-', '.', '_').
pub(crate) fn client_env(v: &serde_json::Value) -> String {
    let s = |k: &str| -> String {
        let raw = match &v[k] {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Bool(b) => (if *b { "1" } else { "0" }).into(),
            serde_json::Value::Number(n) => n.to_string(),
            _ => String::new(),
        };
        raw.chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_'))
            .take(64)
            .collect()
    };
    format!(
        "ROLE={}\nGOLDEN={}\nVER={}\nFIRST={}\nHOST={}\n",
        s("role"),
        s("golden"),
        s("ver"),
        s("first"),
        s("host")
    )
}

/// POST /api/diskless/client/base-done (public) — the asking machine finished its first-boot setup on its golden version
/// (and restarts now): that session becomes its base at the next boot.
async fn base_done(
    State(st): State<SharedState>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let peer = peer.ip().to_canonical().to_string();
    let st2 = st.clone();
    let (m, on) = tokio::task::spawn_blocking(move || asking(&st2, &peer))
        .await
        .map_err(ise)??;
    let Some((g, x)) = on else {
        return Err(bad("not running a diskless golden"));
    };
    set_base_state(
        &st,
        &g,
        &m.mac,
        &BaseState {
            pending: x.session_ver,
            host: m.hostname.clone(),
            lic: m.license_gen,
            akey: crate::agentauth::fingerprint(&st, &m.mac),
        },
    );
    tracing::info!(
        "golden {g}: {} set itself up (g{}) — kept as its base at its next boot",
        who(&m),
        x.session_ver.unwrap_or(0)
    );
    Ok(ok())
}

/// GET /api/diskless/client/agent-key (public) — the asking machine's Remote agent key (hex), for broom-diskless.ps1 to
/// keep in the base it is building: only to a registered machine (its IP with its MAC behind it) on the first boot of
/// its golden version (the base is built right then and restarts at once). Anything else: 403. The maintenance
/// machine never gets one: what it writes goes into the golden, which every machine shares.
async fn agent_key(
    State(st): State<SharedState>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
) -> Result<Response, ApiError> {
    let peer = peer.ip().to_canonical().to_string();
    let st2 = st.clone();
    let (m, on) = tokio::task::spawn_blocking(move || asking(&st2, &peer))
        .await
        .map_err(ise)??;
    let refuse = |why: &str| {
        tracing::warn!("diskless: agent key for {} refused ({why})", who(&m));
        Err((StatusCode::FORBIDDEN, "no key for this machine".to_string()))
    };
    let Some((g, x)) = on else {
        return refuse("not running a diskless golden");
    };
    if x.base_ver.is_some() && x.base_ver == x.session_ver {
        return refuse("not the first boot of its golden version");
    }
    let key = crate::agentauth::hand_to_base(&st, &m.mac).map_err(ise)?;
    tracing::info!(
        "golden {g}: agent key handed to {} for its base (g{})",
        who(&m),
        x.session_ver.unwrap_or(0)
    );
    Ok(([(header::CONTENT_TYPE, "text/plain")], key).into_response())
}

// ---------- API ----------

/// GET /api/diskless — goldens (with what the daemon reports), ISO library, the three places, machines (pickers).
async fn status(State(st): State<SharedState>) -> Result<Json<serde_json::Value>, ApiError> {
    let daemon = tokio::task::spawn_blocking(crate::iscsi::diskless_status)
        .await
        .map_err(ise)?
        .unwrap_or_default();
    let all = st.db.machines().map_err(ise)?;
    let list: Vec<serde_json::Value> = goldens(&st)
        .into_iter()
        .map(|g| {
            let d = daemon.iter().find(|i| i.disk.name == g.name);
            let without_ip: Vec<String> = all
                .iter()
                .filter(|m| !g.groups.is_empty() && for_group(&g.groups, m.grp.as_deref()))
                .filter(|m| m.ip.as_deref().is_none_or(str::is_empty))
                .map(who)
                .collect();
            let targets: Vec<serde_json::Value> = machines_of(&g, &all)
                .into_iter()
                .map(|m| serde_json::json!({"name": who(m), "mac": m.mac, "ip": m.ip, "target": machine_target(&st, &g.name, m)}))
                .collect();
            serde_json::json!({
                "golden": g,
                "iqn": iqn(&st, &g.name),
                "machines": targets,
                "served": d.is_some(),
                "status": d,
                "machines_without_fixed_ip": without_ip,
            })
        })
        .collect();
    let places: serde_json::Map<String, serde_json::Value> = PLACES
        .iter()
        .map(|(k, _)| {
            (
                k.to_string(),
                serde_json::json!({
                    "volume": volume_of(&st, k),
                    "path": dir_of(&st, k).ok().map(|p| p.to_string_lossy().into_owned()),
                }),
            )
        })
        .collect();
    let machines: Vec<serde_json::Value> = all
        .iter()
        .map(|m| serde_json::json!({"id": m.id, "name": who(m), "mac": m.mac, "ip": m.ip, "group": m.grp}))
        .collect();
    Ok(Json(serde_json::json!({
        "goldens": list,
        "isos": isos(&st),
        "places": places,
        "machines": machines,
        // The address the machines reach the server at (boot LAN), for the commands shown on the page.
        "server": st.db.get_config("dhcp_server_ip", ""),
        "error": *LAST_ERR.lock(),
    })))
}

#[derive(Deserialize)]
struct GoldenBody {
    name: String,
    #[serde(default = "default_os")]
    os: String,
    size_gb: u64,
    #[serde(default)]
    iso: Option<String>,
    #[serde(default)]
    groups: Vec<String>,
}

/// POST /api/diskless/golden {name, os=windows, size_gb, iso, groups} — a new blank golden, or change one (same name).
/// golden.img is sparse and can only grow; its OS can't change once created.
async fn upsert(
    State(st): State<SharedState>,
    Json(b): Json<GoldenBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let name = b.name.trim().to_ascii_lowercase();
    if !valid_name(&name) {
        return Err(bad("name: 1-24 lower-case letters / digits / '-'"));
    }
    let os = os_ok(&b.os)?;
    if !(16..=64 << 10).contains(&b.size_gb) {
        return Err(bad("size: 16 GB to 64 TB"));
    }
    let groups = clean_groups(&b.groups).map_err(bad)?;
    let iso = b.iso.filter(|i| !i.is_empty());
    if let Some(i) = &iso {
        let lib = isos(&st);
        let Some(x) = lib.iter().find(|x| &x.name == i) else {
            return Err(bad(format!("ISO {i} is not in the library")));
        };
        if x.os != os {
            return Err(bad(format!("ISO {i} is a {} installer, not {os}", x.os)));
        }
    }
    let p = golden_img(&st, &name).map_err(bad)?;
    let old = goldens(&st).into_iter().find(|g| g.name == name);
    if let Some(o) = &old
        && o.os != os
    {
        return Err(bad(format!(
            "golden {name} is {}: create another one",
            o.os
        )));
    }
    let (want, have) = (
        b.size_gb << 30,
        std::fs::metadata(&p).map_or(0, |m| m.len()),
    );
    if want < have {
        return Err(bad(format!(
            "golden {name} is {} GB: it can only grow",
            have >> 30
        )));
    }
    if want > have {
        std::fs::create_dir_all(p.parent().unwrap()).map_err(ise)?;
        let f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&p)
            .map_err(ise)?;
        f.set_len(want).map_err(ise)?;
        tracing::info!("golden {name}: {} GB ({})", b.size_gb, p.display());
    }
    edit(&st, |list| {
        let g = Golden {
            name: name.clone(),
            os: os.clone(),
            size_gb: b.size_gb,
            iso: iso.clone(),
            groups: groups.clone(),
            maint: old.as_ref().and_then(|o| o.maint),
            ram: old.as_ref().is_some_and(|o| o.ram),
            pins: old
                .as_ref()
                .map(|o| crate::pins::pruned(&o.pins, &groups, false))
                .unwrap_or_default(),
        };
        match list.iter().position(|x| x.name == name) {
            Some(i) => list[i] = g,
            None => list.push(g),
        }
        Ok(())
    })?;
    sync_now(st).await?;
    Ok(ok())
}

#[derive(Deserialize)]
struct NameBody {
    name: String,
}

fn find(st: &SharedState, name: &str) -> Result<Golden, ApiError> {
    goldens(st)
        .into_iter()
        .find(|g| g.name == name)
        .ok_or_else(|| not_found(name))
}

/// Daemon's view of golden `name`: nobody on it, no unsaved maintenance work.
fn idle(name: &str) -> Result<(), String> {
    let Some(i) = crate::iscsi::diskless_status()
        .unwrap_or_default()
        .into_iter()
        .find(|i| i.disk.name == name)
    else {
        return Ok(());
    };
    let on = i.machines.iter().filter(|m| m.connected).count() + i.disk.sessions;
    if on > 0 {
        return Err(format!("{on} machine(s) use it — shut them down first"));
    }
    if i.disk.update_connected || i.disk.update_bytes > 0 {
        return Err("its maintenance work is not saved — Save or Discard it first".into());
    }
    Ok(())
}

/// POST /api/diskless/golden/delete {name} — the golden, its versions and every machine's layers of it.
async fn delete(
    State(st): State<SharedState>,
    Json(b): Json<NameBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    find(&st, &b.name)?;
    if crate::onboard::busy(&st, &b.name) {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "adding hardware to {} is in progress — cancel it first",
                b.name
            ),
        ));
    }
    let n = b.name.clone();
    tokio::task::spawn_blocking(move || idle(&n))
        .await
        .map_err(ise)?
        .map_err(|e| (StatusCode::CONFLICT, e))?;
    let dirs = [
        golden_img(&st, &b.name)
            .map_err(ise)?
            .parent()
            .unwrap()
            .to_path_buf(),
        dir_of(&st, "writeback").map_err(ise)?.join(&b.name),
    ];
    edit(&st, |list| {
        list.retain(|g| g.name != b.name);
        Ok(())
    })?;
    crate::onboard::forget_golden(&st, &b.name);
    sync_now(st).await?;
    tokio::task::spawn_blocking(move || {
        for d in dirs {
            if let Err(e) = crate::volumes::remove_tree(&d)
                && e.kind() != std::io::ErrorKind::NotFound
            {
                return Err(format!("{}: {e}", d.display()));
            }
        }
        Ok(())
    })
    .await
    .map_err(ise)?
    .map_err(ise)?;
    tracing::info!("golden {} deleted", b.name);
    Ok(ok())
}

#[derive(Deserialize)]
struct MaintBody {
    name: String,
    /// The maintenance machine; None = maintenance off.
    id: Option<i64>,
}

/// POST /api/diskless/maint {name, id} — the machine whose next boots install / maintain the golden (writable).
async fn set_maint(
    State(st): State<SharedState>,
    Json(b): Json<MaintBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let w = match b.id {
        Some(id) => Some(who(&machine_by_id(&st, id)?)),
        None => None,
    };
    if crate::onboard::busy(&st, &b.name) {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "adding hardware to {} is in progress — wait for it or cancel it",
                b.name
            ),
        ));
    }
    edit(&st, |list| {
        let g = list
            .iter_mut()
            .find(|g| g.name == b.name)
            .ok_or_else(|| not_found(&b.name))?;
        g.maint = b.id;
        Ok(())
    })?;
    match w {
        Some(w) => tracing::info!("golden {}: {w} is its maintenance machine", b.name),
        None => tracing::info!("golden {}: maintenance off", b.name),
    }
    sync_now(st).await?;
    Ok(ok())
}

/// Save / Discard refused because the daemon still counts the maintenance machine as connected: Windows powers off
/// without logging out of iSCSI and TCP notices a dead client only after ~1 min. No agent and no ping answer = off →
/// its sessions are closed (the daemon flushes its writes) and the step runs again. Blocking.
fn with_maint_off<T>(
    st: &SharedState,
    name: &str,
    step: impl Fn() -> Result<T, String>,
) -> Result<T, String> {
    let e = match step() {
        Err(e) if e.contains("still connected") => e,
        r => return r,
    };
    let Some(m) = find(st, name)
        .ok()
        .and_then(|g| g.maint)
        .and_then(|id| machine_by_id(st, id).ok())
    else {
        return Err(e);
    };
    let Some(ip) = ip_of(st, &m) else {
        return Err(e);
    };
    let w = who(&m);
    if crate::vnc::connected(&m.mac) {
        return Err(format!(
            "the maintenance machine {w} is still on (its agent is connected) — shut it down first"
        ));
    }
    if crate::monitor::ping(&ip) {
        return Err(format!(
            "the maintenance machine {w} still answers on the network — wait for it to power off"
        ));
    }
    let n = crate::iscsi::kick_peer(&ip).map_err(|_| e.clone())?;
    tracing::info!(
        "golden {name}: maintenance machine {w} is off — its {n} iSCSI session(s) closed"
    );
    for _ in 0..20 {
        let busy = crate::iscsi::diskless_status()
            .unwrap_or_default()
            .iter()
            .any(|i| i.disk.name == name && i.disk.update_connected);
        if !busy {
            return step();
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    Err(e)
}

/// POST /api/diskless/save {name} — the maintenance work becomes the golden's next version (machine must be off).
async fn save(
    State(st): State<SharedState>,
    Json(b): Json<NameBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    find(&st, &b.name)?;
    vm_off(&b.name)?;
    let (name, st2) = (b.name.clone(), st.clone());
    let msg = tokio::task::spawn_blocking(move || {
        with_maint_off(&st2, &name, || crate::iscsi::golden_save(&name))
    })
    .await
    .map_err(ise)?
    .map_err(|e| (StatusCode::CONFLICT, e))?;
    let msg = format!("{msg}{}", held(&st, &b.name));
    tracing::info!("golden {}: {msg}", b.name);
    Ok(Json(serde_json::json!({"ok": true, "status": msg})))
}

/// Groups of golden `name` held on an older version than its newest (for a message after a new version).
pub(crate) fn held(st: &SharedState, name: &str) -> String {
    let (Some(g), Some(i)) = (
        goldens(st).into_iter().find(|g| g.name == name),
        served(name),
    ) else {
        return String::new();
    };
    crate::pins::held_note(&g.pins, i.disk.ver)
}

/// Save / Discard wait for the maintenance VM to be off (its disk is still attached until then).
fn vm_off(name: &str) -> Result<(), ApiError> {
    if crate::vmmaint::owns_golden(name) {
        return Err((
            StatusCode::CONFLICT,
            format!("{name} is running in the VM (Maintain in the browser) — shut it down first"),
        ));
    }
    Ok(())
}

/// POST /api/diskless/discard {name} — throw the maintenance work away.
async fn discard(
    State(st): State<SharedState>,
    Json(b): Json<NameBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    find(&st, &b.name)?;
    vm_off(&b.name)?;
    let (name, st2) = (b.name.clone(), st.clone());
    tokio::task::spawn_blocking(move || {
        with_maint_off(&st2, &name, || crate::iscsi::golden_discard(&name))
    })
    .await
    .map_err(ise)?
    .map_err(|e| (StatusCode::CONFLICT, e))?;
    tracing::info!("golden {}: maintenance work discarded", b.name);
    Ok(ok())
}

#[derive(Deserialize)]
struct VolumeBody {
    /// "golden" | "writeback" | "iso".
    kind: String,
    /// Volume id; "" = broom's own folder.
    #[serde(default)]
    id: String,
}

/// POST /api/diskless/volume {kind, id} — where goldens / the machines' layers / the ISO library live. Only while that
/// place is empty (nothing is moved).
async fn set_volume(
    State(st): State<SharedState>,
    Json(b): Json<VolumeBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let sub = sub_of(&b.kind).ok_or_else(|| bad("kind: golden, writeback or iso"))?;
    let id = b.id.trim().to_string();
    if id == volume_of(&st, &b.kind) {
        return Ok(ok());
    }
    let busy = match b.kind.as_str() {
        "iso" => !isos(&st).is_empty(),
        _ => !goldens(&st).is_empty(),
    };
    if busy {
        return Err(bad(format!(
            "the {} place holds data already: delete it first (moving is not supported yet)",
            b.kind
        )));
    }
    let to = match id.as_str() {
        "" => crate::home().join(sub),
        v => crate::volumes::folder_on(&st, v, sub).map_err(bad)?,
    };
    std::fs::create_dir_all(&to).map_err(|e| bad(format!("{}: {e}", to.display())))?;
    st.db
        .set_config(&format!("{}_volume", b.kind), &id)
        .map_err(ise)?;
    tracing::info!("diskless: {} now at {}", b.kind, to.display());
    Ok(ok())
}

// ---------- ISO library ----------

fn iso_upload_dir(st: &SharedState) -> Result<PathBuf, ApiError> {
    Ok(dir_of(st, "iso").map_err(bad)?.join(".upload"))
}

#[derive(Deserialize)]
struct IsoStart {
    name: String,
    #[serde(default = "default_os")]
    os: String,
}

/// POST /api/diskless/iso/upload-start {name, os=windows} — begin uploading an installer ISO (drops a half-done one).
async fn iso_start(
    State(st): State<SharedState>,
    Json(b): Json<IsoStart>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !valid_iso(&b.name) {
        return Err(bad(
            "ISO name: letters, digits, '.', '_', '-', ending in .iso",
        ));
    }
    os_ok(&b.os)?;
    if isos(&st).iter().any(|i| i.name == b.name) {
        return Err(bad(format!("{} is already in the library", b.name)));
    }
    let dir = iso_upload_dir(&st)?.join(&b.name);
    let _ = tokio::fs::remove_dir_all(&dir).await;
    tokio::fs::create_dir_all(&dir).await.map_err(ise)?;
    Ok(ok())
}

#[derive(Deserialize)]
struct IsoChunk {
    name: String,
    offset: u64,
    total: u64,
}

/// PUT /api/diskless/iso/upload-chunk?name=&offset=&total= — up to 16 MB of the ISO at `offset`, in any order.
async fn iso_chunk(
    State(st): State<SharedState>,
    Query(q): Query<IsoChunk>,
    body: Body,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !valid_iso(&q.name) {
        return Err(bad("bad ISO name"));
    }
    let dir = iso_upload_dir(&st)?.join(&q.name);
    crate::images::write_chunk(dir, &q.name, q.offset, q.total, 64 << 30, body).await?;
    Ok(ok())
}

/// POST /api/diskless/iso/upload-done {name, os} — the upload joins the library.
async fn iso_done(
    State(st): State<SharedState>,
    Json(b): Json<IsoStart>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !valid_iso(&b.name) {
        return Err(bad("bad ISO name"));
    }
    let os = os_ok(&b.os)?;
    let up = iso_upload_dir(&st)?.join(&b.name);
    let src = up.join(&b.name);
    let size = std::fs::metadata(&src)
        .map_err(|_| bad("no upload of it in progress"))?
        .len();
    let dst = dir_of(&st, "iso").map_err(bad)?.join(&b.name);
    std::fs::rename(&src, &dst).map_err(ise)?;
    let _ = std::fs::remove_dir_all(&up);
    let _ = std::fs::remove_dir(up.parent().unwrap_or(&up)); // .upload itself, once no other upload runs
    let added = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    edit_isos(&st, |l| {
        l.retain(|i| i.name != b.name);
        l.push(Iso {
            name: b.name.clone(),
            os: os.clone(),
            size,
            added,
        });
        Ok(())
    })?;
    tracing::info!(
        "ISO library: {} added ({os}, {:.1} GB)",
        b.name,
        size as f64 / 1e9
    );
    Ok(ok())
}

#[derive(Deserialize)]
struct IsoOs {
    name: String,
    os: String,
}

/// POST /api/diskless/iso/os {name, os} — correct an ISO's OS.
async fn iso_os(
    State(st): State<SharedState>,
    Json(b): Json<IsoOs>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let os = os_ok(&b.os)?;
    edit_isos(&st, |l| {
        let i = l
            .iter_mut()
            .find(|i| i.name == b.name)
            .ok_or_else(|| bad(format!("{} is not in the library", b.name)))?;
        i.os = os;
        Ok(())
    })?;
    Ok(ok())
}

/// POST /api/diskless/iso/delete {name} — refused while a golden names it as its installer.
async fn iso_delete(
    State(st): State<SharedState>,
    Json(b): Json<NameBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if let Some(g) = goldens(&st)
        .iter()
        .find(|g| g.iso.as_deref() == Some(b.name.as_str()))
    {
        return Err(bad(format!("golden {} installs from it", g.name)));
    }
    edit_isos(&st, |l| {
        let n = l.len();
        l.retain(|i| i.name != b.name);
        if l.len() == n {
            return Err(bad(format!("{} is not in the library", b.name)));
        }
        Ok(())
    })?;
    if valid_iso(&b.name) {
        let lib = dir_of(&st, "iso").map_err(ise)?;
        let _ = std::fs::remove_file(lib.join(&b.name));
        let _ = std::fs::remove_dir_all(lib.join(".boot").join(&b.name)); // casper_files
    }
    tracing::info!("ISO library: {} deleted", b.name);
    Ok(ok())
}

#[cfg(test)]
#[path = "../tests/unit/diskless.rs"]
mod tests;
