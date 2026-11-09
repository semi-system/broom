// machines.rs — the Machines table (MAC / IP / hostname / group / image) API used by the Machines page; the Devices
// page (devices.rs) edits the same rows in bulk. License keys: license.rs. Server settings: settings.rs.
use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use serde::Deserialize;

use crate::SharedState;
use crate::api::{ApiError, bad, ise};
use crate::db::Machine;

pub fn routes() -> Router<SharedState> {
    Router::new()
        .route("/api/machines", post(add)) // Register (Machines + Devices pages)
        .route("/api/machines/base", post(set_base)) // base mode (Machines page)
}

#[derive(Deserialize)]
struct BaseBody {
    id: i64,
    /// The Windows image whose base this machine boots itself; None = off.
    image: Option<i64>,
}

/// POST /api/machines/base {id, image|null} — base mode: when the machine boots `image`, the stage boots that image's
/// base itself, so every change is kept over as many restarts as needed (Windows Update, an app's own restarts); off
/// again → its next boot saves the base and resets to it from then on. Read by /boot/start: no republish.
async fn set_base(
    State(st): State<SharedState>,
    axum::Extension(w): axum::Extension<crate::auth::Who>,
    Json(b): Json<BaseBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let m = machine_by_id(&st, b.id)?;
    let img = match b.image {
        Some(id) => Some(
            st.db
                .image(id)
                .map_err(ise)?
                .filter(|i| i.os == "windows")
                .ok_or_else(|| bad("base mode needs a Windows image"))?,
        ),
        None => None,
    };
    st.db
        .set_machine_base(m.id, img.as_ref().map(|i| i.id))
        .map_err(ise)?;
    match &img {
        Some(i) => tracing::warn!(
            "{}: base mode of {} ON for image {}",
            w.name,
            who(&m),
            i.name
        ),
        None => tracing::info!(
            "{}: base mode of {} off (its next boot saves the base)",
            w.name,
            who(&m)
        ),
    }
    Ok(crate::api::ok())
}

/// A machine deleted: what is kept about it elsewhere goes too — its disks and Remote key (config, by MAC), and the
/// iSCSI disks it was the update machine of (by its id: a machine registered later can get the same id, and with it
/// the right to write those disks). Blocking (the iSCSI daemon is told).
pub(crate) fn forget(st: &SharedState, m: &Machine) {
    let mac = m.mac.to_lowercase();
    for k in [format!("disks:{mac}"), format!("agentkey:{mac}")] {
        let _ = st.db.delete_config(&k);
    }
    crate::games::forget_update(st, m.id, &who(m));
    crate::diskless::forget_machine(st, m);
}

/// A machine's MAC changed: its disks and Remote key follow it.
pub(crate) fn moved(st: &SharedState, old: &str, new: &str) {
    let (old, new) = (old.to_lowercase(), new.to_lowercase());
    if old == new {
        return;
    }
    for p in ["disks:", "agentkey:"] {
        let v = st.db.get_config(&format!("{p}{old}"), "");
        if !v.is_empty() && st.db.set_config(&format!("{p}{new}"), &v).is_ok() {
            let _ = st.db.delete_config(&format!("{p}{old}"));
        }
    }
}

pub(crate) fn who(m: &Machine) -> String {
    m.hostname.clone().unwrap_or_else(|| m.mac.clone())
}

/// The registered machine behind a client IP (its MAC from ARP / lease / fixed IP). Not proof of identity (ARP can be
/// faked): for choosing what to offer, not for handing out secrets (license.rs is stricter).
pub(crate) fn machine_at(st: &SharedState, ip: &str) -> Option<Machine> {
    let mac = crate::license::mac_at(st, ip)?;
    by_mac(st, &mac).ok().flatten()
}

/// The registered machine with this MAC (any case).
pub(crate) fn by_mac(st: &SharedState, mac: &str) -> Result<Option<Machine>, ApiError> {
    let all = st.db.machines().map_err(ise)?;
    Ok(all.into_iter().find(|m| m.mac.eq_ignore_ascii_case(mac)))
}

/// A resource limited to `groups` (empty = every machine, registered or not) is for a machine of group `grp`.
pub(crate) fn for_group(groups: &[String], grp: Option<&str>) -> bool {
    groups.is_empty() || grp.is_some_and(|g| groups.iter().any(|x| x.eq_ignore_ascii_case(g)))
}

/// "VIP, Thuong ,vip" → ["VIP", "Thuong"]: trimmed, no empties, no case-insensitive duplicates; each a valid group
/// name (drivers::group_ok, like a machine's group), at most 50.
pub(crate) fn clean_groups(v: &[String]) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    for g in v
        .iter()
        .flat_map(|s| s.split(','))
        .map(str::trim)
        .filter(|g| !g.is_empty())
    {
        if !crate::drivers::group_ok(g) {
            return Err(format!("group {g:?}: letters/digits/_/-, max 32"));
        }
        if !out.iter().any(|x| x.eq_ignore_ascii_case(g)) {
            out.push(g.to_string());
        }
    }
    if out.len() > 50 {
        return Err("at most 50 groups".into());
    }
    Ok(out)
}

pub(crate) fn machine_by_id(st: &SharedState, id: i64) -> Result<Machine, ApiError> {
    st.db
        .machines()
        .map_err(ise)?
        .into_iter()
        .find(|m| m.id == id)
        .ok_or((StatusCode::NOT_FOUND, format!("machine {id} not found")))
}

pub(crate) const HOSTNAME_RULE: &str = "Hostname: 1-15 characters, only letters/digits/'-', must not start or end with '-', not all digits (Windows computer name)";

/// Windows computer name (NetBIOS) — becomes the Windows name via stage/broom-done. Keep in sync with hostOk() in index.html.
pub(crate) fn hostname_ok(h: &str) -> bool {
    (1..=15).contains(&h.len())
        && h.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        && !h.starts_with('-')
        && !h.ends_with('-')
        && !h.chars().all(|c| c.is_ascii_digit())
}

/// Config key: the group a machine joins by itself at its first network boot (Groups page). Empty = off: machines are
/// registered by hand (Machines / Devices pages).
pub(crate) const NEW_GROUP_KEY: &str = "new_machines_group";
/// At most this many machines wait in that group: the boot menu is open to the whole LAN, so a host cycling made-up
/// MACs must not grow the Machines table without end.
pub(crate) const NEW_MAX: usize = 250;
/// What a machine that joined by itself has in its notes (Devices page).
pub(crate) const NEW_NOTE: &str =
    "Joined by itself at its first network boot - move it to its group";

/// The new-machines group, None = off.
pub(crate) fn new_group(st: &SharedState) -> Option<String> {
    let g = st.db.get_config(NEW_GROUP_KEY, "");
    let g = g.trim();
    (!g.is_empty() && crate::drivers::group_ok(g)).then(|| g.to_string())
}

/// Machine `m` waits in the new-machines group for an admin: it boots what that group gets, but its disks are never
/// partitioned without asking — like an unknown machine's (the stage asks on its screen).
pub(crate) fn waiting(m: &Machine, new_group: Option<&str>) -> bool {
    matches!((m.grp.as_deref(), new_group), (Some(a), Some(b)) if a.eq_ignore_ascii_case(b))
}

/// The row of an unknown machine that just network-booted from `peer`, to join group `grp` by itself: named
/// NEW-<end of its MAC> (the first such name free), its current IP as fixed IP when no other machine / live lease
/// holds it. Err (why, for the log) = not added: the MAC the server sees at `peer` (ARP) must be `mac` (a PC on this
/// LAN booting for itself, not a made-up MAC or one behind a router), and at most NEW_MAX machines wait in `grp`.
pub(crate) fn new_machine(
    mac: &str,
    peer: &str,
    arp: Option<&str>,
    grp: &str,
    all: &[Machine],
    leases: &[crate::db::Lease],
    now: i64,
) -> Result<Machine, String> {
    let mac = crate::devices::norm_mac(mac).ok_or_else(|| format!("bad MAC {mac:?}"))?;
    match arp.and_then(crate::devices::norm_mac) {
        Some(a) if a == mac => {}
        Some(a) => return Err(format!("{peer} is {a} on the network, not {mac}")),
        None => return Err(format!("{peer} is not on the server's LAN (no ARP entry)")),
    }
    if all.iter().filter(|m| waiting(m, Some(grp))).count() >= NEW_MAX {
        return Err(format!(
            "{NEW_MAX} machines already wait in group {grp} - move them to their groups first"
        ));
    }
    let hex: String = mac
        .chars()
        .filter(|c| *c != ':')
        .collect::<String>()
        .to_ascii_uppercase();
    let taken = |h: &str| {
        all.iter().any(|m| {
            m.hostname
                .as_deref()
                .is_some_and(|x| x.eq_ignore_ascii_case(h))
        })
    };
    let hostname = [
        format!("NEW-{}", &hex[6..]),
        format!("NEW-{}", &hex[4..]),
        format!("N{hex}"),
    ]
    .into_iter()
    .find(|h| hostname_ok(h) && !taken(h));
    let mut m = Machine {
        mac: mac.clone(),
        ip: peer
            .parse::<std::net::Ipv4Addr>()
            .ok()
            .map(|a| a.to_string()),
        hostname,
        grp: Some(grp.to_string()),
        notes: Some(NEW_NOTE.into()),
        ..Default::default()
    };
    if all.iter().any(|o| o.ip.is_some() && o.ip == m.ip)
        || crate::devices::ip_free(&m, leases, now).is_err()
    {
        m.ip = None; // another machine's fixed IP or lease: the admin gives it one
    }
    crate::devices::validate(&mut m, all)?;
    Ok(m)
}

/// An unknown machine (MAC `mac`, request from `peer`) at the boot menu while the new-machines group `grp` is on:
/// added to the Machines table in that group (new_machine). None = not added (logged).
pub(crate) fn join_new(st: &SharedState, mac: &str, peer: &str, grp: &str) -> Option<Machine> {
    // One at a time: two PCs booting together must not pick the same name / IP.
    static LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    let _g = LOCK.lock();
    let all = st.db.machines().ok()?;
    if let Some(m) = all.iter().find(|m| m.mac.eq_ignore_ascii_case(mac)) {
        return Some(m.clone()); // its other request was first
    }
    let leases = st.db.leases().unwrap_or_default();
    let arp = crate::license::arp_mac(peer);
    let now = crate::now_secs() as i64;
    let m = match new_machine(mac, peer, arp.as_deref(), grp, &all, &leases, now) {
        Ok(m) => m,
        Err(why) => {
            tracing::warn!("new machine {mac} at {peer} not added to group {grp}: {why}");
            return None;
        }
    };
    match st.db.add_machine_row(&m) {
        Ok(id) => {
            tracing::warn!(
                "new machine joined group {grp} by itself - mac {} - ip {} - hostname {} (move it to its group: Devices / Groups page)",
                m.mac,
                m.ip.as_deref().unwrap_or("-"),
                m.hostname.as_deref().unwrap_or("-")
            );
            Some(Machine { id, ..m })
        }
        Err(e) => {
            tracing::warn!("new machine {mac} at {peer} not added to group {grp}: {e}");
            None
        }
    }
}

#[derive(Deserialize)]
struct NewMachine {
    mac: String,
    ip: Option<String>,
    hostname: Option<String>,
}

async fn add(
    State(st): State<SharedState>,
    Json(b): Json<NewMachine>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // Same checks as the Devices page: MAC normalized, hostname rule, MAC / hostname / IP unique.
    let mut m = Machine {
        mac: b.mac,
        ip: b.ip,
        hostname: b.hostname,
        ..Default::default()
    };
    let all = st.db.machines().map_err(ise)?;
    crate::devices::validate(&mut m, &all).map_err(bad)?;
    crate::devices::ip_free(&m, &st.db.leases().map_err(ise)?, crate::now_secs() as i64)
        .map_err(bad)?;
    let id = st
        .db
        .add_machine(&m.mac, m.ip.as_deref(), m.hostname.as_deref())
        .map_err(bad)?;
    tracing::info!(
        "machine registered - mac {} - ip {} - hostname {}",
        m.mac,
        m.ip.as_deref().unwrap_or("-"),
        m.hostname.as_deref().unwrap_or("-")
    );
    Ok(Json(serde_json::json!({"ok": true, "id": id})))
}

#[cfg(test)]
#[path = "../tests/unit/machines.rs"]
mod tests;
