// pins.rs — versions of the diskless goldens and the games disks: how long they are kept, and which one each group
// gets.
// - Kept: every saved version stays (its layer, iscsid/games.rs Config.retain) until the drive holding the golden /
//   games disk has less than `versions_min_free_pct` % free; then the oldest one nobody uses and no group is held on
//   goes, one at a time, until there is room again. The owner can drop the oldest by hand too.
// - Held (pinned): a group can be held on one version of a golden or a games disk instead of the newest. Its machines
//   boot that version (diskless.rs boot_diskless / prepare_games, games.rs for_client) and it is never dropped
//   (Config.keep_from). The usual flow: a test group on the newest, the lounge held on the last good version; once the
//   new one is checked on a test PC, move the lounge to it (Approve). Machines get a change at their next boot.
// Why: a golden or games update that breaks something must never reach the whole room at once. Keeping versions
// (instead of merging each one away as before) gives a way back, and holding a group lets one PC test the newest
// version while the others stay on the last good one — an approve-before-rollout flow like the one some commercial
// diskless systems offer, here as a version picker per group. Space decides how long versions stay, not a count: a 4 TB goldens drive
// holds many versions, and the oldest go only when the drive actually fills up.
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    routing::{get, post},
};
use serde::Deserialize;
use std::collections::BTreeMap;

use crate::SharedState;
use crate::api::{ApiError, bad, ise};

pub fn routes() -> Router<SharedState> {
    Router::new()
        .route("/api/versions", get(status))
        .route("/api/versions/pin", post(pin))
        .route("/api/versions/drop-oldest", post(drop_oldest))
        .route("/api/versions/keep-free", post(keep_free))
}

const KEY: &str = "versions_min_free_pct";
/// Default: older versions go once their drive has less than 10 % free.
const DEFAULT_PCT: u8 = 10;

/// The % of free space a drive keeps before old versions go.
pub(crate) fn min_free_pct(st: &SharedState) -> u8 {
    st.db
        .get_config(KEY, "")
        .parse::<u8>()
        .ok()
        .filter(|p| (1..=90).contains(p))
        .unwrap_or(DEFAULT_PCT)
}

/// The version machines of group `grp` get (None = the newest). Group names match without case.
pub(crate) fn pin_for(pins: &BTreeMap<String, u64>, grp: Option<&str>) -> Option<u64> {
    let g = grp?;
    pins.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(g))
        .map(|(_, v)| *v)
}

/// The oldest version a group is held on: it and every newer one are kept.
pub(crate) fn keep_from(pins: &BTreeMap<String, u64>) -> Option<u64> {
    pins.values().min().copied()
}

/// Pins of groups that no longer get the disk are dropped (a golden: its groups; a games disk with groups: those).
pub(crate) fn pruned(
    pins: &BTreeMap<String, u64>,
    groups: &[String],
    all_if_none: bool,
) -> BTreeMap<String, u64> {
    pins.iter()
        .filter(|(k, _)| {
            (all_if_none && groups.is_empty()) || groups.iter().any(|g| g.eq_ignore_ascii_case(k))
        })
        .map(|(k, v)| (k.clone(), *v))
        .collect()
}

/// After any change to groups (Groups page, a golden's / games disk's own form): pins of groups that left go.
pub(crate) fn prune(st: &SharedState) -> Result<(), ApiError> {
    crate::diskless::edit_pins(st, &|g| pruned(&g.pins, &g.groups, false))?;
    crate::games::edit(st, |list| {
        for d in list.iter_mut() {
            d.pins = pruned(&d.pins, &d.groups, true);
        }
        Ok(())
    })
}

/// Group `from` renamed to `to` (None = deleted): its pins follow.
pub(crate) fn rename_group(st: &SharedState, from: &str, to: Option<&str>) -> Result<(), ApiError> {
    let mv = |pins: &BTreeMap<String, u64>| -> BTreeMap<String, u64> {
        let mut out = BTreeMap::new();
        for (k, v) in pins {
            if k.eq_ignore_ascii_case(from) {
                if let Some(t) = to {
                    out.insert(t.to_string(), *v);
                }
            } else {
                out.entry(k.clone()).or_insert(*v);
            }
        }
        out
    };
    crate::diskless::edit_pins(st, &|g| mv(&g.pins))?;
    crate::games::edit(st, |list| {
        for d in list.iter_mut() {
            d.pins = mv(&d.pins);
        }
        Ok(())
    })
}

/// The daemon's view of golden (`golden`) / games disk `name`.
fn info(name: &str, golden: bool) -> Option<crate::iscsid::games::Info> {
    if golden {
        crate::diskless::served(name).map(|i| i.disk)
    } else {
        crate::iscsi::games_status()?
            .into_iter()
            .find(|i| i.name == name)
    }
}

/// Hold group `group` of golden / games disk `name` on version `ver` (None = the newest again). Blocking (sync).
pub(crate) fn set(
    st: &SharedState,
    golden: bool,
    name: &str,
    group: &str,
    ver: Option<u64>,
) -> Result<String, ApiError> {
    let group = group.trim();
    if group.is_empty() {
        return Err(bad("pick a group"));
    }
    let what = if golden { "golden" } else { "iSCSI disk" };
    if let Some(v) = ver {
        let i = info(name, golden).ok_or_else(|| bad(format!("{what} {name} is not served")))?;
        // A daemon of an older build lists no versions: only its newest is known to be there.
        let kept = i.versions.iter().any(|x| x.ver == v) || v == i.ver;
        if !kept {
            return Err(bad(format!("{name}: version g{v} is not kept any more")));
        }
    }
    let apply = |pins: &mut BTreeMap<String, u64>| {
        pins.retain(|k, _| !k.eq_ignore_ascii_case(group));
        if let Some(v) = ver {
            pins.insert(group.to_string(), v);
        }
    };
    if golden {
        let g = crate::diskless::goldens(st)
            .into_iter()
            .find(|g| g.name == name)
            .ok_or_else(|| bad(format!("golden {name} not found")))?;
        if !g.groups.iter().any(|x| x.eq_ignore_ascii_case(group)) {
            return Err(bad(format!("group {group} does not boot {name}")));
        }
        crate::diskless::edit_pins(st, &|x| {
            let mut p = x.pins.clone();
            if x.name == name {
                apply(&mut p);
            }
            p
        })?;
        crate::diskless::sync(st).map_err(|e| (StatusCode::CONFLICT, e))?;
    } else {
        crate::games::edit(st, |list| {
            let d = list
                .iter_mut()
                .find(|d| d.name == name)
                .ok_or_else(|| bad(format!("iSCSI disk {name} not found")))?;
            if !d.groups.is_empty() && !d.groups.iter().any(|x| x.eq_ignore_ascii_case(group)) {
                return Err(bad(format!("group {group} does not get {name}")));
            }
            apply(&mut d.pins);
            Ok(())
        })?;
        crate::games::sync(st).map_err(|e| (StatusCode::CONFLICT, e))?;
    }
    Ok(match ver {
        Some(v) => format!("{group} gets {name} g{v} from each machine's next boot"),
        None => format!("{group} gets the newest {name} from each machine's next boot"),
    })
}

/// For a Save message: groups held on an older version than `newest`.
pub(crate) fn held_note(pins: &BTreeMap<String, u64>, newest: u64) -> String {
    let held: Vec<String> = pins
        .iter()
        .filter(|(_, v)| **v < newest)
        .map(|(k, v)| format!("{k} on g{v}"))
        .collect();
    if held.is_empty() {
        String::new()
    } else {
        format!(
            " — held: {} (move them to g{newest} once it is checked)",
            held.join(", ")
        )
    }
}

// ---------- web ----------

/// GET /api/versions → {min_free_pct, goldens: [...], games: [...]}: each with its kept versions (size, saved, in use),
/// newest, groups and pins, and its drive's free space.
async fn status(State(st): State<SharedState>) -> Json<serde_json::Value> {
    let (dl, gs) = tokio::task::spawn_blocking(|| {
        (
            crate::iscsi::diskless_status().unwrap_or_default(),
            crate::iscsi::games_status().unwrap_or_default(),
        )
    })
    .await
    .unwrap_or_default();
    let entry = |name: &str,
                 groups: &[String],
                 pins: &BTreeMap<String, u64>,
                 i: Option<&crate::iscsid::games::Info>| {
        serde_json::json!({
            "name": name,
            "groups": groups,
            "pins": pins,
            "newest": i.map(|i| i.ver),
            "versions": i.map(|i| i.versions.clone()).unwrap_or_default(),
            "update_bytes": i.map_or(0, |i| i.update_bytes),
            "fs_free": i.map_or(0, |i| i.fs_free),
            "fs_size": i.map_or(0, |i| i.fs_size),
        })
    };
    let goldens: Vec<serde_json::Value> = crate::diskless::goldens(&st)
        .iter()
        .map(|g| {
            let i = dl
                .iter()
                .find(|x| !x.games && x.disk.name == g.name)
                .map(|x| &x.disk);
            entry(&g.name, &g.groups, &g.pins, i)
        })
        .collect();
    let games: Vec<serde_json::Value> = crate::games::disks(&st)
        .iter()
        .map(|d| {
            entry(
                &d.name,
                &d.groups,
                &d.pins,
                gs.iter().find(|x| x.name == d.name),
            )
        })
        .collect();
    Json(serde_json::json!({"min_free_pct": min_free_pct(&st), "goldens": goldens, "games": games}))
}

#[derive(Deserialize)]
struct PinBody {
    /// "golden" | "games"
    kind: String,
    name: String,
    group: String,
    /// None = the newest.
    #[serde(default)]
    ver: Option<u64>,
}

/// POST /api/versions/pin {kind, name, group, ver} — hold a group on a version (ver null = the newest).
async fn pin(
    State(st): State<SharedState>,
    axum::Extension(w): axum::Extension<crate::auth::Who>,
    Json(b): Json<PinBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let golden = kind(&b.kind)?;
    let msg = tokio::task::spawn_blocking(move || set(&st, golden, &b.name, &b.group, b.ver))
        .await
        .map_err(ise)??;
    tracing::warn!("versions: {msg} ({})", w.name);
    Ok(Json(serde_json::json!({"ok": true, "status": msg})))
}

fn kind(k: &str) -> Result<bool, ApiError> {
    match k {
        "golden" => Ok(true),
        "games" => Ok(false),
        _ => Err(bad("kind: golden or games")),
    }
}

#[derive(Deserialize)]
struct DropBody {
    kind: String,
    name: String,
}

/// POST /api/versions/drop-oldest {kind, name} (owner) — drop its oldest kept version now (not one in use or held).
async fn drop_oldest(
    State(st): State<SharedState>,
    Json(b): Json<DropBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let golden = kind(&b.kind)?;
    let known = if golden {
        crate::diskless::goldens(&st)
            .iter()
            .any(|g| g.name == b.name)
    } else {
        crate::games::disks(&st).iter().any(|d| d.name == b.name)
    };
    if !known {
        return Err(bad(format!("{} not found", b.name)));
    }
    let name = b.name.clone();
    let v = tokio::task::spawn_blocking(move || crate::iscsi::version_drop(&name, golden))
        .await
        .map_err(ise)?
        .map_err(|e| (StatusCode::CONFLICT, e))?;
    tracing::warn!("versions: {} g{v} dropped by hand", b.name);
    Ok(Json(
        serde_json::json!({"ok": true, "status": format!("{} g{v} dropped", b.name)}),
    ))
}

#[derive(Deserialize)]
struct KeepFreeBody {
    pct: u8,
}

/// POST /api/versions/keep-free {pct} (owner) — old versions go once a drive has less than pct % free (1-90).
async fn keep_free(
    State(st): State<SharedState>,
    Json(b): Json<KeepFreeBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !(1..=90).contains(&b.pct) {
        return Err(bad("1 to 90 %"));
    }
    st.db.set_config(KEY, &b.pct.to_string()).map_err(ise)?;
    let st2 = st.clone();
    tokio::task::spawn_blocking(move || {
        let _ = crate::games::sync(&st2);
        let _ = crate::diskless::sync(&st2);
    })
    .await
    .map_err(ise)?;
    tracing::info!("versions: old versions go below {}% free", b.pct);
    Ok(Json(serde_json::json!({"ok": true})))
}

#[cfg(test)]
#[path = "../tests/unit/pins.rs"]
mod tests;
