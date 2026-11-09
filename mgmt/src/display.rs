// display.rs — screen resolution + refresh rate per machine or per group (Machines page). The Remote agent applies it
// (broom-vnc.cs, op "display": Windows' ChangeDisplaySettingsEx on the main output, only a mode the monitor offers) every
// time it connects — a diskless machine starts from its golden at every boot — and at once when it is changed here.
// A machine's own setting wins over its group's; none = Windows' own choice.
// Why: a diskless (or reset-every-boot) machine starts from the golden, so a resolution set in Windows on one PC is gone
// at its next boot, and one golden serves PCs with different monitors. The server keeps the wish and the agent applies
// it at every start, and only when that PC's monitor offers the mode (another monitor just keeps its own).
use axum::{Json, Router, extract::State, routing::post};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::SharedState;
use crate::api::{ApiError, bad, ise};
use crate::db::Machine;

pub fn routes() -> Router<SharedState> {
    Router::new().route("/api/machines/display", post(set))
}

const KEY: &str = "display_settings";

/// What is set: by machine MAC (lower case) and by group (as typed).
#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
pub(crate) struct Settings {
    #[serde(default)]
    pub machines: BTreeMap<String, String>,
    #[serde(default)]
    pub groups: BTreeMap<String, String>,
}

pub(crate) fn settings(st: &SharedState) -> Settings {
    serde_json::from_str(&st.db.get_config(KEY, "{}")).unwrap_or_default()
}

/// "1920x1080@165" (or 1920×1080, spaces, "Hz") → (width, height, refresh). Sizes 320–16384, refresh 24–1000.
pub(crate) fn parse_mode(s: &str) -> Option<(u32, u32, u32)> {
    let t: String = s
        .to_ascii_lowercase()
        .replace('×', "x")
        .replace("hz", "")
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let (wh, hz) = t.split_once('@')?;
    let (w, h) = wh.split_once('x')?;
    let (w, h, hz) = (w.parse().ok()?, h.parse().ok()?, hz.parse().ok()?);
    ((320..=16384).contains(&w) && (240..=16384).contains(&h) && (24..=1000).contains(&hz))
        .then_some((w, h, hz))
}

pub(crate) fn fmt_mode((w, h, hz): (u32, u32, u32)) -> String {
    format!("{w}x{h}@{hz}")
}

/// The mode machine `m` should run: its own setting, else its group's.
pub(crate) fn effective(s: &Settings, m: &Machine) -> Option<(u32, u32, u32)> {
    s.machines
        .get(&m.mac.to_lowercase())
        .or_else(|| {
            let g = m.grp.as_deref()?;
            s.groups
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(g))
                .map(|(_, v)| v)
        })
        .and_then(|v| parse_mode(v))
}

/// The agent's command for mode `m`.
pub(crate) fn command((w, h, hz): (u32, u32, u32)) -> String {
    serde_json::json!({"op": "display", "w": w, "h": h, "hz": hz}).to_string()
}

/// Machine `mac`'s agent just connected (vnc.rs): its mode, if one is set, goes to it. Blocking.
pub(crate) fn on_connect(st: &SharedState, mac: &str) {
    let Ok(Some(m)) = crate::machines::by_mac(st, mac) else {
        return;
    };
    if let Some(mode) = effective(&settings(st), &m) {
        crate::vnc::command(mac, &command(mode));
    }
}

/// For the machine's Hardware panel: {own, group, effective} ("" = none).
pub(crate) fn info(st: &SharedState, m: &Machine) -> serde_json::Value {
    let s = settings(st);
    let group = m
        .grp
        .as_deref()
        .and_then(|g| s.groups.iter().find(|(k, _)| k.eq_ignore_ascii_case(g)))
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    serde_json::json!({
        "own": s.machines.get(&m.mac.to_lowercase()).cloned().unwrap_or_default(),
        "group": group,
        "effective": effective(&s, m).map(fmt_mode).unwrap_or_default(),
    })
}

#[derive(Deserialize)]
struct SetBody {
    /// These machines' own setting…
    #[serde(default)]
    ids: Vec<i64>,
    /// …or this group's.
    #[serde(default)]
    group: Option<String>,
    /// "1920x1080@165"; "" = remove the setting.
    mode: String,
}

/// POST /api/machines/display {ids | group, mode} — set (or with mode "" remove) the resolution + refresh; machines whose
/// agent is connected get it at once. → {ok, sent}.
async fn set(
    State(st): State<SharedState>,
    Json(b): Json<SetBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mode = if b.mode.trim().is_empty() {
        None
    } else {
        Some(parse_mode(&b.mode).ok_or_else(|| bad("mode: like 1920x1080@165"))?)
    };
    let all = st.db.machines().map_err(ise)?;
    let group = b.group.as_deref().map(str::trim).filter(|g| !g.is_empty());
    if let Some(g) = group
        && !crate::drivers::group_ok(g)
    {
        return Err(bad("group: letters/digits/_/-, max 32"));
    }
    if group.is_none() && b.ids.is_empty() {
        return Err(bad("pick machines or a group"));
    }
    let macs: Vec<String> = all
        .iter()
        .filter(|m| b.ids.contains(&m.id))
        .map(|m| m.mac.to_lowercase())
        .collect();
    crate::db::edit_json(&*st.db, KEY, |s: &mut Settings| {
        for mac in &macs {
            match mode {
                Some(x) => s.machines.insert(mac.clone(), fmt_mode(x)),
                None => s.machines.remove(mac),
            };
        }
        if let Some(g) = group {
            s.groups.retain(|k, _| !k.eq_ignore_ascii_case(g));
            if let Some(x) = mode {
                s.groups.insert(g.to_string(), fmt_mode(x));
            }
        }
        Ok::<_, String>(())
    })
    .map_err(ise)?
    .map_err(ise)?;
    // Now to every connected machine it concerns (removing a setting changes nothing until Windows' own choice
    // returns at its next boot).
    let s = settings(&st);
    let mut sent = 0;
    for m in all.iter().filter(|m| {
        macs.contains(&m.mac.to_lowercase())
            || group.is_some_and(|g| m.grp.as_deref().is_some_and(|x| x.eq_ignore_ascii_case(g)))
    }) {
        if let Some(x) = effective(&s, m)
            && crate::vnc::command(&m.mac, &command(x))
        {
            sent += 1;
        }
    }
    tracing::info!(
        "display: {} for {} → sent to {sent} connected machine(s)",
        mode.map(fmt_mode).unwrap_or_else(|| "none".into()),
        group.map_or_else(
            || format!("{} machine(s)", macs.len()),
            |g| format!("group {g}")
        )
    );
    Ok(Json(serde_json::json!({"ok": true, "sent": sent})))
}

#[cfg(test)]
#[path = "../tests/unit/display.rs"]
mod tests;
