// inventory.rs — each machine's hardware list (Machines page → Hardware; CSV for all): Windows, board + BIOS, CPU, RAM
// sticks, graphics cards + driver, drives, network cards + link speed, monitors and the display modes each output
// offers. The Remote agent (broom-vnc.cs, BuildInventory) sends it once its connection is up, 2 minutes later (the games
// disks mounted by then) and every 30 minutes; kept in the database per machine (config `inventory:<mac>`), so a
// machine that is off still shows what it was.
// Why: a room of identical PCs is only identical until a part is swapped or a monitor changes; the list shows what each
// PC really has (and the display modes the Display setting may choose from) without walking to it.
use axum::{
    Json, Router,
    extract::{Query, State},
    http::header,
    response::IntoResponse,
    routing,
};
use serde::Deserialize;

use crate::SharedState;
use crate::api::{ApiError, ise};

pub fn routes() -> Router<SharedState> {
    Router::new()
        .route("/api/machines/inventory", routing::get(one))
        .route("/api/machines/inventory.csv", routing::get(csv))
}

/// A report larger than this is dropped (a few KB normally; display modes are capped at 200 per output).
const MAX: usize = 256 << 10;

fn key(mac: &str) -> String {
    format!("inventory:{}", mac.to_lowercase())
}

/// The agent's report `text` for machine `mac`: checked, stamped with the time, kept. Blocking (a database write).
pub fn store(st: &SharedState, mac: &str, text: &str) {
    if text.len() > MAX {
        tracing::warn!("inventory of {mac}: {} bytes, dropped", text.len());
        return;
    }
    let Ok(mut v) = serde_json::from_str::<serde_json::Value>(text) else {
        return;
    };
    if v["t"] != "inventory" {
        return;
    }
    if let Some(o) = v.as_object_mut() {
        o.remove("t");
        o.insert("at".into(), crate::now_secs().into());
    }
    if let Err(e) = st.db.set_config(&key(mac), &v.to_string()) {
        tracing::warn!("inventory of {mac} not kept: {e}");
    }
}

/// Machine `mac`'s last hardware list (None = its agent never sent one).
pub fn get(st: &SharedState, mac: &str) -> Option<serde_json::Value> {
    serde_json::from_str(&st.db.get_config(&key(mac), "")).ok()
}

/// The display modes machine `mac`'s outputs offer, (width, height, refresh), each once, largest first.
pub fn modes(st: &SharedState, mac: &str) -> Vec<(u64, u64, u64)> {
    let mut out: Vec<(u64, u64, u64)> = Vec::new();
    for d in get(st, mac)
        .and_then(|v| v["displays"].as_array().cloned())
        .unwrap_or_default()
    {
        for m in d["modes"].as_array().cloned().unwrap_or_default() {
            let n = |i: usize| m[i].as_u64().unwrap_or(0);
            let t = (n(0), n(1), n(2));
            if t.0 > 0 && t.1 > 0 && !out.contains(&t) {
                out.push(t);
            }
        }
    }
    out.sort_by(|a, b| b.cmp(a));
    out
}

#[derive(Deserialize)]
struct IdQuery {
    id: i64,
}

/// GET /api/machines/inventory?id= → {machine, inventory (null = none yet)}.
async fn one(
    State(st): State<SharedState>,
    Query(q): Query<IdQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let m = crate::machines::machine_by_id(&st, q.id)?;
    let modes: Vec<String> = modes(&st, &m.mac)
        .into_iter()
        .map(|(w, h, hz)| format!("{w}x{h}@{hz}"))
        .collect();
    Ok(Json(serde_json::json!({
        "machine": crate::machines::who(&m),
        "inventory": get(&st, &m.mac),
        "display": crate::display::info(&st, &m),
        "modes": modes,
    })))
}

/// One CSV field: quoted, quotes doubled; a leading = + - @ neutralised (a spreadsheet would run it as a formula).
fn field(s: &str) -> String {
    let s = if s.starts_with(['=', '+', '-', '@']) {
        format!("'{s}")
    } else {
        s.to_string()
    };
    format!("\"{}\"", s.replace('"', "\"\""))
}

/// One machine's row (summary of its list): the columns of `csv`.
pub(crate) fn row(name: &str, mac: &str, grp: &str, v: Option<&serde_json::Value>) -> String {
    let s = |k: &str| v.and_then(|v| v[k].as_str()).unwrap_or("").to_string();
    let list = |k: &str, f: &dyn Fn(&serde_json::Value) -> String| -> String {
        v.and_then(|v| v[k].as_array())
            .map(|a| {
                a.iter()
                    .map(f)
                    .filter(|x| !x.is_empty())
                    .collect::<Vec<_>>()
                    .join("; ")
            })
            .unwrap_or_default()
    };
    let gb = |b: u64| format!("{:.0} GB", b as f64 / (1u64 << 30) as f64);
    let ram_total = v
        .and_then(|v| v["ram_total"].as_u64())
        .map(gb)
        .unwrap_or_default();
    let cols = [
        name.to_string(),
        mac.to_string(),
        grp.to_string(),
        format!("{} {}", s("maker"), s("model")).trim().to_string(),
        s("board"),
        s("bios"),
        list("cpus", &|c| {
            format!(
                "{} ({}C/{}T)",
                c["name"].as_str().unwrap_or(""),
                c["cores"].as_u64().unwrap_or(0),
                c["threads"].as_u64().unwrap_or(0)
            )
        }),
        ram_total,
        list("ram", &|r| {
            format!(
                "{} {} {} MT/s {}",
                r["slot"].as_str().unwrap_or(""),
                gb(r["size"].as_u64().unwrap_or(0)),
                r["speed"].as_u64().unwrap_or(0),
                r["part"].as_str().unwrap_or("")
            )
            .trim()
            .to_string()
        }),
        list("gpus", &|g| {
            format!(
                "{} (driver {})",
                g["name"].as_str().unwrap_or(""),
                g["driver"].as_str().unwrap_or("")
            )
        }),
        list("drives", &|d| {
            format!(
                "{} {}",
                d["model"].as_str().unwrap_or(""),
                gb(d["size"].as_u64().unwrap_or(0))
            )
        }),
        list("nics", &|n| {
            let mbps = n["speed"].as_u64().unwrap_or(0) / 1_000_000;
            format!(
                "{} {}{}",
                n["name"].as_str().unwrap_or(""),
                if mbps > 0 {
                    format!("{mbps} Mb/s")
                } else {
                    String::new()
                },
                if n["up"].as_bool() == Some(true) {
                    ""
                } else {
                    " (down)"
                }
            )
        }),
        list("monitors", &|m| {
            format!(
                "{} {}",
                m["maker"].as_str().unwrap_or(""),
                m["name"].as_str().unwrap_or("")
            )
            .trim()
            .to_string()
        }),
        list("displays", &|d| {
            format!(
                "{}x{} @ {} Hz",
                d["w"].as_u64().unwrap_or(0),
                d["h"].as_u64().unwrap_or(0),
                d["hz"].as_u64().unwrap_or(0)
            )
        }),
        format!("{} {}", s("os"), s("build")).trim().to_string(),
        v.and_then(|v| v["at"].as_u64())
            .map(|t| t.to_string())
            .unwrap_or_default(),
    ];
    cols.iter().map(|c| field(c)).collect::<Vec<_>>().join(",")
}

pub(crate) const CSV_HEADER: &str = "hostname,mac,group,maker_model,board,bios,cpu,ram,ram_sticks,gpus,drives,nics,monitors,displays,windows,reported_unix";

/// GET /api/machines/inventory.csv — one row per registered machine.
async fn csv(State(st): State<SharedState>) -> Result<impl IntoResponse, ApiError> {
    let ms = st.db.machines().map_err(ise)?;
    let mut out = String::from(CSV_HEADER);
    out.push('\n');
    for m in &ms {
        let v = get(&st, &m.mac);
        out.push_str(&row(
            m.hostname.as_deref().unwrap_or(""),
            &m.mac,
            m.grp.as_deref().unwrap_or(""),
            v.as_ref(),
        ));
        out.push('\n');
    }
    Ok((
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"broom-hardware.csv\"",
            ),
        ],
        out,
    ))
}

#[cfg(test)]
#[path = "../tests/unit/inventory.rs"]
mod tests;
