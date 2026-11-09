// power.rs — turn machines on, restart them, shut them down (Machines page): one, a selection or a whole group.
// Turn on = Wake-on-LAN (wol.rs; the PC's firmware must have it on). Restart / shut down / cancel = a signed command
// to the machine's Remote agent (vnc.rs → broom-vnc.cs runs Windows' shutdown.exe with a countdown and a message on
// screen), so only machines whose agent is connected; the others are reported, not guessed at.
// Why through the agent: a lounge PC opens no port (no WMI / RDP / remote shutdown service to secure); the agent
// already holds an authenticated connection to the server, so a command reaches only the machine it was meant for,
// and Windows' own countdown warns a customer before the PC goes down.
use axum::{Json, Router, extract::State, routing::post};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::LazyLock;

use crate::SharedState;
use crate::api::{ApiError, bad, ise};

pub fn routes() -> Router<SharedState> {
    Router::new().route("/api/power", post(power))
}

/// The longest countdown a restart / shutdown may have (shutdown.exe takes up to 10 years; a lounge needs minutes).
pub(crate) const MAX_DELAY: u32 = 600;
/// The message shown with the countdown, at most this many characters.
const MAX_MSG: usize = 200;
/// A pending action is shown this long after it was sent, beyond its countdown (the machine going down and, for a
/// restart, coming back).
const SHOW_FOR: u64 = 180;

/// The last power action sent to a machine, for the Machines page while it plays out.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub(crate) struct Pending {
    /// on / restart / shutdown / cancel
    pub what: String,
    /// Unix time it was sent.
    pub at: u64,
    /// Its countdown, seconds (0 for on / cancel).
    pub delay: u32,
}

static PENDING: LazyLock<Mutex<HashMap<String, Pending>>> = LazyLock::new(Default::default);

/// Machine `mac`'s last power action while it is still playing out; None after that.
pub(crate) fn pending(mac: &str) -> Option<Pending> {
    let now = crate::now_secs();
    let mut p = PENDING.lock();
    let mac = mac.to_lowercase();
    match p.get(&mac) {
        Some(x) if now <= x.at + u64::from(x.delay) + SHOW_FOR => Some(x.clone()),
        Some(_) => {
            p.remove(&mac);
            None
        }
        None => None,
    }
}

#[derive(Deserialize)]
struct PowerBody {
    /// on / restart / shutdown / cancel
    action: String,
    /// The machines (ids), or every machine of `group`.
    #[serde(default)]
    ids: Vec<i64>,
    #[serde(default)]
    group: Option<String>,
    /// Countdown before a restart / shutdown, seconds (default 30).
    #[serde(default)]
    delay: Option<u32>,
    /// Shown on the machine's screen with the countdown.
    #[serde(default)]
    msg: Option<String>,
}

#[derive(Serialize, Debug, PartialEq)]
pub(crate) struct Outcome {
    pub id: i64,
    pub name: String,
    pub ok: bool,
    pub msg: String,
}

/// The message as the agent gets it: one line, no quotes or backslashes (it ends up in shutdown.exe's /c "…"), at
/// most MAX_MSG characters.
pub(crate) fn clean_msg(m: &str) -> String {
    m.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .filter(|c| !matches!(c, '"' | '\\' | '%' | '^' | '&' | '|' | '<' | '>'))
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(MAX_MSG)
        .collect()
}

/// The command for the agent (vnc.rs signs it on the way).
pub(crate) fn agent_command(what: &str, delay: u32, msg: &str) -> String {
    serde_json::json!({"op": "power", "do": what, "delay": delay.min(MAX_DELAY), "msg": msg})
        .to_string()
}

/// POST /api/power {action, ids | group, delay?, msg?} → {results: [{id, name, ok, msg}], done: n}. Staff may (a
/// lounge restarts PCs all day).
async fn power(
    State(st): State<SharedState>,
    Json(b): Json<PowerBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let what = b.action.as_str();
    if !matches!(what, "on" | "restart" | "shutdown" | "cancel") {
        return Err(bad("action: on, restart, shutdown or cancel"));
    }
    let delay = b.delay.unwrap_or(30);
    if delay > MAX_DELAY {
        return Err(bad(format!("delay: 0 to {MAX_DELAY} seconds")));
    }
    let msg = clean_msg(b.msg.as_deref().unwrap_or(""));
    let all = st.db.machines().map_err(ise)?;
    let picked: Vec<_> = match &b.group {
        Some(g) if !g.trim().is_empty() => all
            .into_iter()
            .filter(|m| {
                m.grp
                    .as_deref()
                    .is_some_and(|x| x.eq_ignore_ascii_case(g.trim()))
            })
            .collect(),
        _ => all.into_iter().filter(|m| b.ids.contains(&m.id)).collect(),
    };
    if picked.is_empty() {
        return Err(bad("no machine picked (ids or a group with machines)"));
    }
    let mut results = Vec::new();
    for m in &picked {
        let who = crate::machines::who(m);
        let mac = m.mac.to_lowercase();
        let (ok, text) = match what {
            "on" => match crate::wol::wake(&*st.db, &m.mac) {
                Ok(()) => (true, "Wake-on-LAN sent".to_string()),
                Err(e) => (false, format!("Wake-on-LAN failed: {e}")),
            },
            _ if !crate::vnc::connected(&mac) => (
                false,
                "no Broom agent connected (off, still starting, or not running Broom's agent)"
                    .to_string(),
            ),
            _ => {
                let d = if what == "cancel" { 0 } else { delay };
                if crate::vnc::command(&mac, &agent_command(what, d, &msg)) {
                    let t = match what {
                        "cancel" => "cancel sent".to_string(),
                        _ if d == 0 => format!("{what} now"),
                        _ => format!("{what} in {d} s"),
                    };
                    (true, t)
                } else {
                    (
                        false,
                        "the agent's connection is busy - try again".to_string(),
                    )
                }
            }
        };
        if ok {
            let d = if matches!(what, "restart" | "shutdown") {
                delay
            } else {
                0
            };
            PENDING.lock().insert(
                mac.clone(),
                Pending {
                    what: what.to_string(),
                    at: crate::now_secs(),
                    delay: d,
                },
            );
            tracing::info!("power: {what} → {who} ({text})");
        } else {
            tracing::warn!("power: {what} → {who} not done: {text}");
        }
        results.push(Outcome {
            id: m.id,
            name: who,
            ok,
            msg: text,
        });
    }
    let done = results.iter().filter(|r| r.ok).count();
    Ok(Json(
        serde_json::json!({"ok": true, "done": done, "results": results}),
    ))
}

#[cfg(test)]
#[path = "../tests/unit/power.rs"]
mod tests;
