// pkgmgr.rs — what this server's operating system must provide for the VM features (Maintain in the browser, Add
// hardware), and installing it from the web admin. Everything else Broom does is built in; only the VM needs programs
// from the distribution: QEMU and OVMF. Its disk comes from Broom's own daemon over NBD, and Add hardware hands its job
// to the VM over HTTP: no open-iscsi, no ntfs-3g.
// The page shows the package manager found on the server (apt, dnf, yum), what is missing and the exact command; an
// owner presses Install and the command runs as this process (root), its output shown live. One install at a time.
// Another package manager (pacman, zypper, apk…) is named but not driven: package names differ too much to guess.
use axum::{
    Json, Router,
    routing::{get, post},
};
use parking_lot::Mutex;
use serde::Serialize;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use crate::SharedState;
use crate::api::{ApiError, bad, ise};

pub fn routes() -> Router<SharedState> {
    Router::new()
        .route("/api/packages", get(status))
        .route("/api/packages/install", post(install))
}

/// The package managers Broom drives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mgr {
    Apt,
    Dnf,
    Yum,
}

impl Mgr {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Mgr::Apt => "apt",
            Mgr::Dnf => "dnf",
            Mgr::Yum => "yum",
        }
    }

    /// The program that is run (looked up in the usual system folders).
    fn program(self) -> &'static str {
        match self {
            Mgr::Apt => "apt-get",
            Mgr::Dnf => "dnf",
            Mgr::Yum => "yum",
        }
    }
}

/// What the VM features need from the system.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Pkg {
    Qemu,
    Ovmf,
}

impl Pkg {
    /// How the page names it.
    pub(crate) fn what(self) -> &'static str {
        match self {
            Pkg::Qemu => "QEMU (qemu-system-x86_64)",
            Pkg::Ovmf => "OVMF (UEFI firmware for QEMU)",
        }
    }
}

/// The package that holds `p` on a system using `m`.
pub(crate) fn package(m: Mgr, p: Pkg) -> &'static str {
    match (m, p) {
        (Mgr::Apt, Pkg::Qemu) => "qemu-system-x86",
        (Mgr::Apt, Pkg::Ovmf) => "ovmf",
        (_, Pkg::Qemu) => "qemu-kvm",
        (_, Pkg::Ovmf) => "edk2-ovmf",
    }
}

/// The package manager of this system: the first of apt, dnf, yum whose program `has` finds.
pub(crate) fn detect(has: impl Fn(&str) -> bool) -> Option<Mgr> {
    [Mgr::Apt, Mgr::Dnf, Mgr::Yum]
        .into_iter()
        .find(|m| has(m.program()))
}

/// A package manager Broom does not drive, for the page to name (None = none of them found either).
pub(crate) fn other_manager(has: impl Fn(&str) -> bool) -> Option<&'static str> {
    ["zypper", "pacman", "apk", "xbps-install", "emerge"]
        .into_iter()
        .find(|p| has(p))
}

/// PRETTY_NAME of an os-release file ("Ubuntu 24.04.1 LTS"), "" when it has none.
pub(crate) fn os_name(os_release: &str) -> String {
    os_release
        .lines()
        .find_map(|l| l.strip_prefix("PRETTY_NAME="))
        .map(|v| v.trim().trim_matches(['"', '\'']).to_string())
        .unwrap_or_default()
}

/// What the VM needs that is not on the system, given which requirements `present` finds.
pub(crate) fn missing_with(present: impl Fn(Pkg) -> bool) -> Vec<Pkg> {
    [Pkg::Qemu, Pkg::Ovmf]
        .into_iter()
        .filter(|p| !present(*p))
        .collect()
}

/// What is missing on this server now.
pub(crate) fn missing() -> Vec<Pkg> {
    use crate::onboard::{ovmf, qemu};
    missing_with(|p| match p {
        Pkg::Qemu => qemu().is_some(),
        Pkg::Ovmf => ovmf().is_some(),
    })
}

/// The commands that install `missing` with `m`, one after the other: program + arguments of each.
pub(crate) fn steps(m: Mgr, missing: &[Pkg]) -> Vec<Vec<String>> {
    let mut pkgs: Vec<String> = Vec::new();
    for p in missing {
        let n = package(m, *p).to_string();
        if !pkgs.contains(&n) {
            pkgs.push(n);
        }
    }
    if pkgs.is_empty() {
        return Vec::new();
    }
    let word = |s: &str| s.to_string();
    let mut install = vec![word(m.program()), word("install"), word("-y")];
    install.extend(pkgs);
    match m {
        // A new server's package lists are often empty or old: refresh them first.
        Mgr::Apt => vec![vec![word("apt-get"), word("update")], install],
        Mgr::Dnf | Mgr::Yum => vec![install],
    }
}

/// `steps` as one line for people ("apt-get update && apt-get install -y …").
pub(crate) fn command_line(steps: &[Vec<String>]) -> String {
    steps
        .iter()
        .map(|s| s.join(" "))
        .collect::<Vec<_>>()
        .join(" && ")
}

/// What to do about `missing` on this server, for a message: press Install, or install by hand.
pub(crate) fn advice(missing: &[Pkg]) -> String {
    match detect(|p| crate::onboard::which(p).is_some()) {
        Some(m) => format!(
            "press Install on the Diskless page, or run: {}",
            command_line(&steps(m, missing))
        ),
        None => format!(
            "install them with your package manager ({})",
            missing
                .iter()
                .map(|p| p.what())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

// ---------- the install job ----------

/// Longest an install may run (a slow mirror, a big update): then it is stopped.
const TIMEOUT: Duration = Duration::from_secs(20 * 60);
/// Output lines kept for the page (the newest), each cut to this many characters.
const LOG_LINES: usize = 300;
const LINE_CHARS: usize = 300;

#[derive(Clone, Serialize, Default, Debug)]
pub(crate) struct Job {
    /// running | done | failed
    pub state: &'static str,
    pub command: String,
    pub started: u64,
    pub ended: u64,
    pub msg: String,
    pub log: Vec<String>,
}

static JOB: LazyLock<Mutex<Option<Job>>> = LazyLock::new(|| Mutex::new(None));

/// A line of output as the page keeps it: printable text, cut short. None = nothing to keep.
pub(crate) fn clean_line(raw: &str) -> Option<String> {
    // apt and dnf redraw progress with carriage returns: the last redraw is the line.
    let last = raw.rsplit('\r').find(|p| !p.trim().is_empty())?;
    let t: String = last
        .chars()
        .filter(|c| !c.is_control())
        .take(LINE_CHARS)
        .collect();
    let t = t.trim_end().to_string();
    (!t.is_empty()).then_some(t)
}

fn push_log(line: String) {
    if let Some(j) = JOB.lock().as_mut() {
        j.log.push(line);
        if j.log.len() > LOG_LINES {
            j.log.remove(0);
        }
    }
}

fn finish(state: &'static str, msg: String) {
    if let Some(j) = JOB.lock().as_mut() {
        j.state = state;
        j.msg = msg;
        j.ended = crate::now_secs();
    }
}

/// Run one step to its end (or `deadline`), its output into the job's log. Err = what went wrong.
fn run_step(step: &[String], deadline: Instant) -> Result<(), String> {
    let program =
        crate::onboard::which(&step[0]).ok_or(format!("{} is not on this server", step[0]))?;
    let mut child = Command::new(program)
        .args(&step[1..])
        .env("DEBIAN_FRONTEND", "noninteractive")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{}: {e}", step[0]))?;
    let mut readers = Vec::new();
    if let Some(o) = child.stdout.take() {
        readers.push(std::thread::spawn(move || pump(o)));
    }
    if let Some(e) = child.stderr.take() {
        readers.push(std::thread::spawn(move || pump(e)));
    }
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "{} took longer than {} minutes: stopped",
                    step[0],
                    TIMEOUT.as_secs() / 60
                ));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(300)),
            Err(e) => return Err(format!("{}: {e}", step[0])),
        }
    };
    for r in readers {
        let _ = r.join();
    }
    if status.success() {
        Ok(())
    } else {
        Err(format!("{} failed ({status})", step.join(" ")))
    }
}

/// A stream of the command's output → the job's log, a line at a time (split at '\n' and also at '\r').
fn pump(r: impl std::io::Read) {
    let mut r = BufReader::new(r);
    let mut buf = Vec::new();
    while r.read_until(b'\n', &mut buf).is_ok_and(|n| n > 0) {
        if let Some(l) = clean_line(&String::from_utf8_lossy(&buf)) {
            push_log(l);
        }
        buf.clear();
    }
}

fn worker(steps: Vec<Vec<String>>) {
    let deadline = Instant::now() + TIMEOUT;
    for s in &steps {
        push_log(format!("$ {}", s.join(" ")));
        if let Err(e) = run_step(s, deadline) {
            tracing::warn!("packages: {e}");
            return finish("failed", e);
        }
    }
    let left = missing();
    if left.is_empty() {
        tracing::info!("packages: installed");
        finish("done", "installed".into());
    } else {
        let names: Vec<&str> = left.iter().map(|p| p.what()).collect();
        let e = format!("the command ran, but still missing: {}", names.join(", "));
        tracing::warn!("packages: {e}");
        finish("failed", e);
    }
}

// ---------- web ----------

/// GET /api/packages → the package manager, what is missing, the command, the last install.
async fn status() -> Result<Json<serde_json::Value>, ApiError> {
    tokio::task::spawn_blocking(|| {
        let has = |p: &str| crate::onboard::which(p).is_some();
        let mgr = detect(has);
        let miss = missing();
        let os = std::fs::read_to_string("/etc/os-release")
            .map(|t| os_name(&t))
            .unwrap_or_default();
        serde_json::json!({
            "os": os,
            "manager": mgr.map(Mgr::name),
            "other": if mgr.is_none() { other_manager(has) } else { None },
            "supported": mgr.is_some(),
            "missing": miss.iter().map(|p| serde_json::json!({
                "what": p.what(),
                "package": mgr.map(|m| package(m, *p)),
            })).collect::<Vec<_>>(),
            "command": mgr.map(|m| command_line(&steps(m, &miss))),
            "hint": if mgr.is_none() && !miss.is_empty() { Some(advice(&miss)) } else { None },
            "kvm": Path::new("/dev/kvm").exists(),
            "job": JOB.lock().clone(),
        })
    })
    .await
    .map(Json)
    .map_err(ise)
}

/// POST /api/packages/install (owner: a command that runs as root) — installs what is missing.
async fn install() -> Result<Json<serde_json::Value>, ApiError> {
    if !crate::preflight::is_root() {
        return Err(bad("Broom must run as root to install packages"));
    }
    let planned = tokio::task::spawn_blocking(|| {
        let mgr = detect(|p| crate::onboard::which(p).is_some()).ok_or(
            "no apt, dnf or yum on this server: install the packages with its own package manager",
        )?;
        let miss = missing();
        let steps = steps(mgr, &miss);
        if steps.is_empty() {
            return Err("nothing is missing");
        }
        Ok(steps)
    })
    .await
    .map_err(ise)?
    .map_err(bad)?;
    {
        let mut job = JOB.lock();
        if job.as_ref().is_some_and(|j| j.state == "running") {
            return Err((
                axum::http::StatusCode::CONFLICT,
                "an install is already running".into(),
            ));
        }
        *job = Some(Job {
            state: "running",
            command: command_line(&planned),
            started: crate::now_secs(),
            ..Job::default()
        });
    }
    tracing::info!("packages: running {}", command_line(&planned));
    std::thread::spawn(move || worker(planned));
    Ok(crate::api::ok())
}

#[cfg(test)]
#[path = "../tests/unit/pkgmgr.rs"]
mod tests;
