// groups.rs — the Groups page: machine groups and what each one gets. A group is a name, kept where it is used: a
// machine's group (one per machine), and the groups of each image / games disk (none = every machine) and driver
// package. Groups created on the page with nothing in them yet are kept in the config table (groups, JSON).
// Changes made here go through the same rules as on each resource's own page: a driver change re-arms the license
// keys of the machines whose driver set changes (their base is rebuilt), a games disk change goes to the iSCSI daemon.
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    routing::{get, post},
};
use serde::Deserialize;

use crate::SharedState;
use crate::api::{ApiError, bad, ise, ok};
use crate::machines::who;

pub fn routes() -> Router<SharedState> {
    Router::new()
        .route("/api/groups", get(list))
        .route("/api/groups/create", post(create))
        .route("/api/groups/rename", post(rename))
        .route("/api/groups/delete", post(delete))
        .route("/api/groups/set", post(set))
        .route("/api/groups/new-machines", post(set_new_machines))
}

fn saved(st: &SharedState) -> Vec<String> {
    serde_json::from_str(&st.db.get_config("groups", "[]")).unwrap_or_default()
}

/// A list of group names kept in config `key` — the groups made here ("groups"), those hiding their machines' other
/// disks ("hide_disks_groups"), those exempt from the DNS check ("dns_exempt_groups") — changed as one step.
pub(crate) fn edit_names(
    st: &SharedState,
    key: &str,
    f: impl FnOnce(&mut Vec<String>),
) -> Result<(), ApiError> {
    crate::db::edit_json(&*st.db, key, |v: &mut Vec<String>| {
        f(v);
        Ok::<(), ApiError>(())
    })
    .map_err(ise)?
}

/// Every name list a group appears in: `from` renamed to `to` (None = removed).
fn rename_everywhere(st: &SharedState, from: &str, to: Option<&str>) -> Result<(), ApiError> {
    for key in ["groups", "hide_disks_groups", "dns_exempt_groups"] {
        edit_names(st, key, |v| *v = swap(v, from, to))?;
    }
    crate::pins::rename_group(st, from, to)?; // the versions it is held on follow it
    rename_new_machines(st, from, to)
}

fn same(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

fn name_ok(name: &str) -> Result<String, ApiError> {
    let n = name.trim();
    if crate::drivers::group_ok(n) {
        Ok(n.to_string())
    } else {
        Err(bad(format!("group {n:?}: letters/digits/_/-, max 32")))
    }
}

/// Every group in use or created here, one spelling each, sorted.
fn all(st: &SharedState) -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    let mut add = |g: &str| {
        if !g.is_empty() && !v.iter().any(|x| same(x, g)) {
            v.push(g.to_string());
        }
    };
    saved(st).iter().for_each(|g| add(g));
    st.db
        .machines()
        .unwrap_or_default()
        .iter()
        .filter_map(|m| m.grp.as_deref())
        .for_each(&mut add);
    st.db
        .images()
        .unwrap_or_default()
        .iter()
        .flat_map(|i| i.groups.iter())
        .for_each(|g| add(g));
    crate::games::disks(st)
        .iter()
        .flat_map(|d| d.groups.iter())
        .for_each(|g| add(g));
    st.db
        .drivers()
        .unwrap_or_default()
        .iter()
        .flat_map(|d| d.groups.iter())
        .for_each(|g| add(g));
    crate::diskless::goldens(st)
        .iter()
        .flat_map(|g| g.groups.iter())
        .for_each(|g| add(g));
    v.sort_by_key(|g| g.to_ascii_lowercase());
    v
}

/// GET /api/groups — the groups, and every machine / image / games disk / driver package with its groups (the page
/// works out each group's connections).
async fn list(State(st): State<SharedState>) -> Json<serde_json::Value> {
    let machines: Vec<_> = st
        .db
        .machines()
        .unwrap_or_default()
        .iter()
        .map(|m| serde_json::json!({"id": m.id, "name": who(m), "grp": m.grp}))
        .collect();
    let images: Vec<_> = st
        .db
        .images()
        .unwrap_or_default()
        .iter()
        .map(|i| serde_json::json!({"id": i.id, "name": i.name, "os": i.os, "groups": i.groups}))
        .collect();
    // The versions kept of each golden / games disk (version pickers).
    let (dl, gs) = tokio::task::spawn_blocking(|| {
        (
            crate::iscsi::diskless_status().unwrap_or_default(),
            crate::iscsi::games_status().unwrap_or_default(),
        )
    })
    .await
    .unwrap_or_default();
    let kept = |i: Option<&crate::iscsid::games::Info>| -> Vec<u64> {
        i.map(|i| {
            let mut v: Vec<u64> = i.versions.iter().map(|x| x.ver).collect();
            if v.is_empty() {
                v.push(i.ver);
            }
            v
        })
        .unwrap_or_default()
    };
    let disks: Vec<_> = crate::games::disks(&st)
        .iter()
        .map(|d| {
            serde_json::json!({"name": d.name, "letter": d.letter, "groups": d.groups, "pins": d.pins,
                "versions": kept(gs.iter().find(|x| x.name == d.name))})
        })
        .collect();
    let drivers: Vec<_> = st.db.drivers().unwrap_or_default().iter().map(|d| serde_json::json!({"id": d.id, "name": d.name, "all": d.all_machines, "groups": d.groups})).collect();
    // Diskless goldens: their groups' machines boot them (no group = no machine).
    let goldens: Vec<_> = crate::diskless::goldens(&st)
        .iter()
        .map(|g| {
            serde_json::json!({"name": g.name, "os": g.os, "groups": g.groups, "pins": g.pins,
                "versions": kept(dl.iter().find(|x| !x.games && x.disk.name == g.name).map(|x| &x.disk))})
        })
        .collect();
    Json(serde_json::json!({
        "groups": all(&st), "machines": machines, "images": images, "disks": disks, "drivers": drivers,
        "goldens": goldens,
        "hide_disks": crate::disks::hidden_groups(&st),
        "new_machines": crate::machines::new_group(&st),
    }))
}

#[derive(Deserialize)]
struct NewMachinesBody {
    /// "" / null = off.
    #[serde(default)]
    group: Option<String>,
}

/// POST /api/groups/new-machines {group} — an unknown PC that network-boots joins `group` by itself (named
/// NEW-<end of its MAC>, its current IP as fixed IP) and waits there for an admin to move it to its group; its disks
/// are never partitioned without asking meanwhile. Empty = off (machines are registered by hand). The group is
/// created when it is new.
async fn set_new_machines(
    State(st): State<SharedState>,
    axum::Extension(w): axum::Extension<crate::auth::Who>,
    Json(b): Json<NewMachinesBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let g = b.group.as_deref().map(str::trim).unwrap_or("");
    if let Some(cur) = crate::machines::new_group(&st)
        && !same(&cur, g)
    {
        waiting_none(&st, &cur)?;
    }
    if g.is_empty() {
        st.db
            .set_config(crate::machines::NEW_GROUP_KEY, "")
            .map_err(ise)?;
        tracing::info!("{}: new machines are registered by hand again", w.name);
        return Ok(ok());
    }
    let name = name_ok(g)?;
    // One spelling: an existing group keeps its own.
    let name = all(&st)
        .into_iter()
        .find(|x| same(x, &name))
        .unwrap_or(name);
    edit_names(&st, "groups", |v| {
        if !v.iter().any(|x| same(x, &name)) {
            v.push(name.clone());
        }
    })?;
    st.db
        .set_config(crate::machines::NEW_GROUP_KEY, &name)
        .map_err(ise)?;
    tracing::warn!(
        "{}: unknown PCs that network-boot now join group {name} by themselves",
        w.name
    );
    Ok(ok())
}

/// Machines waiting in the new-machines group `cur` are never let out of it by changing or deleting the setting: they
/// would become ordinary machines (no group, or still in `cur`) whose disks may be partitioned without asking. The
/// admin moves them (Devices / Groups page) or deletes them first.
fn waiting_none(st: &SharedState, cur: &str) -> Result<(), ApiError> {
    let n = st
        .db
        .machines()
        .map_err(ise)?
        .iter()
        .filter(|m| crate::machines::waiting(m, Some(cur)))
        .count();
    if n > 0 {
        return Err(bad(format!(
            "{n} machine(s) still wait in group {cur}: move them to their groups (Devices / Groups page) or delete them first"
        )));
    }
    Ok(())
}

/// The new-machines group renamed (`to`) or deleted (None → off).
fn rename_new_machines(st: &SharedState, from: &str, to: Option<&str>) -> Result<(), ApiError> {
    let cur = st.db.get_config(crate::machines::NEW_GROUP_KEY, "");
    if !cur.is_empty() && same(&cur, from) {
        st.db
            .set_config(crate::machines::NEW_GROUP_KEY, to.unwrap_or(""))
            .map_err(ise)?;
    }
    Ok(())
}

#[derive(Deserialize)]
struct NameBody {
    name: String,
}

/// POST /api/groups/create {name} — a new, empty group.
async fn create(
    State(st): State<SharedState>,
    Json(b): Json<NameBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let name = name_ok(&b.name)?;
    if all(&st).iter().any(|g| same(g, &name)) {
        return Err(bad(format!("group {name} already exists")));
    }
    edit_names(&st, "groups", |v| {
        if !v.iter().any(|g| same(g, &name)) {
            v.push(name.clone());
        }
    })?;
    tracing::info!("group {name} created");
    Ok(ok())
}

/// `groups` with `from` replaced by `to` (None = removed), no duplicate left.
fn swap(groups: &[String], from: &str, to: Option<&str>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for g in groups {
        let g = if same(g, from) {
            match to {
                Some(t) => t,
                None => continue,
            }
        } else {
            g.as_str()
        };
        if !out.iter().any(|x| same(x, g)) {
            out.push(g.to_string());
        }
    }
    out
}

/// Apply `f` (groups → new groups) to every image, games disk and driver package, and `machine` (a machine's group →
/// its new one) to every machine. `allow_all`: an image / games disk may lose its last group (= every machine gets
/// it); otherwise that is refused, nothing changed, with their names.
fn apply(
    st: &SharedState,
    f: &dyn Fn(&str, &[String]) -> Vec<String>,
    machine: &dyn Fn(&crate::db::Machine) -> Option<String>,
    allow_all: bool,
) -> Result<(), ApiError> {
    let images = st.db.images().map_err(ise)?;
    let disks = crate::games::disks(st);
    if !allow_all {
        let to_all: Vec<String> = images
            .iter()
            .filter(|i| !i.groups.is_empty() && f(&format!("i{}", i.id), &i.groups).is_empty())
            .map(|i| format!("image {}", i.name))
            .chain(
                disks
                    .iter()
                    .filter(|d| {
                        !d.groups.is_empty() && f(&format!("d{}", d.name), &d.groups).is_empty()
                    })
                    .map(|d| format!("iSCSI disk {}", d.name)),
            )
            .collect();
        if !to_all.is_empty() {
            return Err((
                StatusCode::CONFLICT,
                format!(
                    "{} would go to EVERY machine (no group left)",
                    to_all.join(", ")
                ),
            ));
        }
    }
    // The iSCSI disks first, as one step: two a machine could both get can't share a drive letter — a clash writes
    // nothing at all.
    crate::games::edit(st, |list| {
        for d in list.iter_mut() {
            d.groups = f(&format!("d{}", d.name), &d.groups);
        }
        for a in list.iter() {
            if let Some(b) = list.iter().find(|b| crate::games::clash(a, b)) {
                return Err(bad(format!(
                    "iSCSI disks {} and {} would share drive {}: on the same machines",
                    a.name, b.name, a.letter
                )));
            }
        }
        Ok(())
    })?;
    for i in &images {
        let g = f(&format!("i{}", i.id), &i.groups);
        if g != i.groups {
            st.db.set_image_groups(i.id, &g).map_err(ise)?;
        }
    }
    for d in st.db.drivers().map_err(ise)? {
        let g = f(&format!("r{}", d.id), &d.groups);
        if g != d.groups {
            st.db
                .set_driver_targets(d.id, d.all_machines, &g)
                .map_err(ise)?;
        }
    }
    for m in st.db.machines().map_err(ise)? {
        let g = machine(&m);
        if g != m.grp {
            st.db.set_machine_group(m.id, g.as_deref()).map_err(ise)?;
        }
    }
    // Diskless goldens (no group = no machine: losing the last one is fine).
    crate::diskless::edit_groups(st, &|name, g| f(&format!("g{name}"), g))?;
    Ok(())
}

#[derive(Deserialize)]
struct RenameBody {
    from: String,
    to: String,
}

/// POST /api/groups/rename {from, to} — everywhere (machines, images, games disks, drivers). Into an existing group =
/// the two merged.
async fn rename(
    State(st): State<SharedState>,
    Json(b): Json<RenameBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let to = name_ok(&b.to)?;
    let from = b.from.trim().to_string();
    // Merged into another group, the new-machines group would make that group's machines wait (and unknown PCs get
    // that group's images and goldens): rename it to a new name only.
    if crate::machines::new_group(&st).is_some_and(|c| same(&c, &from))
        && !same(&from, &to)
        && all(&st).iter().any(|g| same(g, &to))
    {
        return Err(bad(format!(
            "group {from} is where new machines wait: it can't be merged into {to}"
        )));
    }
    let st2 = st.clone();
    let (f2, t2) = (from.clone(), to.clone());
    tokio::task::spawn_blocking(move || {
        apply(
            &st2,
            &|_, g| swap(g, &f2, Some(&t2)),
            &|m| {
                m.grp
                    .as_ref()
                    .map(|g| if same(g, &f2) { t2.clone() } else { g.clone() })
            },
            true,
        )?;
        rename_everywhere(&st2, &f2, Some(&t2))
    })
    .await
    .map_err(ise)??;
    sync_games(&st).await;
    tracing::info!("group {from} renamed to {to}");
    Ok(ok())
}

/// POST /api/groups/delete {name} — its machines get no group; it leaves every image / games disk / driver. Refused
/// while an image or games disk is only for this group (it would go to every machine), and while machines wait in it
/// when it is the new-machines group.
async fn delete(
    State(st): State<SharedState>,
    Json(b): Json<NameBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let name = b.name.trim().to_string();
    if crate::machines::new_group(&st).is_some_and(|c| same(&c, &name)) {
        waiting_none(&st, &name)?;
    }
    let (st2, n2) = (st.clone(), name.clone());
    tokio::task::spawn_blocking(move || {
        apply(
            &st2,
            &|_, g| swap(g, &n2, None),
            &|m| m.grp.clone().filter(|g| !same(g, &n2)),
            false,
        )?;
        rename_everywhere(&st2, &n2, None)
    })
    .await
    .map_err(ise)??;
    sync_games(&st).await;
    tracing::info!("group {name} deleted");
    Ok(ok())
}

#[derive(Deserialize)]
struct SetBody {
    name: String,
    /// Machine ids in the group (a machine has one group: one picked here leaves its old one).
    #[serde(default)]
    machines: Vec<i64>,
    #[serde(default)]
    images: Vec<i64>,
    /// Games disk names.
    #[serde(default)]
    disks: Vec<String>,
    /// Driver package ids.
    #[serde(default)]
    drivers: Vec<i64>,
    /// An image / games disk may lose its last group (then every machine gets it).
    #[serde(default)]
    allow_all: bool,
    /// Its machines hide their other disks from the guest (disks.rs); None = unchanged.
    #[serde(default)]
    hide_disks: Option<bool>,
    /// Diskless golden names its machines boot; None = unchanged (a client that doesn't know them).
    #[serde(default)]
    goldens: Option<Vec<String>>,
    /// The version it gets of a golden ("g<name>") / iSCSI disk ("d<name>"): a number holds it there, null = the
    /// newest (pins.rs). Ones not listed are unchanged.
    #[serde(default)]
    versions: Option<std::collections::BTreeMap<String, Option<u64>>>,
}

/// POST /api/groups/set {name, machines, images, disks, drivers, allow_all} — exactly these are the group's. Images /
/// games disks for every machine (no group) are left as they are: limit them on their own page.
async fn set(
    State(st): State<SharedState>,
    Json(b): Json<SetBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let name = name_ok(&b.name)?;
    let (st2, n2) = (st.clone(), name.clone());
    tokio::task::spawn_blocking(move || {
        let want = |key: &str| match key.split_at(1) {
            ("i", id) => b.images.iter().any(|x| x.to_string() == id),
            ("d", d) => b.disks.iter().any(|x| x == d),
            ("r", id) => b.drivers.iter().any(|x| x.to_string() == id),
            _ => false,
        };
        let f = |key: &str, g: &[String]| {
            // Image / games disk for every machine: stays so (not made this group's only). A golden with no group has
            // no machine: it simply gets this one.
            if g.is_empty() && !key.starts_with('r') && !key.starts_with('g') {
                return Vec::new();
            }
            let has = g.iter().any(|x| same(x, &n2));
            let want = match key.split_at(1) {
                ("g", n) => b.goldens.as_ref().map_or(has, |l| l.iter().any(|x| x == n)),
                _ => want(key),
            };
            match (want, has) {
                (true, false) => g.iter().cloned().chain([n2.clone()]).collect(),
                (false, true) => swap(g, &n2, None),
                _ => g.to_vec(),
            }
        };
        let machine = |m: &crate::db::Machine| {
            if b.machines.contains(&m.id) {
                Some(n2.clone())
            } else {
                m.grp.clone().filter(|g| !same(g, &n2))
            }
        };
        apply(&st2, &f, &machine, b.allow_all)?;
        if let Some(on) = b.hide_disks {
            edit_names(&st2, "hide_disks_groups", |v| {
                *v = swap(v, &n2, None);
                if on {
                    v.push(n2.clone());
                }
            })?;
        }
        edit_names(&st2, "groups", |v| {
            if !v.iter().any(|g| same(g, &n2)) {
                v.push(n2.clone());
            }
        })?;
        crate::pins::prune(&st2)?; // versions held for goldens / disks the group no longer gets
        for (k, ver) in b.versions.iter().flatten() {
            let (golden, disk) = match k.split_at(k.len().min(1)) {
                ("g", n) => (true, n),
                ("d", n) => (false, n),
                _ => continue,
            };
            let gets = if golden {
                crate::diskless::goldens(&st2)
                    .iter()
                    .any(|g| g.name == disk && g.groups.iter().any(|x| same(x, &n2)))
            } else {
                crate::games::disks(&st2).iter().any(|d| {
                    d.name == disk && (d.groups.is_empty() || d.groups.iter().any(|x| same(x, &n2)))
                })
            };
            if gets {
                let m = crate::pins::set(&st2, golden, disk, &n2, *ver)?;
                tracing::info!("versions: {m}");
            }
        }
        Ok(())
    })
    .await
    .map_err(ise)??;
    sync_games(&st).await;
    tracing::info!("group {name}: machines, images, iSCSI disks and drivers set");
    Ok(ok())
}

async fn sync_games(st: &SharedState) {
    let st = st.clone();
    if let Ok(Err(e)) = tokio::task::spawn_blocking(move || {
        let _ = crate::diskless::sync(&st); // logs its own errors
        crate::games::sync(&st)
    })
    .await
    {
        tracing::warn!("iSCSI disks: {e}");
    }
}

#[cfg(test)]
#[path = "../tests/unit/groups.rs"]
mod tests;
