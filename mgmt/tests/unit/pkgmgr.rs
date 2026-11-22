use super::*;

fn have<'a>(found: &'a [&'a str]) -> impl Fn(&str) -> bool + 'a {
    move |p| found.contains(&p)
}

/// apt first, then dnf, then yum; none = None. A system with several (a dnf with a yum compatibility link) is driven
/// by the first.
#[test]
fn manager_is_detected() {
    assert_eq!(detect(have(&["apt-get", "dnf"])), Some(Mgr::Apt));
    assert_eq!(detect(have(&["dnf", "yum"])), Some(Mgr::Dnf));
    assert_eq!(detect(have(&["yum"])), Some(Mgr::Yum));
    assert_eq!(detect(have(&["pacman"])), None);
    assert_eq!(other_manager(have(&["pacman"])), Some("pacman"));
    assert_eq!(other_manager(have(&["apk", "zypper"])), Some("zypper"));
    assert_eq!(other_manager(have(&[])), None);
}

#[test]
fn os_release_name() {
    let t =
        "NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nID=ubuntu\n";
    assert_eq!(os_name(t), "Ubuntu 24.04.1 LTS");
    assert_eq!(
        os_name("PRETTY_NAME='Rocky Linux 10.0'\n"),
        "Rocky Linux 10.0"
    );
    assert_eq!(os_name("ID=x\n"), "");
    assert_eq!(os_name(""), "");
}

/// What is missing follows what was found, in the order the page lists it. The VM of both features needs QEMU and OVMF
/// only: its disk comes over NBD from the daemon, and Add hardware's job over HTTP.
#[test]
fn missing_follows_what_is_found() {
    let found = |list: &'static [Pkg]| move |p: Pkg| list.contains(&p);
    assert!(missing_with(found(&[Pkg::Qemu, Pkg::Ovmf])).is_empty());
    assert_eq!(missing_with(found(&[Pkg::Ovmf])), vec![Pkg::Qemu]);
    assert_eq!(missing_with(found(&[Pkg::Qemu])), vec![Pkg::Ovmf]);
    assert_eq!(missing_with(found(&[])), vec![Pkg::Qemu, Pkg::Ovmf]);
}

/// Debian-family names; RHEL-family names (qemu-kvm, edk2-ovmf, iscsi-initiator-utils) for dnf and yum alike.
#[test]
fn package_names() {
    assert_eq!(package(Mgr::Apt, Pkg::Qemu), "qemu-system-x86");
    assert_eq!(package(Mgr::Apt, Pkg::Ovmf), "ovmf");
    for m in [Mgr::Dnf, Mgr::Yum] {
        assert_eq!(package(m, Pkg::Qemu), "qemu-kvm");
        assert_eq!(package(m, Pkg::Ovmf), "edk2-ovmf");
    }
}

/// apt refreshes its lists first; dnf / yum install at once; always non-interactive (-y); nothing missing, nothing to
/// run; and only the missing packages are named.
#[test]
fn install_commands() {
    let all = [Pkg::Qemu, Pkg::Ovmf];
    let apt = steps(Mgr::Apt, &all);
    assert_eq!(apt.len(), 2);
    assert_eq!(apt[0], ["apt-get", "update"]);
    assert_eq!(
        command_line(&apt),
        "apt-get update && apt-get install -y qemu-system-x86 ovmf"
    );
    assert_eq!(
        command_line(&steps(Mgr::Dnf, &[Pkg::Qemu, Pkg::Ovmf])),
        "dnf install -y qemu-kvm edk2-ovmf"
    );
    assert_eq!(
        command_line(&steps(Mgr::Yum, &[Pkg::Ovmf])),
        "yum install -y edk2-ovmf"
    );
    assert!(steps(Mgr::Apt, &[]).is_empty());
    assert_eq!(command_line(&[]), "");
}

/// Output of apt / dnf: progress redrawn with carriage returns keeps its last draw; control characters and long lines
/// are cut; blank lines are not kept.
#[test]
fn output_lines_are_cleaned() {
    assert_eq!(
        clean_line("Get:1 http://x\n").as_deref(),
        Some("Get:1 http://x")
    );
    assert_eq!(
        clean_line("10%\r50%\r100% done\n").as_deref(),
        Some("100% done")
    );
    assert_eq!(clean_line("a\x1b[0mb\n").as_deref(), Some("a[0mb"));
    assert_eq!(clean_line("   \n"), None);
    assert_eq!(clean_line("\r\n"), None);
    assert_eq!(clean_line(&"x".repeat(1000)).unwrap().chars().count(), 300);
}

/// The log keeps the newest lines only.
#[test]
fn log_keeps_the_newest() {
    *JOB.lock() = Some(Job {
        state: "running",
        ..Job::default()
    });
    for i in 0..(LOG_LINES + 25) {
        push_log(format!("line {i}"));
    }
    let j = JOB.lock().clone().unwrap();
    assert_eq!(j.log.len(), LOG_LINES);
    assert_eq!(j.log[0], "line 25");
    assert_eq!(j.log.last().unwrap(), &format!("line {}", LOG_LINES + 24));
    finish("failed", "x".into());
    let j = JOB.lock().clone().unwrap();
    assert_eq!((j.state, j.msg.as_str()), ("failed", "x"));
    *JOB.lock() = None;
}

/// Installing runs a command as root: an owner's action, never a role's (the table's default for a POST); looking at
/// what is missing is open to every signed-in account.
#[test]
fn install_is_owner_only() {
    use crate::auth::{Need, needs};
    use axum::http::Method;
    assert!(matches!(
        needs(&Method::POST, "/api/packages/install"),
        Need::Owner
    ));
    assert!(matches!(needs(&Method::GET, "/api/packages"), Need::Any));
}
