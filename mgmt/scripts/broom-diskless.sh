#!/bin/sh
# broom-diskless.sh - diskless goldens (Linux: Debian / Ubuntu): what the golden needs, and each machine's own
# first-boot setup. Broom's Ubuntu installs run it by themselves; for another install, run it ON THE GOLDEN from its
# maintenance machine before Save:
#   curl -fsS http://<server>/broom-diskless.sh | sudo sh
# Install (no argument): makes the initramfs log in to the iSCSI disk the network boot describes (iBFT), turns swap
# off (a swap file would live on the network disk), and installs itself as /usr/local/sbin/broom-diskless with
# broom-diskless.service, which runs it at every start ("run"): it asks the server what this machine is
# (GET /api/diskless/client?fmt=env, answered by its IP + MAC):
#  - a diskless machine on its first boot of this golden version: takes its own name from the server (Devices page),
#    its own machine-id and SSH host keys, tells the server (POST /api/diskless/client/base-done) and restarts at once
#    - that boot is kept as the machine's base layer; every later boot starts from it, the rest is wiped at each boot.
#  - anything else (later boots, the maintenance machine, the server unreachable): does nothing.
# ASCII only. Logs to the journal (journalctl -t broom-diskless).
set -u
SRV='__SERVER__'
DST=/usr/local/sbin/broom-diskless
UNIT=/etc/systemd/system/broom-diskless.service
# To the journal; on screen too when run by hand (under systemd the screen is the journal already).
log() {
  logger -t broom-diskless "$*" 2>/dev/null || true
  if [ -t 1 ]; then echo "broom-diskless: $*"; fi
}

install_self() {
  [ "$(id -u)" = 0 ] || { echo "Run as root (sudo)."; exit 1; }
  if [ ! -d /etc/iscsi ] || ! command -v update-initramfs >/dev/null 2>&1; then
    log "needs open-iscsi and initramfs-tools (Debian / Ubuntu): apt install open-iscsi, then run this again"
    exit 1
  fi
  curl -fsS "http://$SRV/broom-diskless.sh" -o "$DST.new" || { log "download from $SRV failed"; exit 1; }
  chmod 755 "$DST.new" && mv "$DST.new" "$DST"
  cat > "$UNIT" <<EOF
[Unit]
Description=Broom diskless: this machine's first-boot setup
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=$DST run
TimeoutStartSec=5min

[Install]
WantedBy=multi-user.target
EOF
  mkdir -p /etc/systemd/system/multi-user.target.wants
  ln -sf "$UNIT" /etc/systemd/system/multi-user.target.wants/broom-diskless.service
  # The disk is on the network: the initramfs logs in to whatever disk iPXE described for this boot (the golden for
  # its maintenance machine, each machine's own disk otherwise).
  echo ISCSI_AUTO=true > /etc/iscsi/iscsi.initramfs
  # No swap on the network disk.
  sed -i '/^[^#].*[[:space:]]swap[[:space:]]/ s/^/#/' /etc/fstab
  swapoff -a 2>/dev/null || true
  update-initramfs -u -k all >/dev/null 2>&1 || { log "update-initramfs failed"; exit 1; }
  log "installed (server $SRV): shut down, then Save the golden on the Diskless page"
}

run_boot() {
  R=""
  i=0
  while [ $i -lt 30 ]; do
    R=$(curl -fsS -m 5 "http://$SRV/api/diskless/client?fmt=env" 2>/dev/null) && break
    R=""
    i=$((i + 1))
    sleep 2
  done
  [ -n "$R" ] || { log "server $SRV not reachable - nothing to do"; exit 0; }
  get() { printf '%s\n' "$R" | sed -n "s/^$1=//p" | head -n 1; }
  ROLE=$(get ROLE); FIRST=$(get FIRST); HOST=$(get HOST)
  log "role $ROLE, golden $(get GOLDEN) g$(get VER), first boot: $FIRST, name: $HOST"
  [ "$ROLE" = diskless ] && [ "$FIRST" = 1 ] || exit 0
  # First boot of this machine on this golden version: its own setup, then the restart that keeps it as its base.
  if [ -n "$HOST" ] && [ "$HOST" != "$(hostname)" ]; then
    log "machine name $(hostname) -> $HOST"
    hostnamectl set-hostname "$HOST" 2>/dev/null || echo "$HOST" > /etc/hostname
    sed -i "s/^127\.0\.1\.1[[:space:]].*/127.0.1.1\t$HOST/" /etc/hosts
  fi
  rm -f /etc/machine-id /var/lib/dbus/machine-id
  systemd-machine-id-setup >/dev/null 2>&1 || log "machine-id not renewed"
  if ls /etc/ssh/ssh_host_*_key >/dev/null 2>&1; then
    rm -f /etc/ssh/ssh_host_*
    ssh-keygen -A >/dev/null 2>&1 || log "SSH host keys not renewed"
  fi
  sync
  if ! curl -fsS -m 10 -X POST "http://$SRV/api/diskless/client/base-done" >/dev/null; then
    log "base-done FAILED (set up again at the next boot)"
    exit 0
  fi
  log "base done - restarting to keep it"
  systemctl reboot
}

case "${1:-install}" in
  run) run_boot ;;
  install) install_self ;;
  *) echo "usage: broom-diskless.sh [install|run]"; exit 2 ;;
esac
