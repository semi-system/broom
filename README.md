<p align="center"><img src="docs/images/broom.svg" alt="Broom logo" width="128"></p>

# Broom — open-source diskless boot server for Windows 11 & Linux

[![Release](https://img.shields.io/github/v/release/morningstar-sudo/broom)](https://github.com/morningstar-sudo/broom/releases/latest)
[![License](https://img.shields.io/github/license/morningstar-sudo/broom)](LICENSE)

Network-boot a room of PCs from **one golden image**: every reboot comes up clean. One static Rust binary on any
Linux server, with DHCP, TFTP, iSCSI and the web admin built in. Made for internet cafés, gaming centers and school
labs, up to ~100 PCs per server (see [Sizing](#sizing)).

- **Secure Boot on, no MOK**: every step of the network boot is signed through Microsoft's UEFI CA. With TPM 2.0 +
  HVCI, **FACEIT Anti-Cheat works**.
- **Clean every boot**: Windows (tested on 11 Pro and Enterprise) or Linux clients; writes go to the local SSD and
  are reset at the next boot.
- **UEFI or legacy BIOS (CSM)**: one golden boots both kinds of PC, no second image.
- **One file to deploy**: no dnsmasq, tftpd or targetcli. Build the golden in a VM (or capture a real PC) and
  upload it from the browser.
- **Shared iSCSI disks** for games and apps: update once, every PC gets it at its next boot.
- **Remote in the browser**: a live wall of every PC's screen, click one to take over. Full-screen games included,
  no port open on the PCs.
- **Health and logs**: CPU, RAM, temperatures, SMART / bad sectors for every PC and the server; logs with filter and
  live follow.
- **Versions of every golden**: snapshot and roll back; on XFS / btrfs versions share their common data, so each one
  costs only what changed. Whatever is served stays in one piece on the disk.
- **Diskless machines (no SSD)** as a second mode: the whole disk comes from the server over iSCSI, each machine with
  its own layers, reset at every boot; a new PC's network card is added to the golden from the browser, and goldens
  are maintained in a VM on the server ([details](#diskless-machines-no-ssd)).
- **Power, display, hardware list** per machine or group; **HTTPS** for the web admin.
- **Machine groups, driver packages.** Free, Apache-2.0.

**User guide:** [step by step, from an empty server to a room in daily use](https://broom.hainth.edu.vn/user-guide.html) ·
**Guides:** [broom.hainth.edu.vn](https://broom.hainth.edu.vn/)

## Screenshots

| | |
|---|---|
| ![Windows 11 client network-booted by Broom, with an iSCSI disk mounted as G:](docs/images/client-games-disk.png) | ![Broom web admin Remote page: a wall of every Windows client's screen](docs/images/remote-wall.png) |
| Windows 11 client: C: is the shared golden, G: an iSCSI disk | Remote: every client's screen on one wall |
| ![Broom web admin Server page with live load and charts](docs/images/server-monitoring.png) | ![FACEIT Anti-Cheat running on a Broom diskless client, all recommended security features green](docs/images/faceit-anticheat.png) |
| Server: live load and 10-minute charts | FACEIT Anti-Cheat: Secure Boot, TPM, HVCI all pass |
| ![Broom iPXE boot menu with the Capture / deploy entry](docs/images/boot-menu.png) | ![Broom Capture on a client: owner sign-in, disk and partitions read, upload under way](docs/images/capture.png) |
| Boot menu with **[C] Capture / deploy** | Capturing a PC's disk as an image |

## How it works

1. Build a golden in a VM (Linux, or Windows 11 Pro / Enterprise), or capture a real PC.
2. Upload it in the web admin: the server extracts the disk, builds the boot files and serves it.
3. Clients PXE-boot it read-only; their writes land on the local SSD and are reset at each boot.
   - **Windows:** the golden is cached on the SSD as `golden.vhdx` (downloaded once per new golden, checked with
     sha256 while it downloads) and Windows boots natively from a child VHDX that is recreated every boot. The server
     makes `golden.vhdx` on the fly from the raw disk; with the image's cache set to RAM it serves a compressed copy
     from memory.
   - **Linux:** read-only iSCSI root + `overlayroot`, writeback on the SSD (or in RAM).

Each Windows PC specializes the golden once (name, license) and keeps that as its **base**; driver packages go into
their own layer over it. Every boot resets to `base ← drivers ← fresh child`.

| | Broom | Commercial suites (e.g. CCBoot) | LTSP | FOG Project |
|---|---|---|---|---|
| Open source | yes (Apache-2.0) | no | yes | yes |
| Server | any x86_64 Linux, one binary | Windows | Linux | Linux |
| Windows / Linux clients | yes / yes | yes / — | no / yes | yes / yes |
| Model | diskless (reset every boot) + imaging (capture / deploy a PC's disk) | diskless | thin/fat clients | imaging |

## Requirements

- **Server:** x86_64 Linux (tested on Debian/Ubuntu and Rocky Linux 10), run as root, disk space for the goldens.
- **Clients:** x86_64 PCs, UEFI or legacy BIOS (CSM), **PXE first in the boot order**. Windows images need a local
  SSD; Linux images can run without one (writes in RAM). [Diskless goldens](#diskless-machines-no-ssd) run Windows (or
  Linux) with no disk at all, entirely from the server (tested on UEFI clients only).

## Sizing

Nothing in Broom caps the number of machines; the server's link, disk and RAM do. Traffic comes from a new golden
going out after a publish and from the iSCSI disks while people play (Windows itself runs from each PC's SSD).

| Room | Server link | Image / iSCSI disk | RAM |
|---|---|---|---|
| up to 30 PCs | 1 GbE | SSD | 16 GB |
| 30–60 PCs | 10 GbE | NVMe | 32 GB |
| 60–100 PCs | 2× 10 GbE bonded (LACP) or 25 GbE | NVMe (PCIe 4) | 64 GB+, iSCSI disk cached in RAM |

- **Bonding** is set up on the server's OS: `802.3ad` with `xmit_hash_policy=layer3+4`, LACP on the switch. Then
  pick the bond (e.g. `bond0`) as the DHCP interface. One PC never gets more than one link's speed.
- **Switches:** 1 GbE to the PCs, a 10 GbE uplink per access switch, **PortFast / edge port** on the PC ports
  (classic spanning tree holds a port ~30 s at each link-up, twice per boot).
- **New golden:** machines download it a few at a time at full speed (Windows → *Golden downloads at once*; Auto =
  server link / 1 Gbit/s). A 30 GB golden reaches 100 PCs in about half an hour on 20 Gbit/s: publish off-hours.
- Measure on the **Benchmark** page (server disk, each PC's boot time and read speed) and watch the **Server** page.

## Quick start

Use a **fixed directory**: the images and the database live next to the binary.

```bash
sudo mkdir -p /opt/bootrom && cd /opt/bootrom
sudo curl -fLO https://github.com/morningstar-sudo/broom/releases/latest/download/bootrom-mgmt
sudo curl -fLO https://github.com/morningstar-sudo/broom/releases/latest/download/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS   # must say: bootrom-mgmt: OK
sudo chmod +x bootrom-mgmt
sudo ./bootrom-mgmt install-service      # systemd unit; flags after it (e.g. --port 8080) go into the unit
journalctl -u bootrom-mgmt -f            # shows the one-time setup token
```

**Who built it:** the checksum only proves the download is whole. Every release file also carries a signed build
provenance (GitHub artifact attestation, Sigstore): `gh attestation verify bootrom-mgmt --repo morningstar-sudo/broom`
(GitHub CLI, on any machine) checks that it was built by this repository's CI from a commit of `main`.

The first start detects the network and downloads the release's `broom-assets.zip` (web UI, iPXE, scripts); the first
Windows publish fetches `broom-stage.tar.gz` (client stage). The binary takes them only with the sha256 built into it.
**Offline server:** copy both files of the same release next to the binary. To upgrade: stop the service, replace the
binary (checked the same way), start it.

Open `http://<server-ip>/`: it moves to `https://` with the server's self-signed certificate, so the browser warns
once (the fingerprint is on **Settings → HTTPS**; see [Web admin](#web-admin)). Enter the setup token and set the owner
password. Then the network boot:

- **Keep the router's DHCP** and set its PXE options: next-server / option 66 = the Broom server, boot file /
  option 67 = `snponly.efi` (Secure Boot clients: `sb/snponly-shim.efi`; legacy BIOS clients: `undionly.kpxe`; a
  room with both needs a router that picks the file by client architecture, option 93); or
- **Turn on Broom's DHCP server** (Network page) after switching the router's off: interface, range, gateway, DNS.
  It is off by default, since two DHCP servers break a LAN.

**Register the PCs** (Machines / Devices) before their first Windows boot: on a registered PC with one internal disk
the stage lays out the SSD by itself. Any other PC asks on screen which disk to wipe (Enter = touch nothing). On a PC
with several disks, pick the Broom disk under Devices → *Disks* and optionally hide the others from the guest.

**Secure Boot:** tick **Secure Boot clients** (Network page) and enable the "Microsoft 3rd-party UEFI CA" on the PCs.
Clients then get the iPXE project's signed build and kernels signed for Ubuntu's shim; no MOK enrollment. Golden
drivers must be HVCI-compatible (e.g. VMware: use `e1000e`, not `e1000`).

**Legacy BIOS (CSM):** nothing to switch on: BIOS PCs get their own iPXE and boot the same goldens, the Broom SSD
laid out as MBR. A Windows golden prepped by an older version boots UEFI PCs only: run the prep command again.

## Adding a golden

Upload the powered-off VM folder (only `.vmx` / `.vmdk` are sent, in parallel chunks with retry), or a single
`.vmdk` / `.img` / `.zip`.

- **Linux:** in the VM, `curl -fsSL http://<server>/broom-prep | sudo bash`, power off, upload (OS = Linux).
- **Windows 11 Pro / Enterprise:** set the guest user (Windows page), then in the VM, in Audit Mode (Ctrl+Shift+F3
  at OOBE), PowerShell as Administrator:
  ```powershell
  irm http://<server>/broom-prep-win | iex
  ```
  It syspreps and powers off; upload (OS = Windows). The script holds the guest password and is readable on the boot
  LAN, like the golden itself.
- Both scripts come from your own Broom server over the LAN. To read one before it runs: `curl -fsSLo prep.sh
  http://<server>/broom-prep`, then `less prep.sh` and `sudo bash prep.sh` (Windows: `irm … -OutFile prep.ps1`,
  read it, then `.\prep.ps1`).
- **Capture a real PC:** run the same prep on the PC, then PXE-boot it and pick **[C] Capture / deploy → Capture**.
  Sign in with an owner account, pick the disk, name the image. Only what NTFS uses is sent (40 GB of Windows on a
  1 TB disk sends ~40 GB). BitLocker must be off; keep C: small, since every client gets a C: that size.
- **Deploy** (same menu): write an image's full disk onto a PC's disk (erased) so it boots that Windows natively.
  Change apps there, prep again, capture it back.

## Windows clients

- **Base:** built once per PC on its first boot, and again after a new golden, a rename or a license key. The PC
  restarts once by itself; every later boot resets to it.
- **Base mode** (Machines page, per PC + one image): that PC keeps everything over as many restarts as needed
  (Windows Update, an anti-cheat's first run). Turned off, its next boot saves it as the base. The Machines page marks
  it **BASE**; don't leave it on for guests.
- **Drivers** (Drivers page): packages matched by hardware ID, group or "all machines". A changed set is installed
  once into a driver layer over the base (one extra restart); later boots start with it. Two packages for the same
  device: Windows picks (best match, then newest `DriverVer`).
- **iSCSI disks** (iSCSI Disks page): game libraries on the server, mounted read-only under a drive letter, writes
  kept on the PC's SSD until reboot. Pick an **update machine**, boot it, install, shut down, **Save**: a new
  version, picked up by each PC at its next boot. **Cache** serves a disk from the server's RAM.
- **SSD room** (Windows page): the stage frees *Keep free* GB each boot; a watchdog warns the guest below *Warn* and
  restarts below *Restart* (a full SSD would blue-screen Windows). *Pagefile*: N GB on the SSD, new every boot.
- **Strict reset** (Network page): Windows can only start through PXE. Without it a PC whose PXE fails boots its SSD
  without the reset; the Machines page flags it "not reset".
- **DNS only for healthy PCs** (Network → DNS): the server is the clients' DNS and answers only PCs whose Remote
  agent runs, PCs that just booted, and exempt groups / IPs. Block outside DNS (53, 853) on the router.
- **Remote:** a small agent (`broom-vnc`) dials out to the server; the wall streams only the page shown, the single
  view uses H.264 on Chrome / Edge. Ctrl+Alt+Del, Windows key, Alt+Tab and Paste from the toolbar.
- **Hardware list** (Machines page → Hardware; **Hardware CSV** for all): Windows, computer, board + BIOS, CPU, RAM
  sticks, graphics cards + driver version, drives, network cards + link speed, monitors and each output's current mode
  and the modes it offers — sent by the agent once connected, 2 minutes later (games disks mounted) and every 30
  minutes, kept per machine.
- **Display** (Machines page, owner): resolution + refresh per machine (picked from the modes its monitor offers, in
  its Hardware panel) or for the selected machines / a group (typed, e.g. `1920x1080@165`; a machine's own setting wins
  over its group's). The agent applies it to the main output at every start — only a mode the monitor offers, tested
  first — and at once when changed.
- **Power** (Machines page; staff too): tick machines (or all a filter shows, e.g. one group), then **Turn on**
  (Wake-on-LAN: on in the PC's firmware), **Restart** or **Shut down** (now, or after 30 s / 1 / 5 min with an optional
  message on screen; through the PC's agent, which runs Windows' `shutdown`) or **Cancel** a countdown. A machine
  without a connected agent is listed as not done. `POST /api/power {action, ids | group, delay, msg}` for scripts.

The Windows scripts and helpers are the server's, not the image's: a new server version reaches every PC at its next
boot without a republish.

## Diskless machines (no SSD)

A **golden** (Diskless page) is a whole disk that machines with no local disk boot straight from the server over
iSCSI (iPXE `sanboot`, the iBFT tells the OS where its disk is). Every read and write goes to the server: size it for
that (fast disks for the machines' layers, the server's link) and keep in mind that the server down = every diskless
PC down.

- **Create:** name, OS (Windows by default, or Linux), size, the **installer ISO** from the ISO library, and the
  groups whose machines boot it. It starts as a blank disk.
- **Install / maintain:** pick its **maintenance machine**. Its boot menu then has *Install … from …* (the golden
  attached as a blank disk, the ISO booted as a DVD drive) and *Maintain …* (the golden itself, writable). Install
  the OS, then drivers, software and settings; shut down; **Save** makes that work the golden's next version, which
  every machine gets at its next boot (**Discard** throws it away). Windows ISOs ask to press a key to boot from the
  DVD: press one on the maintenance machine.
- **Machines:** registered machines of the golden's groups with a **fixed IP**. Each gets its own disk (target
  `<golden>.m<mac>`, answered only from its IP with its MAC behind it): the golden, then the machine's own **base**
  layer, then a **session** layer that is wiped at every PXE boot.
- **Storage** (Diskless page): goldens, the machines' layers and the ISO library each go on broom's own folder or a
  server disk. Layers are sparse files of 64 KB blocks: a machine costs what it writes.
- **ISO library:** upload installer ISOs (Windows or Linux); they are served read-only as a DVD-ROM.
- **Linux goldens:** an Ubuntu installer ISO (casper) is not booted as a DVD (its live system cannot find it there):
  Broom boots the ISO's own kernel and initrd, the live system loads the whole ISO over HTTP (the machine needs about
  4 GB of RAM more than the ISO) and an autoinstall seed that only adds steps around the usual screens: log in to the
  golden before the disks are probed, and set the installed system up for it (`broom-diskless.sh`: the initramfs logs
  in to the disk the network boot describes, no swap on the network disk, each machine's own name / machine-id / SSH
  host keys on its first boot). Another Debian / Ubuntu install: run `curl -fsS http://<server>/broom-diskless.sh |
  sudo sh` on it once before Save. Linux goldens boot their distribution's shim (`\EFI\<distro>\shimx64.efi`), not
  `\EFI\BOOT\BOOTX64.EFI`: that one is shim's fallback, which adds a firmware boot entry and restarts every time.
- **Windows goldens:** run `irm http://<server>/broom-diskless.ps1 | iex` on the golden (as Administrator) before
  the first Save: each machine then takes its own name (Devices page) on its first boot, kept as its base. At every
  start the golden's copy runs the server's current version of the script, so a newer Broom reaches every machine
  without a new golden version. A golden set up before that: **Update script** (Diskless page) writes the current
  script into it as its next version, without booting it.
- **Games disks on diskless machines:** a diskless Windows machine has no SSD for its writes, so each one gets its own
  copy of every games disk of its group on the server (target `<disk iqn>.m<mac>`: the disk's newest version + the
  machine's own layer in `<writeback>/.games-<disk>/<mac>/`, dropped at its next PXE boot — like the per-PC writeback
  of commercial diskless systems). `broom-games.ps1` (run by `broom-watch.ps1 -Dir` at start and every 5
  minutes) logs in to it and attaches its `games.vhdx` writable as the disk's letter. The disk's update machine (a
  diskless one too) gets the disk itself, writable, as on SSD machines; Save makes the next version, which every
  machine's copy reads from its next boot.
- **Maintain in the browser (Windows):** the Diskless page runs a golden in a VM on the server (QEMU/KVM, 4 CPU
  threads, 8 GB, internet through QEMU's NAT) and shows its screen in the browser (**Open the screen**: noVNC,
  through Broom's signed-in WebSocket; QEMU's VNC is only a Unix socket). Tick games disks to attach them **writable**
  under their letters, as for an update machine: install or update games, shut the VM down, then **Save** each disk —
  every machine gets it at its next boot. An owner can tick *Keep Windows changes* (Windows / app updates): Save or
  Discard the golden afterwards; without it the VM's Windows changes are thrown away when it stops, so staff (who may
  start it) update games but never change the golden. The VM writes through the server's own iSCSI sessions (the
  daemon lets 127.0.0.1 write while the VM holds the disks) and runs in its own systemd unit `broom-vm-<golden>`, so
  restarting Broom does not stop it. One VM at a time; the golden needs no maintenance machine. Needs
  `qemu-system-x86`, `ovmf`, `open-iscsi` and KVM, as Add hardware. In the VM, Steam and other sign-ins are lost with
  the Windows changes unless they are kept.
- **Remote on diskless machines:** the first boot of each golden version also gets the machine its Remote agent key
  (handed out only on that boot) and the agent's files (`C:\ProgramData\Broom`, SYSTEM and Administrators only), kept
  in its base; every later boot starts the agent (`broom-watch.ps1 -Dir`, its own task), so remote screen, Wake and
  health work as on SSD machines. A new key (Re-issue on Devices) builds the base again. The maintenance machine gets
  no key: what it writes goes into the golden.
- **Add hardware (Windows):** Windows booting from iSCSI only brings up a network card whose *device* it already
  knows (its exact Plug and Play instance ID: bus + slot); a driver alone is not enough. For a PC with a card the
  golden has never seen (a new board, or a card in another slot), pick the golden and that PC under *Add hardware*
  and press Start. Its next network boot starts Windows PE (wimboot + the Windows PE of the golden's installer ISO;
  Microsoft-signed, so it also works with *Secure Boot clients*), which reports its cards to Broom. Broom attaches the
  golden's newest version to itself (iSCSI over 127.0.0.1), boots it in a small VM (QEMU/KVM, no network) where
  `broom-onboard.ps1`, run by the golden's own startup task, creates each card's device with that instance ID and lets
  Windows install the best driver from its driver store, marked as a network-boot driver; then Broom saves the golden's
  next version and the PC restarts into it. Identical PCs need it once; a PC whose cards are all known finishes at
  once. Needs on the server: `qemu-system-x86_64`, OVMF, `iscsiadm` (open-iscsi), `ntfs-3g` and `/dev/kvm` (nested
  KVM, CPU type host, when Broom itself runs in a VM). The card needs a driver in Windows PE (to report) and in the
  golden (to install). **Network-card drivers from the library** (Drivers page; packages whose .inf is Class=Net are
  marked *network card*): every one of them goes to Windows PE along with the reporter, which loads them (`drvload`)
  before it looks for the network, and the package matching the card is copied into the golden and added to its driver
  store before the card is installed. iPXE tells Broom the card it booted with (vendor + device) before Windows PE
  starts, so a card Windows PE still cannot use is named on the Diskless page (and on the PC's screen) with what to do.
  A card without a driver in Windows PE but a second card that has one is reported too (from the problem devices). The Windows PE files come out of the ISO's ISO 9660 part; Microsoft's own ISOs keep them in UDF
  only: copy `boot.wim`, `boot.sdi`, `bootmgr.efi` and the UEFI `BCD` into `<ISO place>/.winpe/<iso>/` then.
- **Versions** (the *kept* versions under each golden on the Diskless page and each disk on the iSCSI Disks page; a
  version per group on the Groups page): every saved version of a golden or games disk is kept until the drive holding
  it has less than the % free set under *Where things are kept* (default 10); then the oldest one that no machine uses and no
  group is held on goes, one at a time. A group boots the **newest** version or one it is **held** on: put a test PC's
  group on the newest, keep the room on the last good one, then move the room once the test PC is fine. Machines pick
  a change up at their next boot. The owner can also drop the oldest version by hand.
- **Behind a router's DHCP** (Broom's DHCP server off): the router's boot file `sb/snponly-shim.efi` (the
  Microsoft-signed iPXE shim) works for every PC, Secure Boot on or off; each diskless PC needs a **fixed lease** on the
  router equal to its fixed IP in Broom (its disk answers only that IP). Windows booted from iSCSI turns the gateway it
  is booted with into a route to its disk *through* that gateway, even on the same subnet, so every disk read would
  go through the router (and a router that tracks connections drops Windows' new connections to Broom). When Broom is
  on the PC's subnet, the Windows boot leaves the gateway out and the startup script adds the router as the default
  route once the disk is up. After moving Broom to another address, **Update script** (Diskless page) writes the new
  address into the golden.

**Tested so far**, on virtual-machine clients: Windows 11 24H2 and Ubuntu 26.04 goldens end to end — installed from the
library (the golden attached, the installer from the server), maintained, saved, then booted diskless: each machine's
own name kept as its base, everything else gone at the next boot. Add hardware: an e1000e in a PCI slot the golden had
never seen and an RTL8139 (another driver) under Secure Boot hung at the Windows spinner before, booted after (Windows
PE report → VM → new version in about 2 minutes), and a vmxnet3 card Windows PE has no driver for booted after its
driver came from the driver library. On a LAN behind a router's DHCP: three clients (e1000e, vmxnet3, RTL8139 with
Secure Boot) booted Windows with the Secure Boot shim, Remote agent, games disk and internet; a golden updated in the
browser VM booted on them; a group held on an older version booted it while a newer one existed. Not tested yet: real
PCs (their network card in Windows PE and in the iSCSI boot), production load, and anti-cheat behind this chain.

## Groups, images, versions

- A machine's **group** decides its boot menu, the images kept on its SSD, its iSCSI disks and drivers (Groups page).
  Things set for no group go to everyone. This organizes, it is not access control.
- **New machines** (Groups page, off by default): an unknown PC that network-boots joins a group you pick by itself
  (named `NEW-<end of its MAC>`, its IP as fixed IP) and waits there until you move it to its group. Meanwhile it
  boots what that group gets, and its disks are never partitioned without asking. Only PCs on the server's own LAN
  (MAC seen behind the IP), at most 250 waiting.
- **Preload** (Windows images): PCs fetch the image ahead of use while booting another one.
- **Versions:** **+ Snapshot now** saves the golden as a version (a hard link: instant, no space). The first upload
  of an image is saved as v1. **→ New image** turns a version into an image; **Delete** frees what no other version
  uses.
- **Shared data:** a new golden is a new file. On a filesystem that can share blocks (**XFS with reflink**, btrfs:
  Broom tries it, it does not go by the name), the version before it then gives back every block they have in common
  (FIDEDUPERANGE: the kernel compares the bytes; blake3 per 64 KB finds the candidates, kept in `<file>.bhash`). Only
  the stored version changes, never the golden being served. On ext4 every version keeps its full size. **Dedup**
  (Versions) does the same for versions saved earlier, after a move or after restoring a backup.
- **Rollback / → New image** serve a version again. Whatever is served is in **one piece** on the disk (PCs read the
  golden start to end): a version that shares its data is scattered, so the publish first rebuilds it in one piece (a
  copy, minutes for 20–50 GB; free space ≈ the golden + 1 GB), with the same bytes and stamp, so no hash is computed
  again. The other versions then share their data with it.
- **Export:** a VMware VM (`.vmx` + `.vmdk`) of an image or version, to edit it again.

## Web admin

| Group | Pages |
|---|---|
| Monitor | **Machines** (state, health, license, Wake / Manage / Remote, base mode), **Remote**, **Server** (load, charts, disks, services) |
| Manage | **Devices** (register, import, per-PC detail and disks), **Groups** |
| Content | **Images**, **iSCSI Disks**, **Drivers** |
| Config | **Network** (DHCP, Secure Boot, strict reset, DNS), **Windows** (guest user, SSD room, downloads), **Settings** (users, boot menu) |
| Tools | **Benchmark**, **Logs** |

Accounts: **owner** (everything) or **staff** (look, Remote, Wake, save a games update; no deleting or settings).

**HTTPS.** The web admin is served on `https://` (port 443, `--https-port` to change it, `--https-port 0` = off);
plain `http://` sends a browser there and refuses the admin API. The machines keep plain HTTP: iPXE, the boot files,
Windows PE, the Remote agents and the scripts on the PCs. At first start Broom makes a **self-signed certificate** for
its host name and addresses (valid 820 days, under Apple's 825-day limit; a new one is made by itself a month before
the end). A browser warns the first time: compare the SHA-256 fingerprint it shows with **Settings → HTTPS**, or
install the certificate on the staff PCs (Download there). **Your own certificate** (PEM certificate with its chain +
its private key) replaces it on the same card, at once (no restart); so does a new self-signed one (after an address
change). Files: `<home>/tls/cert.pem`, `key.pem` (root only). The Capture tool (boot menu [C]) trusts exactly the
server's self-signed certificate; with your own certificate it talks plain HTTP, as the boot does. A switch on the
card serves the admin on plain `http://` too.

## Data, backup

```
/opt/bootrom/
├── bootrom-mgmt     # the binary
├── bootrom.db       # config, accounts, machines, license keys, images (SQLite)
├── images/<name>/   # image.img = the golden (raw, sparse)
├── storage/         # image versions (hard links; on XFS / btrfs they share their common data)
├── games/<name>/    # iSCSI disks
├── disks/<id>/      # other server disks Broom formatted / mounted (Server → Disks)
├── tftp/            # boot files, rebuilt by Publish
└── work/            # scratch
```

Overrides: `BOOTROM_HOME`, `BOOTROM_IMAGES_DIR`, `BOOTROM_STORAGE_DIR`, `BOOTROM_DB=sqlite:///path/bootrom.db`.

**Backup:** `bootrom.db` (`sqlite3 bootrom.db ".backup /backup/bootrom.db"`, keep it private: license keys and the
guest password), `images/` + `storage/` together while no publish runs (`rsync -aSH`), `games/`, and `disks/<id>/`
(or follow the symlinks with `rsync -L`). `*.bhash` files are a cache and can be left out. Restore: stop, put the
files back, start. A copy does not keep the data versions share: press **Dedup** on each image's versions after a
restore.

**Server disks for images:** Server → Disks formats a free disk XFS with reflink (ext4 without `mkfs.xfs`), or adds
a folder you mounted. Versions share their data on XFS with reflink or btrfs, not on ext4 (e.g. a server's own ext4
disk): keep the images on a disk formatted here.

**Forgot the owner password:** stop the service, `sqlite3 bootrom.db "DELETE FROM config WHERE key='users'"` (removes
every account), start it: a new setup token is printed.

## Security

Every admin page and `/api/*` route needs a login (session in the database, `Host` check, throttled after 5
failures). Boot endpoints stay open, since a PXE client can't log in.

**Passwords never cross the network.** Signing in (web page and Capture) is a handshake like WPA2's: hello → the
account's salt and a server nonce → a proof made from the password (PBKDF2-SHA256, 600 000 rounds, in the browser) →
the server's own proof back. The server keeps only a verifier per account, so a copied database logs nobody in, and a
sniffed sign-in gives neither the password nor a reusable proof. A new password (first owner, change, reset by an
owner) travels as its verifier sealed with the session's key (the first one with the setup token, never typed
anywhere but the page). The web admin is on HTTPS (see Web admin): the session cookie is `Secure`, so a browser never
sends it over plain HTTP. What the network must do:

- **Segment the boot LAN.** The goldens (HTTP) and iSCSI (`:3260`) are readable by any host on it. Keep guest Wi-Fi
  and unknown laptops off it, and keep real secrets out of goldens.
- **Check the certificate** the first time a browser shows the admin page (fingerprint on Settings → HTTPS), or
  install it on the staff PCs: a browser told to accept any certificate can be shown a fake one by a host that
  redirects its traffic (ARP spoofing from a guest PC). Port isolation stops that kind of redirection too.
- License keys go to a PC once, over plain HTTP, while its base is built.
- iSCSI writes are accepted only from a disk's update machine (IP + MAC).
- Remote agents dial out; each PC has its own key, both sides prove it at every connection and every command is signed.
- The guest is a local administrator (games need it): disk hiding, strict reset and DNS gating keep the room clean,
  they are not locks.

## Build

- **Windows:** `build.cmd` (runs in WSL `Ubuntu-24.04`). **Linux / WSL:** `./build.sh`. Output `mgmt/dist/bootrom-mgmt`.
- Needs Rust stable via [rustup](https://rustup.rs) (toolchain pinned in `mgmt/rust-toolchain.toml`), `musl-tools`,
  `git`, `gcc`, `make`, `perl`, `liblzma-dev`. The binary is static (musl): it runs on any x86_64 Linux.
- Tests (`cargo test`, run by `build.sh`) also use `cpio`, `busybox-initramfs` and `qemu-utils`. `./build.sh --live`
  adds the root-only tests (asks for sudo): NTFS (`ntfs-3g`), LVM (`lvm2`), and the version store on real XFS / ext4
  filesystems on loop devices (`xfsprogs`, `e2fsprogs`).
- **iPXE** is fetched at `mgmt/ipxe/IPXE_COMMIT`, patched with `mgmt/ipxe/patches/` and embedded; rebuilt only when
  those change (`--ipxe` forces it).
- A local build has no Windows stage bundle. Make one on an Ubuntu machine with a `-generic` kernel and copy it next to
  the binary:
  ```bash
  sudo mgmt/dist/bootrom-mgmt build-stage /tmp/stage --kernel "$(ls /lib/modules | grep -- -generic$ | sort -V | tail -1)"
  ```
- CI (`.github/workflows/build.yml`) tests, builds the static binary, the Windows helpers and the stage bundle, and
  releases every push to `main`.

```
mgmt/
├── src/        # server: boot menu, images, publish, capture, dhcp / tftp / iscsi, winstage + vhdx, Remote, auth
│   ├── iscsid/ # the iSCSI target daemon
│   └── db/     # `Db` trait + SQLite
├── scripts/    # client side: stage.sh, broom-*.ps1, broom-fw.cs, broom-vnc.cs
├── static/     # web admin
└── ipxe/       # iPXE commit + patches; signed/ = official Secure Boot builds
```

## FAQ

**Do the clients need a disk?** Windows images: yes, a local SSD (cache + session writes keep boots fast and the
server idle). Linux: no. [Diskless goldens](#diskless-machines-no-ssd): no disk at all, the server carries the load.

**How many machines?** About 100 per server with the hardware in [Sizing](#sizing). The rooms running it today are
small: grow gradually and watch the Server page.

**Anti-cheat (FACEIT)?** Works with Secure Boot, TPM 2.0 and HVCI on. If it needs a first run on each PC, use
**Base mode** for that PC.

**Free?** Yes, Apache-2.0, including commercial use.

## License

Apache License 2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE). The binary embeds **iPXE** (GPLv2 with the UBDL
exception): its source is upstream iPXE at `mgmt/ipxe/IPXE_COMMIT` plus `mgmt/ipxe/patches/`; `mgmt/ipxe/signed/`
holds unmodified official builds. `broom-stage.tar.gz` is made of unmodified Ubuntu binaries under their own licenses
(`SOURCES.txt` inside lists each package).
