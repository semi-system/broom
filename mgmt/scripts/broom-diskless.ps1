# broom-diskless.ps1 - diskless goldens (Windows): each machine's own first-boot setup + the Remote agent.
# Install it ON THE GOLDEN, from its maintenance machine (PowerShell as Administrator), before Save:
#   irm http://<server>/broom-diskless.ps1 | iex
# It copies itself to C:\Windows\Setup\Scripts\broom-diskless.ps1 and registers a SYSTEM startup task. At every start
# it runs the server's current version of this script (fetched again; the copy on the golden is only the way in, so
# a newer Broom reaches every machine without a new golden version), which asks the server what this machine is
# (GET /api/diskless/client, answered by its IP + MAC):
#  - a diskless machine on its first boot of this golden version: takes its own name from the server (Devices page),
#    gets its Remote agent key (agentauth.rs) and the agent's files into C:\ProgramData\Broom, tells the server the
#    setup is done (POST /api/diskless/client/base-done) and restarts at once - that boot is kept as the machine's base
#    layer; every later boot starts from it, everything else is wiped at each boot.
#  - a diskless machine on a later boot: starts the Remote agent and mounts its games disks (broom-watch.ps1 -Dir, its
#    own task; broom-games.ps1 at start and every 5 minutes).
#  - the maintenance machine: nothing - what it writes goes into the golden every machine shares (no key, no agent).
#    The maintenance VM on the server (Diskless page, Maintain in the browser: vmmaint.rs) also gets its games disks,
#    writable, under their letters (broom-games.ps1 -LinesFile).
#  - anything else (the server unreachable): nothing.
# ASCII only. Logs to C:\Windows\Temp\broom-diskless.log (in the session layer: gone at the next boot).
$ErrorActionPreference = 'Stop'
$srv = '__SERVER__'
$dst = "$env:SystemRoot\Setup\Scripts\broom-diskless.ps1"
$run = "$env:SystemRoot\Temp\broom-diskless.run.ps1"
$log = "$env:SystemRoot\Temp\broom-diskless.log"
$dir = "$env:ProgramData\Broom"
function step($m) {
  $l = '{0:yyyy-MM-dd HH:mm:ss} {1}' -f (Get-Date), $m
  Write-Host "[broom] $m" -ForegroundColor Cyan
  try { [IO.File]::AppendAllText($log, $l + "`r`n") } catch { }
}
$me = $MyInvocation.MyCommand.Path

# 1. Installing (run by hand on the golden): copy + startup task, then stop.
if ($me -ne $dst -and $me -ne $run) {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'Run PowerShell as Administrator.' -ForegroundColor Red; return
  }
  New-Item -ItemType Directory -Force -Path (Split-Path $dst) | Out-Null
  $self = (Invoke-WebRequest -UseBasicParsing "http://$srv/broom-diskless.ps1").Content
  [IO.File]::WriteAllText($dst, $self, [Text.Encoding]::ASCII)
  $a = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File $dst"
  $t = New-ScheduledTaskTrigger -AtStartup
  $s = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 10) -StartWhenAvailable
  Register-ScheduledTask -TaskName BroomDiskless -Action $a -Trigger $t -Settings $s -User SYSTEM -RunLevel Highest -Force | Out-Null
  # A diskless machine's disk is on the network: no hibernation / fast startup (resume from a stale session layer).
  powercfg /hibernate off | Out-Null
  # No machine's agent files or key in the golden (an older version of this script on a maintenance boot, a copy).
  if (Test-Path $dir) { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue }
  Write-Host "Installed: task BroomDiskless runs $dst at every start (server $srv)." -ForegroundColor Green
  Write-Host 'Shut down this machine, then Save the golden on the Diskless page.' -ForegroundColor Green
  return
}

# 2. At start (SYSTEM): the network may come a little after the task starts.
function Text($url) {
  $r = Invoke-WebRequest -UseBasicParsing -TimeoutSec 10 $url
  if ($r.Content -is [byte[]]) { [Text.Encoding]::ASCII.GetString($r.Content) } else { [string]$r.Content }
}
$info = $null
for ($i = 0; $i -lt 30 -and -not $info; $i++) {
  try { $info = Invoke-RestMethod -UseBasicParsing -TimeoutSec 5 "http://$srv/api/diskless/client" } catch { Start-Sleep -Seconds 2 }
}
if (-not $info) { step "server $srv not reachable - nothing to do"; exit }

# The server's current version of this script, when it differs from the golden's copy: that one runs instead.
# Same trust as the boot itself: this machine's whole disk comes from the same server.
if ($me -eq $dst) {
  try {
    $cur = Text "http://$srv/broom-diskless.ps1"
    if ($cur.Length -gt 100 -and $cur -ne [IO.File]::ReadAllText($dst)) {
      [IO.File]::WriteAllText($run, $cur, [Text.Encoding]::ASCII)
      & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $run
      exit
    }
  } catch { step "server's version of this script not fetched ($_) - running the golden's copy" }
}

step ("role {0}, golden {1} g{2}, first boot: {3}, name: {4}" -f $info.role, $info.golden, $info.ver, $info.first, $info.host)
# The LAN's router: when the server is on this machine's subnet, its boot gave Windows no gateway (Windows would send
# its whole disk through the router otherwise), so the default route is added now that the disk is connected - on the
# network card that reaches the server, for this boot only (not kept in the base or the golden).
if ($info.gateway) {
  try {
    if (-not (Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue)) {
      $if = (Find-NetRoute -RemoteIPAddress $srv -ErrorAction Stop | Select-Object -First 1).InterfaceIndex
      New-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -InterfaceIndex $if -NextHop $info.gateway -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
      step "default route via $($info.gateway) added (interface $if)"
    }
  } catch { step "default route via $($info.gateway) NOT added: $_" }
}
# The server's scripts.sha256: a downloaded script runs only if it matches.
function Fetch($f, $to) {
  $sum = $null
  foreach ($l in ((Text "http://$srv/tftp/broom-scripts/scripts.sha256") -split "`n")) {
    $p = $l.Trim() -split '\s+'
    if ($p.Count -eq 2 -and $p[1] -eq $f) { $sum = $p[0] }
  }
  if (-not $sum) { throw "$f is not in the server's scripts.sha256" }
  Invoke-WebRequest -UseBasicParsing -TimeoutSec 60 -OutFile $to "http://$srv/tftp/broom-scripts/$f"
  if ((Get-FileHash -Algorithm SHA256 $to).Hash.ToLower() -ne $sum) { Remove-Item -LiteralPath $to -Force; throw "$f does not match scripts.sha256" }
}
if ($info.role -eq 'maintenance') {
  # Its writes go into the golden: no machine's key or agent files may end up there. .NET's Directory.Delete does not
  # follow a folder mount point (it only removes it), so a volume mounted inside is never emptied with it.
  if (Test-Path $dir) {
    try { [IO.Directory]::Delete($dir, $true); step "removed $dir from the golden" } catch { step "could not remove ${dir}: $_" }
  }
  # The maintenance VM on the server: its games disks (found by their disk serial), writable, under their letters.
  if ($info.vm -and $info.games) {
    try {
      $gs = "$env:SystemRoot\Temp\broom-games-vm.ps1"; $lf = "$env:SystemRoot\Temp\broom-games-vm.txt"
      Fetch 'broom-games.ps1' $gs
      [IO.File]::WriteAllText($lf, [string]$info.games, [Text.Encoding]::ASCII)
      & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $gs -Srv $srv -LinesFile $lf
      step ("VM: games disks {0} (log: broom-games.log)" -f (($info.games -split "`n" | Where-Object { $_ } | ForEach-Object { ($_ -split ' ')[0] }) -join ', '))
    } catch { step "VM games disks FAILED: $_" }
  }
  exit
}
if ($info.role -ne 'diskless') { exit }

# The agent's files (broom-watch.ps1, broom-games.ps1, broom-vnc.cs or the release's broom-vnc.exe) from the server's
# script folder,
# each checked against its scripts.sha256; unchanged ones stay. The folder: SYSTEM + Administrators only (the key).
function AgentFiles {
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  & icacls $dir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
  $sums = @{}
  foreach ($l in ((Text "http://$srv/tftp/broom-scripts/scripts.sha256") -split "`n")) {
    $p = $l.Trim() -split '\s+'
    if ($p.Count -eq 2 -and $p[0] -match '^[0-9a-f]{64}$') { $sums[$p[1]] = $p[0] }
  }
  foreach ($f in 'broom-watch.ps1', 'broom-games.ps1', 'broom-vnc.cs', 'broom-vnc.exe') {
    $p = "$dir\$f"
    if (-not $sums.ContainsKey($f)) {
      if (Test-Path $p) { Remove-Item -LiteralPath $p -Force }   # not in this release (a local build has no exe)
      continue
    }
    if ((Test-Path $p) -and (Get-FileHash -Algorithm SHA256 $p).Hash.ToLower() -eq $sums[$f]) { continue }
    Invoke-WebRequest -UseBasicParsing -TimeoutSec 60 -OutFile $p "http://$srv/tftp/broom-scripts/$f"
    if ((Get-FileHash -Algorithm SHA256 $p).Hash.ToLower() -ne $sums[$f]) {
      Remove-Item -LiteralPath $p -Force
      throw "$f does not match the server's scripts.sha256"
    }
  }
}
function WatchArgs { "-NoProfile -ExecutionPolicy Bypass -File `"$dir\broom-watch.ps1`" -Srv $srv -Dir `"$dir`"" }

if ($info.first) {
  # First boot of this machine on this golden version: its own setup, then the restart that keeps it as its base.
  if ($info.host -and ($info.host -ne $env:COMPUTERNAME)) {
    step "machine name $env:COMPUTERNAME -> $($info.host)"
    try { Rename-Computer -NewName $info.host -Force -ErrorAction Stop } catch { step "rename FAILED: $_" }
  }
  # The Remote agent: its files, this machine's key (handed out only on this boot), and its compiled copy, all kept in
  # the base. A failure here only leaves the machine without the agent.
  try {
    AgentFiles
    $k = (Text "http://$srv/api/diskless/client/agent-key").Trim()
    if ($k -notmatch '^[0-9a-f]{64}$') { throw 'no key from the server' }
    [IO.File]::WriteAllText("$dir\agent.key", $k, [Text.Encoding]::ASCII)
    $p = Start-Process powershell.exe -ArgumentList ((WatchArgs) + ' -Prepare') -WindowStyle Hidden -Wait -PassThru
    step 'agent files, key and build ready'
  } catch { step "agent setup FAILED: $_ (the machine works without it; set up again with its next base)" }
  try {
    Invoke-RestMethod -UseBasicParsing -TimeoutSec 10 -Method Post "http://$srv/api/diskless/client/base-done" | Out-Null
    step 'base done - restarting to keep it'
  } catch { step "base-done FAILED: $_ (set up again at the next boot)"; exit }
  Restart-Computer -Force
  exit
}

# A later boot: the agent, through broom-watch.ps1 (its own task: it loops; this task has a time limit).
try { AgentFiles } catch { step "agent files not updated: $_" }
if (-not (Test-Path "$dir\agent.key")) { step 'no agent key in this base - the agent starts after the next base'; exit }
if (-not (Test-Path "$dir\broom-watch.ps1")) { step 'no broom-watch.ps1 - no agent'; exit }
try {
  $act = New-ScheduledTaskAction -Execute powershell.exe -Argument (WatchArgs)
  $set = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
  Register-ScheduledTask -TaskName BroomWatch -Action $act -Settings $set -User SYSTEM -RunLevel Highest -Force | Out-Null
  Start-ScheduledTask -TaskName BroomWatch
  step 'agent started (task BroomWatch)'
} catch { step "agent task FAILED: $_" }
