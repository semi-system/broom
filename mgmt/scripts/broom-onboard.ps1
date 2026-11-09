# broom-onboard.ps1 - "Add hardware": runs ONLY inside Broom's onboarding VM, never on a client.
# Broom boots the golden in a small VM on the server with this file in place of broom-diskless.ps1 (the golden's
# BroomDiskless startup task runs it as SYSTEM) and the job next to it (broom-onboard.json: the network cards a new PC
# reported from Windows PE - their device instance IDs, hardware IDs, compatible IDs).
# For each card it does what Windows Plug and Play does when it meets that card on that PC: it creates the device with
# exactly that instance ID and installs the best driver for it from the driver store; the card's driver is marked as a
# network-boot driver (BootFlags) so Windows loads it when it boots from the network. Then it writes
# broom-onboard-result.json and powers the VM off. Broom then puts the original broom-diskless.ps1 back and saves the
# golden's next version (or throws the work away if a card failed).
# Why: Windows booting from iSCSI only brings up a network card whose device it already knows - a driver alone is not
# enough (tested in the lab: a never-seen card hung at the Windows spinner with its driver installed and flagged).
# Creating the device the way Plug and Play would, inside the golden, is what makes the card bootable. Commercial
# diskless systems offer a similar "add new hardware" step; this is Broom's own implementation of the idea.
# ASCII only.
$ErrorActionPreference = 'Continue'
$dir = "$env:SystemRoot\Setup\Scripts"
$job = Join-Path $dir 'broom-onboard.json'
$out = Join-Path $dir 'broom-onboard-result.json'
$log = Join-Path $dir 'broom-onboard.log'
function step($m) {
  $l = '{0:yyyy-MM-dd HH:mm:ss} {1}' -f (Get-Date), $m
  try { [IO.File]::AppendAllText($log, $l + "`r`n") } catch { }
}
function done($ok, $nics, $msg) {
  $r = [ordered]@{ ok = $ok; msg = $msg; nics = @($nics); windows = [Environment]::OSVersion.VersionString }
  [IO.File]::WriteAllText($out, ($r | ConvertTo-Json -Depth 5), [Text.Encoding]::ASCII)
  step "result: ok=$ok $msg - powering off"
  Stop-Computer -Force
  exit
}
step 'onboarding VM: started'
if (-not (Test-Path $job)) { done $false @() 'no job file' }
try { $j = Get-Content -Raw $job | ConvertFrom-Json } catch { done $false @() "job file unreadable: $_" }

# Drivers from Broom's library for these cards (Drivers page; Broom put each package under broom-drv\<name>): into the
# driver store first, so "the best driver from the driver store" below can be one of them. Broom removes the folder.
foreach ($d in @($j.drivers)) {
  if (-not $d) { continue }
  $p = Join-Path $dir $d
  if (-not (Test-Path $p)) { step "driver package $d missing"; continue }
  $o = & pnputil.exe /add-driver (Join-Path $p '*.inf') /subdirs 2>&1 | Out-String
  step ("driver package {0}: pnputil exit {1}: {2}" -f $d, $LASTEXITCODE, (($o -split "`r?`n" | Where-Object { $_ -match 'Added|Published|Failed|already|Total' }) -join ' | '))
}

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
namespace BroomOnboard {
public static class Dev {
  [StructLayout(LayoutKind.Sequential)]
  public struct SP_DEVINFO_DATA { public int cbSize; public Guid ClassGuid; public int DevInst; public IntPtr Reserved; }
  const int DIF_REGISTERDEVICE = 0x19, DIF_SELECTBESTCOMPATDRV = 0x17, DIF_ALLOW_INSTALL = 0x18,
    DIF_INSTALLDEVICEFILES = 0x15, DIF_REGISTER_COINSTALLERS = 0x22, DIF_INSTALLINTERFACES = 0x20, DIF_INSTALLDEVICE = 0x02;
  const int SPDIT_COMPATDRIVER = 2, SPDRP_HARDWAREID = 1, SPDRP_COMPATIBLEIDS = 2, SPDRP_SERVICE = 4, SPDRP_DRIVER = 9,
    SPDRP_CONFIGFLAGS = 10, DIIDFLAG_NOFINISHINSTALLUI = 2;
  static readonly int ERROR_DEVINST_ALREADY_EXISTS = unchecked((int)0xE0000207);
  static readonly int ERROR_DI_DO_DEFAULT = unchecked((int)0xE000020E);
  [DllImport("setupapi.dll", SetLastError = true)]
  static extern IntPtr SetupDiCreateDeviceInfoList(ref Guid cls, IntPtr hwnd);
  [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern bool SetupDiCreateDeviceInfoW(IntPtr set, string name, ref Guid cls, string desc, IntPtr hwnd, int flags, ref SP_DEVINFO_DATA d);
  [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern bool SetupDiOpenDeviceInfoW(IntPtr set, string id, IntPtr hwnd, int flags, ref SP_DEVINFO_DATA d);
  [DllImport("setupapi.dll", SetLastError = true)]
  static extern bool SetupDiSetDeviceRegistryPropertyW(IntPtr set, ref SP_DEVINFO_DATA d, int prop, byte[] buf, int len);
  [DllImport("setupapi.dll", SetLastError = true)]
  static extern bool SetupDiGetDeviceRegistryPropertyW(IntPtr set, ref SP_DEVINFO_DATA d, int prop, out int type, byte[] buf, int len, out int need);
  [DllImport("setupapi.dll", SetLastError = true)]
  static extern bool SetupDiCallClassInstaller(int dif, IntPtr set, ref SP_DEVINFO_DATA d);
  [DllImport("setupapi.dll", SetLastError = true)]
  static extern bool SetupDiBuildDriverInfoList(IntPtr set, ref SP_DEVINFO_DATA d, int type);
  [DllImport("setupapi.dll", SetLastError = true)]
  static extern bool SetupDiDestroyDeviceInfoList(IntPtr set);
  [DllImport("newdev.dll", SetLastError = true)]
  static extern bool DiInstallDevice(IntPtr hwnd, IntPtr set, ref SP_DEVINFO_DATA d, IntPtr drv, int flags, out bool reboot);

  static byte[] Multi(string[] v) { return Encoding.Unicode.GetBytes(string.Join("\0", v) + "\0\0"); }
  static string Prop(IntPtr set, ref SP_DEVINFO_DATA d, int p) {
    int type, need; byte[] b = new byte[2048];
    if (!SetupDiGetDeviceRegistryPropertyW(set, ref d, p, out type, b, b.Length, out need)) return null;
    if (type == 4) return BitConverter.ToInt32(b, 0).ToString();
    return Encoding.Unicode.GetString(b, 0, need).TrimEnd('\0').Replace('\0', ';');
  }
  static string Err() { return "0x" + Marshal.GetLastWin32Error().ToString("X8"); }
  static bool Dif(int dif, IntPtr set, ref SP_DEVINFO_DATA d, StringBuilder log, bool must) {
    if (SetupDiCallClassInstaller(dif, set, ref d)) return true;
    int e = Marshal.GetLastWin32Error();
    if (e == ERROR_DI_DO_DEFAULT || !must) { log.AppendFormat(" dif 0x{0:X}: 0x{1:X8} (ignored);", dif, e); return true; }
    log.AppendFormat(" dif 0x{0:X} FAILED 0x{1:X8};", dif, e); return false;
  }
  // The device's key under Enum with its IDs. Windows lets SetupAPI set hardware / compatible IDs only on root-enumerated
  // (ROOT\) devices - a PCI or USB device's IDs come from its bus driver (seen: 0xE0000209 INVALID_REG_PROPERTY) - so
  // they are written straight into the key, as the bus driver's report would have put them.
  static void EnumKey(string instance, string[] hwids, string[] compat, StringBuilder log) {
    using (Microsoft.Win32.RegistryKey k = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(@"SYSTEM\CurrentControlSet\Enum\" + instance)) {
      if (k.GetValue("HardwareID") == null) { k.SetValue("HardwareID", hwids, Microsoft.Win32.RegistryValueKind.MultiString); log.Append(" HardwareID written;"); }
      if (compat != null && compat.Length > 0 && k.GetValue("CompatibleIDs") == null) k.SetValue("CompatibleIDs", compat, Microsoft.Win32.RegistryValueKind.MultiString);
      if (k.GetValue("ClassGUID") == null) k.SetValue("ClassGUID", "{4d36e972-e325-11ce-bfc1-08002be10318}");
    }
  }
  // Returns "ok|<service>|<driver key>|<configflags>|<log>" or "fail||||<log>".
  public static string Install(string instance, string[] hwids, string[] compat) {
    Guid net = new Guid("4d36e972-e325-11ce-bfc1-08002be10318");
    StringBuilder log = new StringBuilder();
    // 1. The device: created through SetupAPI (registered with the PnP manager); its IDs into its Enum key.
    IntPtr set = SetupDiCreateDeviceInfoList(ref net, IntPtr.Zero);
    if (set == new IntPtr(-1)) return "fail||||list " + Err();
    try {
      SP_DEVINFO_DATA d = new SP_DEVINFO_DATA(); d.cbSize = Marshal.SizeOf(typeof(SP_DEVINFO_DATA));
      if (SetupDiCreateDeviceInfoW(set, instance, ref net, null, IntPtr.Zero, 0, ref d)) {
        log.Append(" created;");
        byte[] h = Multi(hwids);
        if (SetupDiSetDeviceRegistryPropertyW(set, ref d, SPDRP_HARDWAREID, h, h.Length)) log.Append(" ids via SetupAPI;");
        if (Dif(DIF_REGISTERDEVICE, set, ref d, log, true)) log.Append(" registered;");
      } else {
        int e = Marshal.GetLastWin32Error();
        if (e != ERROR_DEVINST_ALREADY_EXISTS) log.Append(" create 0x" + e.ToString("X8") + ";");
        else log.Append(" exists;");
      }
    } finally { SetupDiDestroyDeviceInfoList(set); }
    try { EnumKey(instance, hwids, compat, log); } catch (Exception ex) { return "fail||||enum key: " + ex.Message + log; }
    // 2. Opened again: SetupAPI reads the IDs from the key now.
    set = SetupDiCreateDeviceInfoList(ref net, IntPtr.Zero);
    if (set == new IntPtr(-1)) return "fail||||list " + Err() + log;
    try {
      SP_DEVINFO_DATA d = new SP_DEVINFO_DATA(); d.cbSize = Marshal.SizeOf(typeof(SP_DEVINFO_DATA));
      if (!SetupDiOpenDeviceInfoW(set, instance, IntPtr.Zero, 0, ref d)) return "fail||||open " + Err() + log;
      log.Append(" opened (ids: " + Prop(set, ref d, SPDRP_HARDWAREID) + ");");
      string svc0 = Prop(set, ref d, SPDRP_SERVICE);
      if (!string.IsNullOrEmpty(svc0)) {
        return "ok|" + svc0 + "|" + Prop(set, ref d, SPDRP_DRIVER) + "|" + Prop(set, ref d, SPDRP_CONFIGFLAGS) + "|" + log + " already installed";
      }
      // The best driver from the driver store (inbox or added), as Plug and Play would choose it.
      bool reboot;
      if (DiInstallDevice(IntPtr.Zero, set, ref d, IntPtr.Zero, DIIDFLAG_NOFINISHINSTALLUI, out reboot)) {
        log.Append(" DiInstallDevice ok" + (reboot ? " (reboot)" : "") + ";");
      } else {
        log.Append(" DiInstallDevice " + Err() + ", class installer steps:");
        if (!SetupDiBuildDriverInfoList(set, ref d, SPDIT_COMPATDRIVER)) return "fail||||driver list " + Err() + log;
        if (!Dif(DIF_SELECTBESTCOMPATDRV, set, ref d, log, true)) return "fail||||no driver for it in the driver store;" + log;
        Dif(DIF_ALLOW_INSTALL, set, ref d, log, false);
        Dif(DIF_INSTALLDEVICEFILES, set, ref d, log, false);
        Dif(DIF_REGISTER_COINSTALLERS, set, ref d, log, false);
        Dif(DIF_INSTALLINTERFACES, set, ref d, log, false);
        if (!Dif(DIF_INSTALLDEVICE, set, ref d, log, true)) return "fail||||" + log;
      }
      string svc = Prop(set, ref d, SPDRP_SERVICE);
      if (string.IsNullOrEmpty(svc)) return "fail||||installed but no service" + log;
      return "ok|" + svc + "|" + Prop(set, ref d, SPDRP_DRIVER) + "|" + Prop(set, ref d, SPDRP_CONFIGFLAGS) + "|" + log;
    } finally { SetupDiDestroyDeviceInfoList(set); }
  }
}
}
'@

$res = @(); $bad = 0
foreach ($n in @($j.nics)) {
  step "card $($n.instance) ($($n.name))"
  $hw = [string[]]@($n.hwids); $cp = [string[]]@($n.compat)
  $r = ([BroomOnboard.Dev]::Install([string]$n.instance, $hw, $cp)).Split('|', 5)
  $e = [ordered]@{ instance = $n.instance; name = $n.name; ok = ($r[0] -eq 'ok'); service = $r[1]; driver = $r[2]; configflags = $r[3]; log = $r[4] }
  if ($e.ok) {
    # Network-boot driver: the boot loader loads it when Windows starts from the network (iSCSI), whatever its Start.
    $k = "HKLM:\SYSTEM\CurrentControlSet\Services\$($e.service)"
    try {
      $bf = (Get-ItemProperty -Path $k -Name BootFlags -ErrorAction SilentlyContinue).BootFlags
      if ($null -eq $bf) { $bf = 0 }
      if (($bf -band 1) -eq 0) { Set-ItemProperty -Path $k -Name BootFlags -Value ([int]($bf -bor 1)) -Type DWord; $e.log += " BootFlags $bf->$($bf -bor 1);" }
      $e.start = (Get-ItemProperty -Path $k -Name Start).Start
    } catch { $e.ok = $false; $e.log += " service $($e.service): $_" }
    try {
      $drv = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\$($e.driver)" -ErrorAction Stop
      $e.inf = $drv.InfPath; $e.version = $drv.DriverVersion; $e.desc = $drv.DriverDesc
    } catch { }
  }
  if (-not $e.ok) { $bad++ }
  step ("  -> ok={0} service={1} driver={2} flags={3} {4}" -f $e.ok, $e.service, $e.driver, $e.configflags, $e.log)
  $res += $e
}
# Broom decides per card (the PC's boot card must be in; another card without a driver in the golden, e.g. Wi-Fi,
# is only reported).
$n = @($res).Count
if ($n -eq 0) { done $false @() 'the job lists no network card' }
if ($bad -ge $n) { done $false $res "no card installed ($bad of $n failed)" }
done $true $res ("{0} of {1} card(s) installed" -f ($n - $bad), $n)
