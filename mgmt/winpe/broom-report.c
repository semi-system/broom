/* broom-report.c - "Add hardware", Windows PE side (onboard.rs). Broom boots a new PC into Windows PE with wimboot and
 * injects this program plus a startnet.cmd that runs it:
 *   broom-report.exe <server> <token> [<ip> <mask> <gateway>]
 * It lists the PC's network cards the way Windows sees them (pnputil: device instance IDs, hardware IDs, compatible
 * IDs; wmic: which card has which MAC), sends that to Broom, shows Broom's progress while Broom installs the card(s)
 * into the golden, then restarts the PC (it boots the golden's new version).
 * A native program on purpose: the Windows PE of a Windows 11 24H2 installer has cscript but no working script engine
 * (seen 31 Oct 2026: "Can't find script engine JScript/VBScript"), and no PowerShell or curl. Only kernel32 + winhttp.
 * First it loads the network-card drivers Broom sends along (broom-drivers.tar: the library's network-card packages),
 * for a card Windows PE has none for; when Broom still cannot be reached it lists what Windows PE sees.
 * Build: winpe/build.sh (mingw-w64), output scripts/broom-report.exe (committed, embedded as an asset). ASCII only. */
#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static wchar_t host[256];
static INTERNET_PORT port = 80;
static char token[80];

static void say(const char *m) { printf("  %s\n", m); fflush(stdout); }

/* Run a command; its output (UTF-16 output from wmic folded to ASCII). Caller frees. */
static char *run(const char *cmd) {
    FILE *p = _popen(cmd, "rb");
    size_t cap = 1 << 16, n = 0;
    char *b = malloc(cap + 1);
    if (!b) return NULL;
    if (p) {
        size_t k;
        while ((k = fread(b + n, 1, cap - n, p)) > 0) {
            n += k;
            if (n == cap) {
                char *nb = realloc(b, cap * 2 + 1);
                if (!nb) break;
                b = nb;
                cap *= 2;
            }
        }
        _pclose(p);
    }
    /* UTF-16LE (wmic into a pipe) -> drop the zero bytes; then cut anything not printable ASCII. */
    size_t w = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)b[i];
        if (c == 0 || c == 0xFF || c == 0xFE) continue;
        b[w++] = (c == '\r' || c == '\n' || c == '\t' || (c >= 32 && c < 127)) ? (char)c : '?';
    }
    b[w] = 0;
    return b;
}

/* HTTP to Broom: path is "/api/onboard/..."; the token is appended. Returns the status (0 = no answer); body in *out. */
static int http(const wchar_t *verb, const char *path, const char *body, char **out) {
    int status = 0;
    *out = NULL;
    wchar_t wpath[512];
    swprintf(wpath, 512, L"%hs?t=%hs", path, token);
    HINTERNET s = WinHttpOpen(L"broom-report", WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME,
                              WINHTTP_NO_PROXY_BYPASS, 0);
    if (!s) return 0;
    WinHttpSetTimeouts(s, 5000, 5000, 30000, 30000);
    HINTERNET c = WinHttpConnect(s, host, port, 0);
    HINTERNET r = c ? WinHttpOpenRequest(c, verb, wpath, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0) : NULL;
    DWORD len = body ? (DWORD)strlen(body) : 0;
    if (r && WinHttpSendRequest(r, L"Content-Type: text/plain\r\n", (DWORD)-1L, (LPVOID)body, len, len, 0) &&
        WinHttpReceiveResponse(r, NULL)) {
        DWORD code = 0, sz = sizeof(code);
        WinHttpQueryHeaders(r, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, NULL, &code, &sz, NULL);
        status = (int)code;
        size_t cap = 4096, n = 0;
        char *b = malloc(cap + 1);
        DWORD got = 0;
        while (b && WinHttpReadData(r, b + n, (DWORD)(cap - n), &got) && got > 0) {
            n += got;
            if (n == cap) {
                char *nb = realloc(b, cap * 2 + 1);
                if (!nb) break;
                b = nb;
                cap *= 2;
            }
        }
        if (b) b[n] = 0;
        *out = b;
    }
    if (r) WinHttpCloseHandle(r);
    if (c) WinHttpCloseHandle(c);
    WinHttpCloseHandle(s);
    return status;
}

/* "key":"value" out of Broom's JSON answer (compact, no nesting) -> buf. */
static void field(const char *json, const char *key, char *buf, size_t cap) {
    char pat[64];
    buf[0] = 0;
    if (!json) return;
    snprintf(pat, sizeof pat, "\"%s\":\"", key);
    const char *p = strstr(json, pat);
    if (!p) return;
    p += strlen(pat);
    size_t n = 0;
    while (*p && *p != '"' && n + 1 < cap) {
        if (*p == '\\' && p[1]) p++;
        buf[n++] = *p++;
    }
    buf[n] = 0;
}

static int reachable(void) {
    char *b = NULL;
    int st = http(L"GET", "/api/onboard/state", NULL, &b);
    free(b);
    return st == 200;
}

/* ---- Network-card drivers from Broom's library (drivers.rs: winpe_bundle) ----
 * Some cards have no driver in Windows PE (it would never reach Broom). Broom sends every network-card package of its
 * library as broom-drivers.tar (a plain ustar; wimboot puts it in X:\Windows\System32). Unpacked to X:\broom-drivers,
 * then every .inf is loaded with drvload, before the network is looked for. */
static void mkdirs(const char *path) {
    char t[MAX_PATH];
    snprintf(t, sizeof t, "%s", path);
    for (char *p = t + 3; *p; p++) {
        if (*p == '\\') {
            *p = 0;
            CreateDirectoryA(t, NULL);
            *p = '\\';
        }
    }
    CreateDirectoryA(t, NULL);
}

/* A path from the archive is safe: relative, no "..", no drive or stream colon. */
static int safe_rel(const char *n) {
    if (!*n || n[0] == '/' || n[0] == '\\' || strchr(n, ':')) return 0;
    for (const char *p = n; *p; p++)
        if (p[0] == '.' && p[1] == '.' && (p == n || p[-1] == '/' || p[-1] == '\\')) return 0;
    return 1;
}

/* Unpack ustar `tar` (with GNU long names) into `dest`; returns the number of files written, -1 if unreadable. */
static int untar(const char *tar, const char *dest) {
    FILE *f = fopen(tar, "rb");
    if (!f) return -1;
    unsigned char h[512];
    char longname[1024] = "", name[1024], out[MAX_PATH];
    int files = 0;
    static unsigned char buf[1 << 16];
    while (fread(h, 1, 512, f) == 512) {
        int zero = 1;
        for (int i = 0; i < 512; i++)
            if (h[i]) { zero = 0; break; }
        if (zero) break;
        char sz[13];
        memcpy(sz, h + 124, 12);
        sz[12] = 0;
        unsigned long long size = strtoull(sz, NULL, 8), pad = (512 - size % 512) % 512;
        char type = (char)h[156];
        if (type == 'L') {
            size_t n = size < sizeof longname - 1 ? (size_t)size : sizeof longname - 1;
            if (fread(longname, 1, n, f) != n) break;
            longname[n] = 0;
            fseek(f, (long)(size - n + pad), SEEK_CUR);
            continue;
        }
        if (longname[0]) {
            snprintf(name, sizeof name, "%s", longname);
            longname[0] = 0;
        } else {
            memcpy(name, h, 100);
            name[100] = 0;
        }
        for (char *p = name; *p; p++)
            if (*p == '/') *p = '\\';
        if ((type == '0' || type == 0) && safe_rel(name) &&
            snprintf(out, sizeof out, "%s\\%s", dest, name) < (int)sizeof out) {
            char *slash = strrchr(out, '\\');
            *slash = 0;
            mkdirs(out);
            *slash = '\\';
            FILE *o = fopen(out, "wb");
            unsigned long long left = size;
            while (left > 0) {
                size_t n = left < sizeof buf ? (size_t)left : sizeof buf;
                if (fread(buf, 1, n, f) != n) { left = 0; break; }
                if (o) fwrite(buf, 1, n, o);
                left -= n;
            }
            if (o) { fclose(o); files++; }
            fseek(f, (long)pad, SEEK_CUR);
        } else {
            fseek(f, (long)(size + pad), SEEK_CUR);
        }
    }
    fclose(f);
    return files;
}

/* drvload every .inf under `dir`; counts loaded / tried. */
static void load_infs(const char *dir, int *ok, int *tried) {
    char pat[MAX_PATH], p[MAX_PATH], cmd[MAX_PATH + 64];
    WIN32_FIND_DATAA fd;
    snprintf(pat, sizeof pat, "%s\\*", dir);
    HANDLE hf = FindFirstFileA(pat, &fd);
    if (hf == INVALID_HANDLE_VALUE) return;
    do {
        if (!strcmp(fd.cFileName, ".") || !strcmp(fd.cFileName, "..")) continue;
        snprintf(p, sizeof p, "%s\\%s", dir, fd.cFileName);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            load_infs(p, ok, tried);
        } else {
            size_t n = strlen(fd.cFileName);
            if (n > 4 && !_stricmp(fd.cFileName + n - 4, ".inf")) {
                snprintf(cmd, sizeof cmd, "drvload \"%s\" >nul 2>&1", p);
                (*tried)++;
                if (system(cmd) == 0) (*ok)++;
                else printf("  not loaded: %s (unsigned for Windows PE, or not for this Windows)\n", p + 17);
            }
        }
    } while (FindNextFileA(hf, &fd));
    FindClose(hf);
}

static void load_drivers(void) {
    char tar[MAX_PATH];
    GetSystemDirectoryA(tar, sizeof tar);
    strncat(tar, "\\broom-drivers.tar", sizeof tar - strlen(tar) - 1);
    if (GetFileAttributesA(tar) == INVALID_FILE_ATTRIBUTES) return;
    int n = untar(tar, "X:\\broom-drivers");
    if (n <= 0) {
        say("Broom's network-card drivers could not be unpacked");
        return;
    }
    int ok = 0, tried = 0;
    load_infs("X:\\broom-drivers", &ok, &tried);
    printf("  loaded %d of %d network-card drivers from Broom's library\n", ok, tried);
    fflush(stdout);
}

/* Broom cannot be reached: the network cards Windows PE has no driver for (devices with a problem whose IDs carry the
 * network-controller class code CC_0200), so the card can be looked up and its driver added on Broom. */
static void show_cards(void) {
    char *pr = run("pnputil /enum-devices /problem /ids");
    int found = 0;
    say("");
    for (char *b = pr; b && *b;) {
        char *end = strstr(b, "\r\n\r\n");
        if (end) *end = 0;
        if (strstr(b, "CC_0200")) {
            char inst[300] = "", hw[300] = "";
            const char *i = strstr(b, "Instance ID:"), *h = strstr(b, "Hardware IDs:");
            if (i) sscanf(i + 12, " %299[^\r\n]", inst);
            if (h) sscanf(h + 13, " %299[^\r\n]", hw);
            printf("  Network card without a driver: %s\n    %s\n", hw, inst);
            found++;
        }
        b = end ? end + 4 : NULL;
    }
    free(pr);
    if (!found) say("No network card with a missing driver found (cable, switch port or DHCP?).");
    else {
        say("Add the card's driver on Broom (Drivers page: an extracted driver folder with its .cat, zipped),");
        say("press Retry under Add hardware (Diskless page), then network-boot this PC again.");
    }
}

static int ipv4(const char *s) {
    int a, b, c, d;
    char x;
    return s && sscanf(s, "%d.%d.%d.%d%c", &a, &b, &c, &d, &x) == 4;
}

int main(int argc, char **argv) {
    if (argc < 3 || strncmp(argv[1], "http://", 7) != 0) {
        say("usage: broom-report.exe http://<server> <token> [<ip> <mask> <gateway>]");
        return 2;
    }
    /* http://host[:port] */
    char h[256];
    snprintf(h, sizeof h, "%s", argv[1] + 7);
    char *colon = strchr(h, ':');
    if (colon) {
        *colon = 0;
        port = (INTERNET_PORT)atoi(colon + 1);
    }
    swprintf(host, 256, L"%hs", h);
    snprintf(token, sizeof token, "%s", argv[2]);

    say("Broom: adding this PC's network card to the golden");
    /* 0. Network-card drivers from Broom's library, for a card Windows PE has none for. */
    load_drivers();
    /* 1. The network: Windows PE's DHCP; without a lease after ~40 s, the address iPXE had. */
    int ok = 0;
    for (int i = 0; i < 20 && !(ok = reachable()); i++) Sleep(2000);
    if (!ok && argc >= 5 && ipv4(argv[3]) && ipv4(argv[4])) {
        char cmd[512];
        printf("  no DHCP answer - using %s/%s\n", argv[3], argv[4]);
        snprintf(cmd, sizeof cmd, "wmic nicconfig where \"IPEnabled=TRUE\" call EnableStatic (\"%s\"),(\"%s\") >nul 2>&1",
                 argv[3], argv[4]);
        system(cmd);
        if (argc >= 6 && ipv4(argv[5]) && strcmp(argv[5], "0.0.0.0") != 0) {
            snprintf(cmd, sizeof cmd, "wmic nicconfig where \"IPEnabled=TRUE\" call SetGateways (\"%s\"),(1) >nul 2>&1",
                     argv[5]);
            system(cmd);
        }
        for (int i = 0; i < 15 && !(ok = reachable()); i++) Sleep(2000);
    }
    if (!ok) {
        printf("  Broom (%s) cannot be reached: Windows PE may have no driver for this network card.\n", argv[1]);
        system("ipconfig");
        show_cards();
        return 1;
    }
    /* 2. What Windows sees: every network device with its IDs, then which one has which MAC. */
    char *pnp = run("pnputil /enum-devices /class Net /ids");
    if (pnp && !strstr(pnp, "Hardware IDs")) {
        char *more = run("pnputil /enum-devices /class Net /properties");
        if (more) {
            char *both = malloc(strlen(pnp) + strlen(more) + 3);
            if (both) {
                sprintf(both, "%s\r\n%s", pnp, more);
                free(pnp);
                pnp = both;
            }
            free(more);
        }
    }
    /* A card Windows PE has no driver for is not in the Net class: it is among the problem devices (Broom keeps those
       whose class code says network controller). */
    char *prob = run("pnputil /enum-devices /problem /ids");
    if (pnp && prob) {
        char *both = malloc(strlen(pnp) + strlen(prob) + 3);
        if (both) {
            sprintf(both, "%s\r\n%s", pnp, prob);
            free(pnp);
            pnp = both;
        }
    }
    free(prob);
    char *macs = run("wmic nic get MACAddress,PNPDeviceID 2>nul");
    /* Whether the firmware booted with Secure Boot on (shown in the job's log). */
    char *sb = run("reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State /v UEFISecureBootEnabled 2>nul");
    size_t len = (pnp ? strlen(pnp) : 0) + (macs ? strlen(macs) : 0) + (sb ? strlen(sb) : 0) + 96;
    char *report = malloc(len);
    if (!report) return 1;
    snprintf(report, len, "%s\r\n=== wmic nic ===\r\n%s\r\n=== secure boot ===\r\n%s", pnp ? pnp : "", macs ? macs : "",
             sb ? sb : "");
    char *ans = NULL;
    int st = http(L"POST", "/api/onboard/report", report, &ans);
    if (st != 200) {
        printf("  Broom refused the report: %d %s\n", st, ans ? ans : "");
        printf("%s\n", report);
        return 1;
    }
    printf("  Sent. %s\n", ans ? ans : "");
    free(ans);
    /* 3. Broom installs the card(s) into the golden in a VM on the server (a few minutes). Its progress: */
    char last[1024] = "", state[64], msg[1024];
    for (;;) {
        Sleep(5000);
        ans = NULL;
        if (http(L"GET", "/api/onboard/state", NULL, &ans) != 200) {
            free(ans);
            continue;
        }
        field(ans, "state", state, sizeof state);
        field(ans, "msg", msg, sizeof msg);
        free(ans);
        for (char *c = msg; *c; c++)
            if ((unsigned char)*c >= 127 || (unsigned char)*c < 32) *c = '-';
        if (strcmp(msg, last) != 0) {
            say(msg);
            snprintf(last, sizeof last, "%s", msg);
        }
        if (strcmp(state, "done") == 0) {
            say("Done - restarting into the golden.");
            Sleep(5000);
            system("wpeutil reboot");
            return 0;
        }
        if (strcmp(state, "waiting") != 0 && strcmp(state, "installing") != 0) {
            printf("  Not done (%s) - see the Diskless page. Restarting in 60 s.\n", state[0] ? state : "no job");
            Sleep(60000);
            system("wpeutil reboot");
            return 1;
        }
    }
}
