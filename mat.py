#!/usr/bin/env python3
# ddosmat.py - wifi recon + network toolkit + android remote control via adb
#
# commands:
#   /scan /wifi /clients /ports /ping /dns /trace /info
#   /control        - find adb-exposed phones on the subnet and remote-control them
#   /flood          - spawn ddos.py in cwd
#   /help /clear /exit
#
# deps:
#   pkg install termux-api       (for wifi scan details)
#   pkg install android-tools    (for adb — required for /control)
#   pkg install iputils          (for ping/traceroute)
#   pkg install iproute2         (optional, gateway detection)

import asyncio
import concurrent.futures
import json
import os
import shlex
import shutil
import socket
import subprocess
import sys
import time

VERSION = "1.1"

DEFAULT_TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 161, 389,
    443, 445, 465, 514, 515, 548, 554, 587, 631, 636, 873, 993, 995,
    1080, 1433, 1521, 1723, 1883, 2049, 2082, 2083, 2086, 2087,
    2181, 2222, 2375, 3000, 3128, 3306, 3389, 3690, 4000, 4443, 5000,
    5060, 5222, 5357, 5432, 5555, 5601, 5672, 5900, 5984, 6379, 6667,
    7001, 7070, 8000, 8008, 8080, 8081, 8086, 8088, 8443, 8500, 8834,
    8888, 9000, 9042, 9090, 9200, 9300, 9443, 10000, 11211, 15672,
    25565, 27017, 27018, 50000, 50070,
]

PORT_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap",
    161: "snmp", 389: "ldap", 443: "https", 445: "smb", 465: "smtps",
    514: "syslog", 587: "smtp-sub", 631: "ipp", 993: "imaps", 995: "pop3s",
    1080: "socks", 1433: "mssql", 1521: "oracle", 1723: "pptp", 1883: "mqtt",
    2049: "nfs", 3306: "mysql", 3389: "rdp", 5432: "postgres",
    5555: "adb-tcp", 5900: "vnc", 5984: "couchdb", 6379: "redis",
    6667: "irc", 8080: "http-alt", 8443: "https-alt", 8888: "http-alt",
    9200: "elastic", 11211: "memcached", 25565: "minecraft", 27017: "mongodb",
}

BANNER = r"""
  ___  ___  ___  ___  __  __    _  _____
 |   \|   \/ _ \/ __| \ \/ /   /_\|_   _|
 | |) | |) | (_) \__ \  >  <   / _ \ | |
 |___/|___/ \___/|___/ /_/\_\ /_/ \_\|_|

  wifi recon + network toolkit + android remote
  v{}   /help for commands
""".format(VERSION)

# ---------- utils ----------

def has(cmd):
    return shutil.which(cmd) is not None


def run(cmd, timeout=10, capture=True):
    try:
        p = subprocess.run(
            cmd, shell=isinstance(cmd, str),
            capture_output=capture, text=True, timeout=timeout,
        )
        return p.returncode, (p.stdout or ""), (p.stderr or "")
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except FileNotFoundError as e:
        return -2, "", str(e)
    except Exception as e:
        return -3, "", str(e)


def c(text, color):
    codes = {"r": "31", "g": "32", "y": "33", "b": "34", "m": "35",
             "c": "36", "w": "37", "bold": "1", "dim": "2"}
    code = codes.get(color, "0")
    return f"\033[{code}m{text}\033[0m"


def print_table(headers, rows, widths=None):
    if not rows:
        print(c("  (no results)", "dim"))
        return
    ncols = len(headers)
    if widths is None:
        widths = [len(h) for h in headers]
        for r in rows:
            for i in range(ncols):
                widths[i] = max(widths[i], len(str(r[i])))
    fmt = "  ".join("{{:<{}}}".format(w) for w in widths)
    print("  " + c(fmt.format(*headers), "bold"))
    print("  " + c("  ".join("-" * w for w in widths), "dim"))
    for r in rows:
        print("  " + fmt.format(*[str(x) for x in r]))


def prefix_bin(name):
    prefix = os.environ.get("PREFIX", "/data/data/com.termux/files/usr")
    p = os.path.join(prefix, "bin", name)
    return p if os.path.exists(p) else name


# ---------- network info ----------

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.3)
        s.connect(("1.1.1.1", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        pass
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return None


def get_gateway():
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                parts = line.strip().split()
                if len(parts) >= 3 and parts[1] == "00000000":
                    h = parts[2]
                    return ".".join(str(int(h[i:i+2], 16))
                                    for i in (6, 4, 2, 0))
    except Exception:
        pass
    rc, out, _ = run(["ip", "route"])
    if rc == 0:
        for line in out.splitlines():
            if line.startswith("default") and "via" in line:
                parts = line.split()
                return parts[parts.index("via") + 1]
    return None


def get_subnet(local_ip):
    if not local_ip or local_ip.count(".") != 3:
        return None
    return ".".join(local_ip.split(".")[:3])


def read_arp_table():
    entries = {}
    try:
        with open("/proc/net/arp") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) < 6:
                    continue
                ip, _, flags, mac, _, dev = parts[:6]
                if mac == "00:00:00:00:00:00" or flags == "0x0":
                    continue
                entries[ip] = {"mac": mac, "dev": dev}
    except Exception:
        pass
    return entries


def wifi_scan():
    tool = prefix_bin("termux-wifi-scaninfo")
    if not has(tool) and not os.path.exists(tool):
        print(c("  [!] termux-api not installed", "y"))
        print(c("      pkg install termux-api  + install Termux:API app", "dim"))
        return []
    rc, out, err = run([tool], timeout=20)
    if rc != 0 or not out.strip():
        print(c(f"  [!] wifi scan failed: {err.strip() or 'no output'}", "y"))
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        print(c("  [!] bad scan json", "y"))
        return []

    rows = []
    for ap in data:
        ssid = ap.get("ssid", "") or "<hidden>"
        bssid = ap.get("bssid", "")
        freq = ap.get("frequency", 0)
        sig = ap.get("level", ap.get("rssi", 0))
        cap = ap.get("capabilities", "")
        band = "2.4" if freq and freq < 3000 else ("5" if freq else "?")
        ch = freq_to_channel(freq) if freq else ""
        rows.append((ssid, bssid, f"{sig}dBm", band, ch, short_sec(cap)))
    rows.sort(key=lambda r: int(r[2].rstrip("dBm") or -999), reverse=True)
    print(c(f"\n  [+] {len(rows)} networks\n", "g"))
    print_table(["SSID", "BSSID", "Signal", "Band", "Ch", "Sec"], rows)
    print()
    return rows


def freq_to_channel(freq):
    if not freq:
        return ""
    if freq == 2484:
        return "14"
    if 2412 <= freq <= 2472:
        return str((freq - 2407) // 5)
    if 5000 <= freq <= 5900:
        return str((freq - 5000) // 5)
    return ""


def short_sec(cap):
    if not cap:
        return "open"
    cap = cap.upper()
    for k in ("WPA3", "WPA2", "WPA", "WEP"):
        if k in cap:
            return k
    return "open"


# ---------- host discovery ----------

async def _probe(ip, port, timeout=0.35):
    try:
        r, w = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        w.close()
        try:
            await w.wait_closed()
        except Exception:
            pass
        return ip
    except Exception:
        return None


async def _sweep_ports(ips, ports, timeout=0.35, concurrency=512):
    sem = asyncio.Semaphore(concurrency)
    found = set()

    async def one(ip, port):
        async with sem:
            r = await _probe(ip, port, timeout)
            if r:
                found.add(r)

    tasks = [one(ip, port) for ip in ips for port in ports]
    await asyncio.gather(*tasks)
    return found


async def _sweep_ip(ip, ports, timeout=0.35):
    for port in ports:
        r = await _probe(ip, port, timeout)
        if r:
            return ip
    return None


def discover_clients(subnet, do_ping=True):
    if not subnet:
        print(c("  [!] no subnet", "y"))
        return []
    ips = [f"{subnet}.{i}" for i in range(1, 255)]

    print(c(f"  [*] probing {subnet}.0/24 ...", "dim"))
    found = set()

    if do_ping and has("ping"):
        found |= set(ping_sweep(ips, timeout=1))

    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        found |= loop.run_until_complete(
            _sweep_ports(ips, [80, 443, 22, 5555], timeout=0.3)
        )
        loop.close()
    except Exception:
        pass

    arp = read_arp_table()
    found |= set(arp.keys())

    rows = []
    for ip in sorted(found, key=lambda x: tuple(int(p) for p in x.split("."))):
        mac = arp.get(ip, {}).get("mac", "")
        vendor = lookup_vendor(mac)
        rows.append((ip, mac or "-", vendor or "-"))
    print(c(f"\n  [+] {len(rows)} live hosts\n", "g"))
    print_table(["IP", "MAC", "Vendor"], rows)
    print()
    return rows


def ping_sweep(ips, timeout=1):
    def p(ip):
        rc, _, _ = run(["ping", "-c", "1", "-W", str(timeout), ip],
                       timeout=timeout + 1)
        return ip if rc == 0 else None
    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as ex:
        for r in ex.map(p, ips):
            if r:
                found.append(r)
    return found


# ---------- port scan ----------

async def _scan_one(ip, port, timeout=0.8):
    try:
        r, w = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        banner = ""
        try:
            data = await asyncio.wait_for(r.read(128), timeout=0.5)
            if data:
                banner = data.decode("utf-8", "replace").strip().splitlines()[0][:48]
        except Exception:
            pass
        w.close()
        try:
            await w.wait_closed()
        except Exception:
            pass
        return (port, "open", banner)
    except Exception:
        return None


async def _port_scan(ip, ports, concurrency=512, timeout=0.8):
    sem = asyncio.Semaphore(concurrency)
    results = []

    async def one(port):
        async with sem:
            r = await _scan_one(ip, port, timeout)
            if r:
                results.append(r)

    await asyncio.gather(*(one(p) for p in ports))
    return sorted(results)


def port_scan(ip, ports):
    t0 = time.time()
    print(c(f"  [*] scanning {ip} — {len(ports)} ports", "dim"))
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        results = loop.run_until_complete(_port_scan(ip, ports))
        loop.close()
    except Exception as e:
        print(c(f"  [!] {e}", "y"))
        return []
    dt = time.time() - t0
    print(c(f"\n  [+] {len(results)} open in {dt:.2f}s\n", "g"))
    rows = [(p, s, PORT_NAMES.get(p, ""), b) for p, s, b in results]
    print_table(["Port", "State", "Service", "Banner"], rows)
    print()
    return results


# ---------- single-host ----------

def ping_host(ip, count=4):
    rc, out, err = run(["ping", "-c", str(count), ip], timeout=count * 2 + 2)
    if rc == -2:
        print(c("  [!] pkg install iputils", "y"))
        return
    print(out)


def dns_lookup(host):
    print(c(f"\n  [*] resolving {host}\n", "dim"))
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        print(c(f"  [!] {e}", "y"))
        return
    rows, seen = [], set()
    for fam, _, _, _, sa in infos:
        ip = sa[0]
        if ip in seen:
            continue
        seen.add(ip)
        try:
            rev = socket.gethostbyaddr(ip)[0]
        except Exception:
            rev = "-"
        rows.append(("IPv4" if fam == socket.AF_INET else "IPv6", ip, rev))
    print_table(["Family", "Address", "PTR"], rows)
    print()


def traceroute(host, max_hops=20):
    print(c(f"\n  [*] traceroute {host}\n", "dim"))
    if not has("ping"):
        print(c("  [!] pkg install iputils", "y"))
        return
    for ttl in range(1, max_hops + 1):
        rc, out, _ = run(
            ["ping", "-c", "1", "-W", "1", "-t", str(ttl), host], timeout=3
        )
        line = ""
        for l in out.splitlines():
            if "bytes from" in l:
                line = l.strip()
                break
            if "From " in l or "from " in l:
                line = l.strip()
                break
        print(f"  {ttl:>2}  {line}" if line else f"  {ttl:>2}  * * *")
        if line and "Time to live exceeded" not in line:
            break


# ---------- vendor ----------

_OUI = {
    "00:1A:2B": "Apple", "00:1B:63": "Apple", "00:1E:C2": "Apple",
    "3C:07:54": "Apple", "40:6C:8F": "Apple", "68:AB:1E": "Apple",
    "7C:D1:C3": "Apple", "8C:85:90": "Apple", "9C:04:EB": "Apple",
    "A4:83:E7": "Apple", "B8:E8:56": "Apple", "C8:2A:14": "Apple",
    "D0:03:DF": "Apple", "F0:18:98": "Apple",
    "3C:5A:B4": "Google", "3C:28:6D": "Google", "54:60:09": "Google",
    "94:EB:2C": "Google", "A4:77:33": "Google", "F4:F5:D8": "Google",
    "F4:F5:E8": "Google", "DA:A1:19": "Google",
    "00:1D:D8": "Microsoft", "28:18:78": "Microsoft", "7C:1E:52": "Microsoft",
    "60:45:BD": "Microsoft", "C8:3F:26": "Microsoft",
    "00:1B:44": "Samsung", "2C:44:01": "Samsung", "50:32:75": "Samsung",
    "78:1F:DB": "Samsung", "8C:71:F8": "Samsung", "BC:14:85": "Samsung",
    "CC:07:AB": "Samsung", "E8:50:8B": "Samsung",
    "00:1E:58": "D-Link", "1C:7E:E5": "D-Link", "84:C9:B2": "D-Link",
    "00:24:B2": "Netgear", "20:4E:7F": "Netgear", "9C:3D:CF": "Netgear",
    "A0:40:A0": "Netgear", "C0:3F:0E": "Netgear",
    "F8:1A:67": "TP-Link", "50:C7:BF": "TP-Link", "A4:2B:B0": "TP-Link",
    "C4:6E:1F": "TP-Link", "EC:08:6B": "TP-Link",
    "00:0C:29": "VMware", "00:50:56": "VMware", "08:00:27": "VirtualBox",
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    "00:17:88": "Philips Hue", "00:55:DA": "Ring", "34:3E:A4": "Ring",
    "44:65:0D": "Amazon", "68:54:FD": "Amazon", "74:C2:46": "Amazon",
    "A0:02:DC": "Amazon", "F0:27:2D": "Amazon", "FC:65:DE": "Amazon",
    "0C:47:C9": "Espressif", "24:0A:C4": "Espressif", "30:AE:A4": "Espressif",
    "3C:71:BF": "Espressif", "5C:CF:7F": "Espressif", "84:0D:8E": "Espressif",
    "A4:CF:12": "Espressif", "B4:E6:2D": "Espressif", "CC:50:E3": "Espressif",
    "DC:4F:22": "Espressif", "EC:FA:BC": "Espressif", "F4:CF:A2": "Espressif",
}


def lookup_vendor(mac):
    if not mac or mac == "-":
        return None
    return _OUI.get(mac.upper()[:8])


# ---------- ADB / remote control ----------

def adb_available():
    return has("adb")


def adb_cmd(serial, *args, timeout=15):
    """run adb -s <serial> <args...>. returns (rc, stdout, stderr)."""
    cmd = ["adb", "-s", serial] + list(args)
    return run(cmd, timeout=timeout)


def adb_scan_subnet(subnet, timeout=0.6, concurrency=512):
    """look for phones with adb tcp exposed on 5555 (and a few common alt ports)."""
    if not subnet:
        print(c("  [!] no subnet to scan", "y"))
        return []
    ips = [f"{subnet}.{i}" for i in range(1, 255)]
    print(c(f"  [*] hunting adb endpoints on {subnet}.0/24 ...", "dim"))

    # primary: 5555. also probe 5556-5557 (occasionally used) and a slice of
    # android 11 wireless-debug ephemeral range — those need pairing though.
    ports = [5555, 5556, 5557]

    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        hits = loop.run_until_complete(
            _scan_adb(ips, ports, timeout, concurrency)
        )
        loop.close()
    except Exception as e:
        print(c(f"  [!] {e}", "y"))
        return []

    if not hits:
        print(c("\n  [+] no adb-exposed phones on this subnet\n", "y"))
        print(c("  notes:", "dim"))
        print(c("    - adb tcp must be enabled on the target", "dim"))
        print(c("      (Settings > Developer options > Wireless debugging,", "dim"))
        print(c("       or `adb tcpip 5555` over usb once)", "dim"))
        print(c("    - android 11+ wireless debugging uses a randomized port", "dim"))
        print(c("      and requires pairing — not blind-scannable", "dim"))
        print()
        return []

    print(c(f"\n  [+] {len(hits)} adb endpoint(s) found\n", "g"))
    rows = [(ip, p, "adb-tcp") for ip, p in hits]
    print_table(["IP", "Port", "Service"], rows)
    print()
    return hits


async def _scan_adb(ips, ports, timeout, concurrency):
    sem = asyncio.Semaphore(concurrency)
    hits = []

    async def one(ip, port):
        async with sem:
            r = await _probe(ip, port, timeout)
            if r:
                hits.append((ip, port))

    await asyncio.gather(*(one(ip, p) for ip in ips for p in ports))
    return hits


def adb_connect(ip, port=5555):
    if not adb_available():
        print(c("  [!] adb not installed", "y"))
        print(c("      pkg install android-tools", "dim"))
        return None
    serial = f"{ip}:{port}"
    print(c(f"  [*] adb connect {serial}", "dim"))
    rc, out, err = run(["adb", "connect", serial], timeout=15)
    print("  " + (out.strip() or err.strip()))
    time.sleep(0.4)
    rc, out, _ = run(["adb", "devices"], timeout=10)
    for line in out.splitlines()[1:]:
        if line.startswith(serial):
            state = line.split()[-1] if len(line.split()) > 1 else "?"
            if state == "device":
                print(c(f"  [+] connected: {serial}", "g"))
                return serial
            if state == "unauthorized":
                print(c(f"  [!] {serial} -> unauthorized", "y"))
                print(c("      look at the target phone's screen — accept the RSA prompt", "dim"))
                return None
            if state == "offline":
                print(c(f"  [!] {serial} -> offline", "y"))
                return None
    print(c(f"  [!] could not connect to {serial}", "y"))
    return None


SESSION_HELP = """\
  session commands:
    screen                     — capture screenshot to ./shots/
    tap X Y                    — tap at coordinate
    swipe X1 Y1 X2 Y2 [ms]     — swipe gesture
    text <string>              — type text (spaces become %s)
    key <KEYCODE|name>         — keyevent (home/back/recents/power/unlock)
    shell <cmd>                — run raw shell command on the device
    apps                       — list installed packages
    start <pkg>                — launch package
    stop <pkg>                 — force-stop package
    info                       — device model / android version / battery
    pull <remote> [local]      — copy file from device
    push <local> <remote>      — copy file to device
    install <apk>              — install/update apk
    unlock                     — attempt wake + swipe-up unlock
    back | home | recents      — quick nav keys
    power                      — power button toggle
    help | exit
"""

KEY_NAMES = {
    "home": "KEYCODE_HOME", "back": "KEYCODE_BACK", "recents": "KEYCODE_APP_SWITCH",
    "power": "KEYCODE_POWER", "menu": "KEYCODE_MENU", "enter": "KEYCODE_ENTER",
    "volup": "KEYCODE_VOLUME_UP", "voldown": "KEYCODE_VOLUME_DOWN",
    "mute": "KEYCODE_VOLUME_MUTE", "play": "KEYCODE_MEDIA_PLAY_PAUSE",
    "next": "KEYCODE_MEDIA_NEXT", "prev": "KEYCODE_MEDIA_PREVIOUS",
    "camera": "KEYCODE_CAMERA", "search": "KEYCODE_SEARCH",
    "wake": "KEYCODE_WAKEUP", "sleep": "KEYCODE_SLEEP",
}


def adb_screencap(serial, out_dir="shots"):
    os.makedirs(out_dir, exist_ok=True)
    remote = "/sdcard/.ddosmat_shot.png"
    ts = time.strftime("%Y%m%d_%H%M%S")
    local = os.path.join(out_dir, f"{serial.replace(':','_')}_{ts}.png")
    rc, out, err = adb_cmd(serial, "shell", "screencap", "-p", remote, timeout=20)
    if rc != 0:
        print(c(f"  [!] screencap failed: {err.strip() or out.strip()}", "y"))
        return None
    rc, out, err = adb_cmd(serial, "pull
