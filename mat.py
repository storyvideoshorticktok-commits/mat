#!/usr/bin/env python3
# ddosmat.py - wifi recon + network toolkit + android remote via adb
import asyncio, concurrent.futures, json, os, shlex, shutil, socket, subprocess, sys, time

VERSION = "1.1"

BANNER = r"""
  ___  ___  ___  ___  __  __    _  _____
 |   \|   \/ _ \/ __| \ \/ /   /_\|_   _|
 | |) | |) | (_) \__ \  >  <   / _ \ | |
 |___/|___/ \___/|___/ /_/\_\ /_/ \_\|_|
  wifi recon + network toolkit + android remote
  v{}   /help for commands
""".format(VERSION)

TOP_PORTS = [21,22,23,25,53,80,81,88,110,111,135,139,143,161,389,443,445,465,514,515,548,554,587,631,636,873,993,995,1080,1433,1521,1723,1883,2049,2082,2083,2086,2087,2181,2222,2375,3000,3128,3306,3389,3690,4000,4443,5000,5060,5222,5357,5432,5555,5601,5672,5900,5984,6379,6667,7001,7070,8000,8008,8080,8081,8086,8088,8443,8500,8834,8888,9000,9042,9090,9200,9300,9443,10000,11211,15672,25565,27017,27018,50000,50070]

PORT_NAMES = {21:"ftp",22:"ssh",23:"telnet",25:"smtp",53:"dns",80:"http",110:"pop3",111:"rpcbind",135:"msrpc",139:"netbios",143:"imap",161:"snmp",389:"ldap",443:"https",445:"smb",465:"smtps",514:"syslog",587:"smtp-sub",631:"ipp",993:"imaps",995:"pop3s",1080:"socks",1433:"mssql",1521:"oracle",1723:"pptp",1883:"mqtt",2049:"nfs",3306:"mysql",3389:"rdp",5432:"postgres",5555:"adb-tcp",5900:"vnc",5984:"couchdb",6379:"redis",6667:"irc",8080:"http-alt",8443:"https-alt",8888:"http-alt",9200:"elastic",11211:"memcached",25565:"minecraft",27017:"mongodb"}

def has(x): return shutil.which(x) is not None

def run(cmd, timeout=10):
    try:
        p = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or ""), (p.stderr or "")
    except subprocess.TimeoutExpired: return -1, "", "timeout"
    except FileNotFoundError as e: return -2, "", str(e)
    except Exception as e: return -3, "", str(e)

def c(t, k):
    m = {"r":"31","g":"32","y":"33","b":"34","m":"35","c":"36","w":"37","bold":"1","dim":"2"}
    return f"\033[{m.get(k,'0')}m{t}\033[0m"

def table(headers, rows):
    if not rows:
        print(c("  (no results)", "dim")); return
    w = [len(h) for h in headers]
    for r in rows:
        for i, x in enumerate(r): w[i] = max(w[i], len(str(x)))
    f = "  ".join("{{:<{}}}".format(x) for x in w)
    print("  " + c(f.format(*headers), "bold"))
    print("  " + c("  ".join("-"*x for x in w), "dim"))
    for r in rows: print("  " + f.format(*[str(x) for x in r]))

def pbin(n):
    pre = os.environ.get("PREFIX", "/data/data/com.termux/files/usr")
    p = os.path.join(pre, "bin", n)
    return p if os.path.exists(p) else n

def local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(0.3)
        s.connect(("1.1.1.1", 80)); ip = s.getsockname()[0]; s.close(); return ip
    except Exception:
        pass
    try: return socket.gethostbyname(socket.gethostname())
    except Exception: return None

def gateway():
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                p = line.strip().split()
                if len(p) >= 3 and p[1] == "00000000":
                    h = p[2]
                    return ".".join(str(int(h[i:i+2],16)) for i in (6,4,2,0))
    except Exception: pass
    rc, o, _ = run(["ip","route"])
    if rc == 0:
        for l in o.splitlines():
            if l.startswith("default") and "via" in l:
                p = l.split(); return p[p.index("via")+1]
    return None

def subnet(ip):
    if not ip or ip.count(".") != 3: return None
    return ".".join(ip.split(".")[:3])

def arp():
    d = {}
    try:
        with open("/proc/net/arp") as f:
            for l in f.readlines()[1:]:
                p = l.split()
                if len(p) < 6: continue
                ip, _, fl, mac, _, dev = p[:6]
                if mac == "00:00:00:00:00:00" or fl == "0x0": continue
                d[ip] = {"mac": mac, "dev": dev}
    except Exception: pass
    return d

def freq_ch(f):
    if not f: return ""
    if f == 2484: return "14"
    if 2412 <= f <= 2472: return str((f-2407)//5)
    if 5000 <= f <= 5900: return str((f-5000)//5)
    return ""

def sec(cap):
    if not cap: return "open"
    cap = cap.upper()
    for k in ("WPA3","WPA2","WPA","WEP"):
        if k in cap: return k
    return "open"

def wifi_scan():
    tool = pbin("termux-wifi-scaninfo")
    if not has(tool) and not os.path.exists(tool):
        print(c("  [!] termux-api not installed", "y"))
        print(c("      pkg install termux-api  + install Termux:API app", "dim"))
        return []
    rc, out, err = run([tool], timeout=20)
    if rc != 0 or not out.strip():
        print(c(f"  [!] wifi scan failed: {err.strip() or 'no output'}", "y")); return []
    try: data = json.loads(out)
    except json.JSONDecodeError:
        print(c("  [!] bad json", "y")); return []
    rows = []
    for ap in data:
        ssid = ap.get("ssid","") or "<hidden>"
        rows.append((ssid, ap.get("bssid",""), f"{ap.get('level', ap.get('rssi',0))}dBm",
                     "2.4" if ap.get("frequency",0) and ap.get("frequency",0) < 3000 else ("5" if ap.get("frequency",0) else "?"),
                     freq_ch(ap.get("frequency",0)), sec(ap.get("capabilities",""))))
    rows.sort(key=lambda r: int(r[2].rstrip("dBm") or -999), reverse=True)
    print(c(f"\n  [+] {len(rows)} networks\n", "g"))
    table(["SSID","BSSID","Signal","Band","Ch","Sec"], rows)
    print(); return rows

async def _probe(ip, port, t=0.35):
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=t)
        w.close()
        try: await w.wait_closed()
        except Exception: pass
        return ip
    except Exception: return None

async def _sweep(ips, ports, t=0.35):
    sem = asyncio.Semaphore(512); found = set()
    async def one(ip, port):
        async with sem:
            r = await _probe(ip, port, t)
            if r: found.add(r)
    await asyncio.gather(*(one(i,p) for i in ips for p in ports))
    return found

def ping_sweep(ips, t=1):
    def p(ip):
        rc, _, _ = run(["ping","-c","1","-W",str(t),ip], timeout=t+1)
        return ip if rc == 0 else None
    r = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as ex:
        for x in ex.map(p, ips):
            if x: r.append(x)
    return r

def clients():
    s = subnet(local_ip())
    if not s: print(c("  [!] no subnet", "y")); return []
    ips = [f"{s}.{i}" for i in range(1,255)]
    print(c(f"  [*] probing {s}.0/24 ...", "dim"))
    found = set()
    if has("ping"): found |= set(ping_sweep(ips))
    try:
        loop = asyncio.new_event_loop(); asyncio.set_event_loop(loop)
        found |= loop.run_until_complete(_sweep(ips, [80,443,22,5555], 0.3))
        loop.close()
    except Exception: pass
    a = arp(); found |= set(a.keys())
    rows = [(ip, a.get(ip,{}).get("mac","-"), vendor(a.get(ip,{}).get("mac",""))) for ip in sorted(found, key=lambda x: tuple(int(y) for y in x.split(".")))]
    rows = [(ip, mac or "-", v or "-") for ip, mac, v in rows]
    print(c(f"\n  [+] {len(rows)} live hosts\n", "g"))
    table(["IP","MAC","Vendor"], rows)
    print(); return rows

async def _scan_one(ip, port, t=0.8):
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=t)
        banner = ""
        try:
            d = await asyncio.wait_for(r.read(128), timeout=0.5)
            if d: banner = d.decode("utf-8","replace").strip().splitlines()[0][:48]
        except Exception: pass
        w.close()
        try: await w.wait_closed()
        except Exception: pass
        return (port, "open", banner)
    except Exception: return None

def port_scan(ip, ports):
    t0 = time.time()
    print(c(f"  [*] scanning {ip} — {len(ports)} ports", "dim"))
    async def go():
        sem = asyncio.Semaphore(512); res = []
        async def one(p):
            async with sem:
                r = await _scan_one(ip, p)
                if r: res.append(r)
        await asyncio.gather(*(one(p) for p in ports))
        return sorted(res)
    try:
        loop = asyncio.new_event_loop(); asyncio.set_event_loop(loop)
        results = loop.run_until_complete(go()); loop.close()
    except Exception as e:
        print(c(f"  [!] {e}", "y")); return []
    dt = time.time()-t0
    print(c(f"\n  [+] {len(results)} open in {dt:.2f}s\n", "g"))
    table(["Port","State","Service","Banner"], [(p,s,PORT_NAMES.get(p,""),b) for p,s,b in results])
    print(); return results

def ping_host(ip, n=4):
    rc, o, e = run(["ping","-c",str(n),ip], timeout=n*2+2)
    if rc == -2: print(c("  [!] pkg install iputils", "y")); return
    print(o)

def dns(host):
    print(c(f"\n  [*] resolving {host}\n", "dim"))
    try: infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e: print(c(f"  [!] {e}", "y")); return
    rows = []; seen = set()
    for fam, _, _, _, sa in infos:
        ip = sa[0]
        if ip in seen: continue
        seen.add(ip)
        try: rev = socket.gethostbyaddr(ip)[0]
        except Exception: rev = "-"
        rows.append(("IPv4" if fam == socket.AF_INET else "IPv6", ip, rev))
    table(["Family","Address","PTR"], rows); print()

def trace(host, maxh=20):
    print(c(f"\n  [*] traceroute {host}\n", "dim"))
    if not has("ping"): print(c("  [!] pkg install iputils", "y")); return
    for ttl in range(1, maxh+1):
        _, o, _ = run(["ping","-c","1","-W","1","-t",str(ttl),host], timeout=3)
        line = ""
        for l in o.splitlines():
            if "bytes from" in l or "from " in l or "From " in l: line = l.strip(); break
        print(f"  {ttl:>2}  {line}" if line else f"  {ttl:>2}  * * *")
        if line and "Time to live exceeded" not in line: break

_OUI = {"00:1A:2B":"Apple","00:1B:63":"Apple","3C:07:54":"Apple","40:6C:8F":"Apple","68:AB:1E":"Apple","7C:D1:C3":"Apple","8C:85:90":"Apple","9C:04:EB":"Apple","A4:83:E7":"Apple","B8:E8:56":"Apple","C8:2A:14":"Apple","D0:03:DF":"Apple","F0:18:98":"Apple","3C:5A:B4":"Google","3C:28:6D":"Google","54:60:09":"Google","94:EB:2C":"Google","A4:77:33":"Google","F4:F5:D8":"Google","F4:F5:E8":"Google","00:1D:D8":"Microsoft","28:18:78":"Microsoft","7C:1E:52":"Microsoft","60:45:BD":"Microsoft","C8:3F:26":"Microsoft","00:1B:44":"Samsung","2C:44:01":"Samsung","50:32:75":"Samsung","78:1F:DB":"Samsung","8C:71:F8":"Samsung","BC:14:85":"Samsung","CC:07:AB":"Samsung","E8:50:8B":"Samsung","00:1E:58":"D-Link","1C:7E:E5":"D-Link","84:C9:B2":"D-Link","00:24:B2":"Netgear","20:4E:7F":"Netgear","9C:3D:CF":"Netgear","A0:40:A0":"Netgear","C0:3F:0E":"Netgear","F8:1A:67":"TP-Link","50:C7:BF":"TP-Link","A4:2B:B0":"TP-Link","C4:6E:1F":"TP-Link","EC:08:6B":"TP-Link","00:0C:29":"VMware","00:50:56":"VMware","08:00:27":"VirtualBox","B8:27:EB":"Raspberry Pi","DC:A6:32":"Raspberry Pi","E4:5F:01":"Raspberry Pi","00:17:88":"Philips Hue","00:55:DA":"Ring","34:3E:A4":"Ring","44:65:0D":"Amazon","68:54:FD":"Amazon","74:C2:46":"Amazon","A0:02:DC":"Amazon","F0:27:2D":"Amazon","FC:65:DE":"Amazon","0C:47:C9":"Espressif","24:0A:C4":"Espressif","30:AE:A4":"Espressif","3C:71:BF":"Espressif","5C:CF:7F":"Espressif","84:0D:8E":"Espressif","A4:CF:12":"Espressif","B4:E6:2D":"Espressif","CC:50:E3":"Espressif","DC:4F:22":"Espressif","EC:FA:BC":"Espressif","F4:CF:A2":"Espressif"}

def vendor(mac):
    if not mac or mac == "-": return None
    return _OUI.get(mac.upper()[:8])

def adb_ok(): return has("adb")

def adb(serial, *args, timeout=15):
    return run(["adb","-s",serial] + list(args), timeout=timeout)

async def _scan_adb(ips):
    sem = asyncio.Semaphore(512); hits = []
    async def one(ip, port):
        async with sem:
            r = await _probe(ip, port, 0.6)
            if r: hits.append((ip, port))
    await asyncio.gather(*(one(i,p) for i in ips for p in (5555,5556,5557)))
    return hits

def adb_scan():
    s = subnet(local_ip())
    if not s: print(c("  [!] no subnet", "y")); return []
    ips = [f"{s}.{i}" for i in range(1,255)]
    print(c(f"  [*] hunting adb on {s}.0/24 ...", "dim"))
    try:
        loop = asyncio.new_event_loop(); asyncio.set_event_loop(loop)
        hits = loop.run_until_complete(_scan_adb(ips)); loop.close()
    except Exception as e: print(c(f"  [!] {e}", "y")); return []
    if not hits:
        print(c("\n  [+] no adb endpoints found\n", "y"))
        print(c("  notes:", "dim"))
        print(c("    - target needs adb tcp enabled (wireless debugging)", "dim"))
        print(c("    - android 11+ uses a randomized port + pairing", "dim"))
        print(); return []
    print(c(f"\n  [+] {len(hits)} adb endpoint(s)\n", "g"))
    table(["IP","Port","Service"], [(i,p,"adb-tcp") for i,p in hits])
    print(); return hits

def adb_connect(ip, port=5555):
    if not adb_ok():
        print(c("  [!] adb not installed — pkg install android-tools", "y")); return None
    s = f"{ip}:{port}"
    print(c(f"  [*] adb connect {s}", "dim"))
    _, o, e = run(["adb","connect",s], timeout=15)
    print("  " + (o.strip() or e.strip()))
    time.sleep(0.4)
    _, o, _ = run(["adb","devices"], timeout=10)
    for l in o.splitlines()[1:]:
        if l.startswith(s):
            state = l.split()[-1] if len(l.split()) > 1 else "?"
            if state == "device": print(c(f"  [+] connected: {s}", "g")); return s
            if state == "unauthorized":
                print(c("  [!] unauthorized — accept RSA prompt on target screen", "y")); return None
            if state == "offline": print(c("  [!] offline", "y")); return None
    print(c(f"  [!] failed to connect {s}", "y")); return None

KEYS = {"home":"KEYCODE_HOME","back":"KEYCODE_BACK","recents":"KEYCODE_APP_SWITCH","power":"KEYCODE_POWER","menu":"KEYCODE_MENU","enter":"KEYCODE_ENTER","volup":"KEYCODE_VOLUME_UP","voldown":"KEYCODE_VOLUME_DOWN","mute":"KEYCODE_VOLUME_MUTE","play":"KEYCODE_MEDIA_PLAY_PAUSE","next":"KEYCODE_MEDIA_NEXT","prev":"KEYCODE_MEDIA_PREVIOUS","camera":"KEYCODE_CAMERA","search":"KEYCODE_SEARCH","wake":"KEYCODE_WAKEUP","sleep":"KEYCODE_SLEEP"}

SHELP = """\
  screen                      screenshot to ./shots/
  tap X Y                     tap
  swipe X1 Y1 X2 Y2 [ms]      swipe
  text <string>               type (spaces -> %s)
  key <name|KEYCODE>          keyevent
  shell <cmd>                 raw shell
  apps                        list packages
  start <pkg>                 launch package
  stop <pkg>                  force-stop
  info                        device info
  pull <remote> [local]       pull file
  push <local> <remote>       push file
  install <apk>               install apk
  unlock                      wake + swipe up
  back | home | recents | power
  help | exit
"""

def adb_shot(s):
    os.makedirs("shots", exist_ok=True)
    rem = "/sdcard/.ddosmat_shot.png"
    ts = time.strftime("%Y%m%d_%H%M%S")
    loc = f"shots/{s.replace(':','_')}_{ts}.png"
    rc, o, e = adb(s, "shell", "screencap", "-p", rem, timeout=20)
    if rc != 0: print(c(f"  [!] screencap failed: {e.strip() or o.strip()}", "y")); return
    rc, o, e = adb(s, "pull", rem, loc, timeout=30)
    adb(s, "shell", "rm", "-f", rem)
    if rc != 0: print(c(f"  [!] pull failed: {e.strip() or o.strip()}", "y")); return
    print(c(f"  [+] saved {loc}", "g"))

def adb_session(s):
    print(c(f"\n  [*] session: {s}", "g"))
    print(c("  'help' for commands, 'exit' to disconnect\n", "dim"))
    while True:
        try: line = input(c(f"  {s}> ", "c")).strip()
        except (EOFError, KeyboardInterrupt): print(); break
        if not line: continue
        if line in ("exit","quit","q"): break
        if line == "help": print(SHELP); continue
        p = line.split(None, 1); cmd = p[0]; rest = p[1] if len(p) > 1 else ""
        try:
            if cmd == "screen": adb_shot(s)
            elif cmd == "tap":
                xy = rest.split()
                if len(xy) != 2: print(c("  usage: tap X Y", "y")); continue
                adb(s, "shell", "input", "tap", xy[0], xy[1])
            elif cmd == "swipe":
                a = rest.split()
                if len(a) not in (4,5): print(c("  usage: swipe X1 Y1 X2 Y2 [ms]", "y")); continue
                adb(s, "shell", "input", "swipe", *a)
            elif cmd == "text":
                if not rest: print(c("  usage: text <s>", "y")); continue
                adb(s, "shell", "input", "text", rest.replace(" ","%s"))
            elif cmd == "key":
                if not rest: print(c("  usage: key <name>", "y")); continue
                k = KEYS.get(rest.lower(), rest.upper())
                if not k.startswith("KEYCODE_"): k = "KEYCODE_" + k
                adb(s, "shell", "input", "keyevent", k)
            elif cmd == "shell":
                if not rest: print(c("  usage: shell <cmd>", "y")); continue
                _, o, e = adb(s, "shell", *shlex.split(rest), timeout=30)
                if o: print(o.rstrip())
                if e: print(c(e.rstrip(), "y"))
            elif cmd == "apps":
                _, o, _ = adb(s, "shell", "pm", "list", "packages", timeout=20)
                for l in o.splitlines():
                    if l.startswith("package:"): print("   " + l.replace("package:",""))
            elif cmd == "start":
                if rest: adb(s, "shell", "monkey", "-p", rest, "-c", "android.intent.category.LAUNCHER", "1")
            elif cmd == "stop":
                if rest: adb(s, "shell", "am", "force-stop", rest)
            elif cmd == "info":
                _, o, _ = adb(s, "shell", "getprop")
                pr = {}
                for l in o.splitlines():
                    if "]" in l and "[" in l:
                        k = l.split("]:",1)[0].strip("[").strip()
                        v = l.split("]:",1)[1].strip().strip("[]")
                        pr[k] = v
                rows = [("model", pr.get("ro.product.model","?")), ("brand", pr.get("ro.product.brand","?")),
                        ("android", pr.get("ro.build.version.release","?")), ("sdk", pr.get("ro.build.version.sdk","?")),
                        ("abi", pr.get("ro.product.cpu.abi","?")), ("serial", pr.get("ro.serialno","?"))]
                _, o, _ = adb(s, "shell", "dumpsys", "battery", timeout=15)
                for l in o.splitlines():
                    l = l.strip()
                    if l.startswith("level:"): rows.append(("battery", l.split(":",1)[1].strip() + "%"))
                table(["Prop","Value"], rows)
            elif cmd == "pull":
                a = rest.split()
                if not a: print(c("  usage: pull <remote> [local]", "y")); continue
                _, o, e = adb(s, "pull", a[0], a[1] if len(a)>1 else ".", timeout=120)
                print((o or e).rstrip())
            elif cmd == "push":
                a = rest.split()
                if len(a) != 2: print(c("  usage: push <local> <remote>", "y")); continue
                _, o, e = adb(s, "push", a[0], a[1], timeout=120)
                print((o or e).rstrip())
            elif cmd == "install":
                if rest: _, o, e = adb(s, "install", "-r", rest, timeout=300); print((o or e).rstrip())
            elif cmd == "unlock":
                adb(s, "shell", "input", "keyevent", "KEYCODE_WAKEUP"); time.sleep(0.3)
                adb(s, "shell", "input", "swipe", "540", "1800", "540", "800", "300")
                print(c("  [+] sent wake + swipe", "g"))
            elif cmd == "back": adb(s, "shell", "input", "keyevent", "KEYCODE_BACK")
            elif cmd == "home": adb(s, "shell", "input", "keyevent", "KEYCODE_HOME")
            elif cmd == "recents": adb(s, "shell", "input", "keyevent", "KEYCODE_APP_SWITCH")
            elif cmd == "power": adb(s, "shell", "input", "keyevent", "KEYCODE_POWER")
            else: print(c(f"  unknown: {cmd}  (type 'help')", "y"))
        except KeyboardInterrupt: print(); continue
        except Exception as e: print(c(f"  [!] {e}", "y"))
    run(["adb","disconnect",s], timeout=10)
    print(c(f"  [*] disconnected {s}", "dim"))

def cmd_control(a):
    if 
