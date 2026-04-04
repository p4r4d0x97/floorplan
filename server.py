#!/usr/bin/env python3
"""
NetMap Server
Usage: python server.py [devices.xml]

API:
  GET  /api/devices              all devices from XML
  GET  /api/status               current status store {mac: status}
  POST /api/ping                 body: {macs:[...]}  — ping those IPs, grouped by VLAN, 15s pause between groups
                                 returns {mac: "online"|"offline"|"no_info", ...}
  GET  /api/history              {mac: {status, last_seen, last_changed}} for switches only
  GET  /api/layout               saved map layout JSON
  POST /api/layout               save map layout JSON
  GET  /api/alerts               saved alert rules [{id,mac,name,condition,notified}]
  POST /api/alerts               save alert rules
  GET  /api/search?q=...         search by ip or name (max 20)
"""

import sys, os, json, time, threading, subprocess, platform, hashlib, secrets
import xml.etree.ElementTree as ET
import http.server, socketserver, urllib.parse
from pathlib import Path
from collections import defaultdict

# ── Config ───────────────────────────────────────────────────────────────────────────────
PORT         = 8000
VLAN_PAUSE   = 15
LAYOUT_FILE  = Path(__file__).parent / "layout.json"
HISTORY_FILE = Path(__file__).parent / "history.json"
ALERTS_FILE  = Path(__file__).parent / "alerts.json"
KNOWN_FILE   = Path(__file__).parent / "known_macs.json"
AUTH_FILE    = Path(__file__).parent / "auth.json"

DHCP_VLANS   = {"1088", "1048"}

# ── Stores ───────────────────────────────────────────────────────────────────────────────
devices_by_mac: dict[str, dict] = {}
status_store:   dict[str, str]  = {}
history_store:  dict[str, dict] = {}
known_macs:     set             = set()
active_tokens:  set             = set()
xml_path = None   # set at startup, used by /api/reload
store_lock = threading.Lock()
ping_lock  = threading.Lock()

# ── Device type ─────────────────────────────────────────────────────────────────
def guess_type(name: str) -> str:
    n = (name or "").lower()
    if any(x in n for x in ["sw","switch"]):        return "switch"
    if any(x in n for x in ["rt","router","gw"]):   return "router"
    if any(x in n for x in ["ap","wifi","wlan"]):   return "access_point"
    if any(x in n for x in ["srv","server","nas"]): return "server"
    if any(x in n for x in ["cam","camera","nvr"]): return "camera"
    if any(x in n for x in ["prn","print"]):        return "printer"
    if any(x in n for x in ["pc","desktop","laptop","ws"]): return "pc"
    return "unknown"

# ── XML parser ──────────────────────────────────────────────────────────────────
def load_xml(path: str) -> dict[str, dict]:
    try:
        tree = ET.parse(path)
    except ET.ParseError as e:
        raise ValueError(f"XML parse error in '{path}': {e}") from e
    except FileNotFoundError:
        raise ValueError(f"XML file not found: '{path}'")
    except Exception as e:
        raise ValueError(f"Failed to read XML: {e}") from e

    root = tree.getroot()
    # Core fields we always handle explicitly
    CORE = {"mac","ip","name","switch","port","vlan"}
    out = {}
    for dev in root.findall("device"):
        g  = lambda t: (dev.findtext(t) or "").strip()
        # treat literal "None" from XML the same as empty
        gn = lambda t: "" if g(t).lower() in ("none","null","-") else g(t)
        mac = gn("mac")
        if not mac: continue
        name = gn("name")
        record = {
            "mac":    mac,
            "ip":     gn("ip"),
            "name":   name,
            "switch": gn("switch"),
            "port":   gn("port"),
            "vlan":   gn("vlan"),
            "type":   gn("type") or guess_type(name),
        }
        # Capture ALL extra fields from XML automatically
        for child in dev:
            if child.tag not in CORE and child.tag != "type" and child.text:
                val = child.text.strip()
                if val.lower() not in ("none","null","-"):
                    record[child.tag] = val
        out[mac] = record
    return out

def make_demo() -> dict[str, dict]:
    rows = [
        ("00:1A:2B:3C:4D:01","192.168.1.2","PC-Alice","192.168.8.11","1","10"),
        ("00:1A:2B:3C:4D:02","192.168.1.3","PC-Bob","192.168.8.11","2","10"),
        ("00:1A:2B:3C:4D:03","192.168.1.4","PC-Carol","192.168.8.11","3","20"),
        ("00:1A:2B:3C:4D:04","192.168.1.5","AP-H1-01","192.168.8.11","24","99"),
        ("00:1A:2B:3C:4D:10","192.168.1.10","SW-H1-A-1","192.168.8.11","48","1"),
        ("00:1A:2B:3C:4D:11","192.168.1.11","SW-H1-A-2","192.168.8.11","47","1"),
        ("00:1A:2B:3C:4D:12","192.168.1.12","SW-H1-A-3","192.168.8.11","46","1"),
        ("00:2B:3C:4D:5E:01","192.168.2.2","PC-Dave","192.168.8.21","1","10"),
        ("00:2B:3C:4D:5E:02","192.168.2.3","CAM-H2-01","192.168.8.21","10","30"),
        ("00:2B:3C:4D:5E:10","192.168.2.10","SW-H2-A-1","192.168.8.21","48","1"),
        ("00:2B:3C:4D:5E:11","192.168.2.11","SW-H2-A-2","192.168.8.21","47","1"),
        ("00:3C:4D:5E:6F:01","192.168.3.2","Printer-WH","192.168.8.31","5","20"),
        ("00:3C:4D:5E:6F:02","192.168.3.3","CAM-WH-01","192.168.8.31","6","30"),
        ("00:3C:4D:5E:6F:10","192.168.3.10","SW-WH-A-1","192.168.8.31","48","1"),
        ("00:3C:4D:5E:6F:11","192.168.3.11","SW-WH-A-2","192.168.8.31","47","1"),
        ("00:3C:4D:5E:6F:20","192.168.3.20","SW-WH-B-1","192.168.8.32","48","1"),
        ("00:4D:5E:6F:70:01","192.168.4.2","SRV-AD-01","192.168.8.41","1","5"),
        ("00:4D:5E:6F:70:02","192.168.4.3","SRV-AD-02","192.168.8.41","2","5"),
        ("00:4D:5E:6F:70:03","192.168.4.4","PC-Admin","192.168.8.41","3","10"),
        ("00:4D:5E:6F:70:10","192.168.4.10","SW-AD-A-1","192.168.8.41","48","1"),
        ("00:4D:5E:6F:70:11","192.168.4.11","SW-AD-A-2","192.168.8.41","47","1"),
        ("00:4D:5E:6F:70:12","192.168.4.12","AP-AD-01","192.168.8.41","20","99"),
    ]
    out = {}
    for mac,ip,name,sw,port,vlan in rows:
        out[mac] = {"mac":mac,"ip":ip,"name":name,"switch":sw,
                    "port":port,"vlan":vlan,"type":guess_type(name)}
    return out

# ── Ping ────────────────────────────────────────────────────────────────────────
def ping_once(ip: str) -> bool:
    """Single ICMP ping. Works on Windows and Linux/macOS."""
    system = platform.system().lower()
    try:
        if system == "windows":
            cmd = ["ping", "-n", "1", "-w", "2000", ip]
        else:
            cmd = ["ping", "-c", "1", "-W", "2", ip]

        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False
    except FileNotFoundError:
        print("[ping] ERROR: 'ping' command not found")
        return False
    except Exception as e:
        print(f"[ping] {ip} → exception: {e}")
        return False

def update_history(mac: str, new_status: str):
    """Update history for switches only. Thread-safe (called inside store_lock)."""
    dev = devices_by_mac.get(mac)
    if not dev or dev.get("type") != "switch":
        return
    now = time.time()
    prev = history_store.get(mac, {})
    prev_status = prev.get("status", "no_info")
    entry = {
        "status":       new_status,
        "last_changed": prev.get("last_changed", now) if prev_status == new_status else now,
        "last_seen":    now if new_status == "online" else prev.get("last_seen", None),
        "prev_status":  prev_status,
    }
    history_store[mac] = entry

def do_ping(macs: list[str]) -> dict[str, str]:
    """
    Ping a list of MACs. Groups by VLAN, pauses VLAN_PAUSE seconds between groups.
    Updates status_store and history_store. Returns {mac: status}.
    """
    if not ping_lock.acquire(blocking=False):
        # another ping is in progress — return current store snapshot
        with store_lock:
            return {m: status_store.get(m, "no_info") for m in macs}
    try:
        devs = [devices_by_mac[m] for m in macs if m in devices_by_mac]
        by_vlan = defaultdict(list)
        for d in devs:
            by_vlan[d.get("vlan", "0")].append(d)

        results = {}
        for i, (vlan, group) in enumerate(sorted(by_vlan.items())):
            batch = {}
            is_dhcp = vlan in DHCP_VLANS

            def probe(d, res=batch, dhcp=is_dhcp):
                mac  = d["mac"]
                ip   = d.get("ip", "")
                name = d.get("name", "")

                if dhcp:
                    # DHCP VLAN — ping by hostname, fall back to IP if name empty
                    target = name if name else ip
                    if not target:
                        res[mac] = "no_info"; return
                    ok = ping_once(target)
                    print(f"[ping] DHCP VLAN {vlan}  {name} ({ip}) → {'online' if ok else 'offline'}")
                    res[mac] = "online" if ok else "offline"
                else:
                    # Static VLAN — ping by IP
                    if not ip:
                        res[mac] = "no_info"; return
                    res[mac] = "online" if ping_once(ip) else "offline"

            threads = []
            for d in group:
                t = threading.Thread(target=probe, args=(d,), daemon=True)
                threads.append(t); t.start()
            for t in threads:
                t.join(timeout=6)
            # mark anything that didn't respond at all
            for d in group:
                if d["mac"] not in batch:
                    batch[d["mac"]] = "no_info"
            results.update(batch)
            online = sum(1 for s in batch.values() if s == "online")
            mode   = "hostname" if is_dhcp else "ip"
            print(f"[ping] VLAN {vlan:>6} ({mode:>8})  {len(group):>3} devs  online={online}")
            if i < len(by_vlan) - 1:
                time.sleep(VLAN_PAUSE)

        with store_lock:
            status_store.update(results)
            for mac, st in results.items():
                update_history(mac, st)
        save_history()
        return results
    finally:
        ping_lock.release()

# ── Persistence ─────────────────────────────────────────────────────────────────
def load_layout() -> dict:
    if LAYOUT_FILE.exists():
        try: return json.loads(LAYOUT_FILE.read_text())
        except: pass
    return {"rooms":[], "devices":{}, "racks":[], "annotations":[], "drawings":[]}

def save_layout(data: dict):
    LAYOUT_FILE.write_text(json.dumps(data, indent=2))

def load_history() -> dict:
    if HISTORY_FILE.exists():
        try: return json.loads(HISTORY_FILE.read_text())
        except: pass
    return {}

def save_history():
    HISTORY_FILE.write_text(json.dumps(history_store, indent=2))

def load_alerts() -> list:
    if ALERTS_FILE.exists():
        try: return json.loads(ALERTS_FILE.read_text())
        except: pass
    return []

def save_alerts(data: list):
    ALERTS_FILE.write_text(json.dumps(data, indent=2))

# ── Auth ─────────────────────────────────────────────────────────────────────
def hash_pw(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def load_auth() -> dict:
    """Returns {hash: str} or {} if no password set yet."""
    if AUTH_FILE.exists():
        try: return json.loads(AUTH_FILE.read_text())
        except: pass
    return {}

def save_auth(pw_hash: str):
    AUTH_FILE.write_text(json.dumps({"hash": pw_hash}))

def auth_status() -> str:
    """'none' if no password set, 'set' if password exists."""
    return "set" if load_auth().get("hash") else "none"

def verify_token(headers) -> bool:
    token = headers.get("X-Auth-Token","")
    return token in active_tokens


    if KNOWN_FILE.exists():
        try: return set(json.loads(KNOWN_FILE.read_text()))
        except: pass
    return set()

def load_known_macs() -> set:
    if KNOWN_FILE.exists():
        try: return set(json.loads(KNOWN_FILE.read_text()))
        except: pass
    return set()

def save_known_macs():
    KNOWN_FILE.write_text(json.dumps(list(known_macs)))

def merge_devices(new_devs: dict):
    """
    Merge newly parsed XML devices into devices_by_mac.
    - New MAC → add it
    - Existing MAC with any changed field → update ALL fields (including Extra/tags)
    - MAC in known_macs but not in new_devs → keep, set removed=True
    - MAC in new_devs that was removed → clear removed flag
    """
    global known_macs
    changed = []

    for mac, dev in new_devs.items():
        if mac in devices_by_mac:
            existing = devices_by_mac[mac]
            # Compare ALL fields from new device — not just a hardcoded subset
            # This catches Extra fields, tags, and any custom XML fields
            core_skip = {"removed"}
            updates = {
                k: v for k, v in dev.items()
                if k not in core_skip and existing.get(k) != v
            }
            # Also detect fields that were removed from XML
            removed_keys = [
                k for k in existing
                if k not in core_skip and k not in dev
            ]
            if updates or removed_keys:
                for k in removed_keys:
                    existing.pop(k, None)
                existing.update(updates)
                existing.pop("removed", None)
                all_changes = list(updates.keys()) + [f"-{k}" for k in removed_keys]
                changed.append(f"updated {existing.get('name',mac)}: {all_changes}")
            elif existing.get("removed"):
                existing.pop("removed", None)
                changed.append(f"restored {existing.get('name',mac)}")
        else:
            devices_by_mac[mac] = {**dev, "removed": False}
            status_store[mac] = "no_info"
            changed.append(f"new device {dev.get('name',mac)} ({dev.get('ip','')})")

    # mark anything previously known but absent from new XML
    for mac in known_macs:
        if mac not in new_devs and mac in devices_by_mac:
            if not devices_by_mac[mac].get("removed"):
                devices_by_mac[mac]["removed"] = True
                changed.append(f"removed from XML: {devices_by_mac[mac].get('name',mac)}")

    known_macs.update(new_devs.keys())
    save_known_macs()

    if changed:
        print(f"[xml] {len(changed)} change(s):")
        for c in changed: print(f"      • {c}")
    else:
        print("[xml] no changes detected")

    return changed

# ── HTTP ─────────────────────────────────────────────────────────────────────────
class Handler(http.server.SimpleHTTPRequestHandler):

    def do_GET(self):
        p = urllib.parse.urlparse(self.path)
        path, qs = p.path, urllib.parse.parse_qs(p.query)

        if path == "/api/devices":
            # include removed flag so frontend can distinguish
            self._json(list(devices_by_mac.values()))

        elif path == "/api/reload":
            if xml_path:
                try:
                    new_devs = load_xml(xml_path)
                    changes  = merge_devices(new_devs)
                    self._json({"ok": True, "changes": changes,
                                "total": len(devices_by_mac)})
                except ValueError as e:
                    self._json({"ok": False, "msg": str(e)})
                except Exception as e:
                    self._json({"ok": False, "msg": f"Unexpected error: {e}"})
            else:
                self._json({"ok": False, "msg": "No XML file loaded — start server with: python server.py devices.xml"})

        elif path == "/api/ping-test":
            # Quick single-IP test: /api/ping-test?ip=192.168.1.1
            ip = qs.get("ip",[""])[0].strip()
            if not ip:
                self._json({"error": "provide ?ip=..."})
                return
            import time as _t
            t0=_t.time()
            ok=ping_once(ip)
            ms=round((_t.time()-t0)*1000)
            self._json({"ip":ip,"reachable":ok,"ms":ms,
                        "platform":platform.system()})

        elif path == "/api/debug":
            with store_lock:
                sample_devs  = list(devices_by_mac.items())[:15]
                sample_status = list(status_store.items())[:15]
            self._json({
                "total_devices":     len(devices_by_mac),
                "total_status_keys": len(status_store),
                "sample_device_macs":  [m for m,_ in sample_devs],
                "sample_device_ips":   {m:d.get("ip","?") for m,d in sample_devs},
                "sample_status":       {m:s for m,s in sample_status},
                "platform": platform.system(),
            })

        elif path == "/api/auth/status":
            # Returns whether a password has been set
            self._json({"status": auth_status()})

        elif path == "/api/status":
            with store_lock:
                self._json(dict(status_store))

        elif path == "/api/history":
            # return history enriched with device name/ip for switches
            out = {}
            with store_lock:
                for mac, h in history_store.items():
                    d = devices_by_mac.get(mac, {})
                    out[mac] = {**h, "name": d.get("name",""), "ip": d.get("ip","")}
            self._json(out)

        elif path == "/api/alerts":
            self._json(load_alerts())

        elif path == "/api/layout":
            self._json(load_layout())

        elif path == "/api/search":
            q = qs.get("q",[""])[0].lower().strip()
            res = [d for d in devices_by_mac.values()
                   if q in d.get("ip","").lower() or q in d.get("name","").lower()] if q else []
            self._json(res[:20])

        else:
            super().do_GET()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length)

        if self.path == "/api/ping":
            try:
                data  = json.loads(body)
                macs  = data.get("macs", [])
                if not macs:
                    self._json({})
                    return
                # run in a thread so HTTP response returns immediately with a job token
                # but for simplicity we block (client shows spinner anyway)
                result = do_ping(macs)
                self._json(result)
            except Exception as e:
                self._error(str(e))

        elif self.path == "/api/layout":
            try:
                save_layout(json.loads(body))
                self._json({"ok": True})
            except Exception as e:
                self._error(str(e))

        elif self.path == "/api/alerts":
            try:
                save_alerts(json.loads(body))
                self._json({"ok": True})
            except Exception as e:
                self._error(str(e))

        elif self.path == "/api/auth/login":
            # POST {password} → returns {token} or 401
            try:
                data = json.loads(body)
                pw   = data.get("password","")
                auth = load_auth()
                if not auth.get("hash"):
                    # No password set yet — first login sets the password
                    save_auth(hash_pw(pw))
                    token = secrets.token_hex(32)
                    active_tokens.add(token)
                    self._json({"ok": True, "token": token, "first_setup": True})
                elif auth["hash"] == hash_pw(pw):
                    token = secrets.token_hex(32)
                    active_tokens.add(token)
                    self._json({"ok": True, "token": token})
                else:
                    self.send_response(401)
                    self._cors(); self.end_headers()
                    self.wfile.write(json.dumps({"ok": False, "error": "Wrong password"}).encode())
            except Exception as e:
                self._error(str(e))

        elif self.path == "/api/auth/logout":
            try:
                data  = json.loads(body)
                token = data.get("token","")
                active_tokens.discard(token)
                self._json({"ok": True})
            except Exception as e:
                self._error(str(e))

        elif self.path == "/api/auth/change-password":
            # POST {token, old_password, new_password}
            try:
                data   = json.loads(body)
                token  = data.get("token","")
                old_pw = data.get("old_password","")
                new_pw = data.get("new_password","")
                auth   = load_auth()
                if token not in active_tokens:
                    self.send_response(401); self._cors(); self.end_headers()
                    self.wfile.write(json.dumps({"ok":False,"error":"Not authenticated"}).encode())
                    return
                if auth.get("hash") and auth["hash"] != hash_pw(old_pw):
                    self.send_response(401); self._cors(); self.end_headers()
                    self.wfile.write(json.dumps({"ok":False,"error":"Wrong current password"}).encode())
                    return
                save_auth(hash_pw(new_pw))
                self._json({"ok": True})
            except Exception as e:
                self._error(str(e))

        else:
            self.send_response(404); self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200); self._cors(); self.end_headers()

    def _json(self, obj):
        data = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",len(data))
        self._cors(); self.end_headers(); self.wfile.write(data)

    def _error(self, msg):
        data = json.dumps({"error":msg}).encode()
        self.send_response(400)
        self.send_header("Content-Type","application/json")
        self._cors(); self.end_headers(); self.wfile.write(data)

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin","*")
        self.send_header("Access-Control-Allow-Methods","GET,POST,OPTIONS")
        self.send_header("Access-Control-Allow-Headers","Content-Type")

    def log_message(self, fmt, *a):
        msg = fmt % a
        if "/api/status" not in msg and "/api/history" not in msg:
            print(f"  {msg}")

# ── Main ────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    #global xml_path
    xml_path = sys.argv[1] if len(sys.argv) > 1 else None

    # load previously known MACs first so merge can detect removals
    known_macs.update(load_known_macs())

    if xml_path:
        print(f"📂  Loading {xml_path} …")
        try:
            new_devs = load_xml(xml_path)
            merge_devices(new_devs)
        except ValueError as e:
            print(f"\n❌  {e}")
            print("    Fix the XML file and click ⟳ XML in the browser to reload.")
            print("    Starting with empty device list.\n")
    else:
        print("⚠️   No XML file — using demo data")
        print("    Usage: python server.py devices.xml")
        demo = make_demo()
        merge_devices(demo)

    with store_lock:
        for mac in devices_by_mac:
            if mac not in status_store:
                status_store[mac] = "no_info"

    history_store.update(load_history())
    print(f"✅  {len(devices_by_mac)} devices ({sum(1 for d in devices_by_mac.values() if d.get('removed'))} removed)")

    www = Path(__file__).parent / "www"
    www.mkdir(exist_ok=True)
    os.chdir(www)

    print(f"\n  ┌──────────────────────────────────┐")
    print(f"  │  NetMap  →  http://localhost:{PORT}  │")
    print(f"  └──────────────────────────────────┘\n")

    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", PORT), Handler) as srv:
        srv.serve_forever()