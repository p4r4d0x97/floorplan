from __future__ import annotations
import getpass
import re
import time
import socket
import os
import uuid
import requests
import urllib3
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from enum import Enum

import paramiko
from lxml import etree

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ─── Config ───────────────────────────────────────────────────────────────────

EXTREME_IPS   = ["192.168.8.10", "192.168.8.11", "192.168.8.12"]
FIREWALL_HOST = "192.168.93.160"
XML_FILE      = "inventory.xml"
MAX_WORKERS   = 8

RACK_MAPPING = {
    "192.168.8.10": "Rack02",
    "192.168.8.11": "Rack03",
    "192.168.8.12": "Rack03",
}

VLAN_TYPE_MAP = {
    "pc":      ["22", "23"],
    "switch":  ["8",  "9"],
    "printer": ["30", "31"],
    "plc":     ["40", "41"],
    "hmi":     ["42", "43"],
    "camera":  ["50"],
    "server":  ["10", "11"],
}

# ── Tag: location ─────────────────────────────────────────────────────────────

LOCATION_VLAN_WHITELIST = {"21", "22", "23", "24"}

LOCATION_TAG_MAP = {
    "C:\\Temp\\Production":  "location:production_line",
    "C:\\Temp\\Office":      "location:office",
    "C:\\Temp\\Engineering": "location:engineering",
    "C:\\Temp\\Warehouse":   "location:warehouse",
}

# ── Tag: printer model ────────────────────────────────────────────────────────

PRINTER_VLAN_WHITELIST = {"28", "151"}

PRINTER_MODEL_MAP = {
    "HP":      "model:hp",
    "Zebra":   "model:zebra",
    "Canon":   "model:canon",
    "Epson":   "model:epson",
    "Brother": "model:brother",
    "Ricoh":   "model:ricoh",
    "Xerox":   "model:xerox",
}

# ── Serial + second NIC ───────────────────────────────────────────────────────

SERIAL_NIC_VLAN_WHITELIST = {"21", "22", "23", "24"}
SERIAL_NIC_NAME_PREFIXES  = ("C0", "W")


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.utcnow().isoformat() + "Z"

def _sub(parent: etree._Element, tag: str, text: str) -> etree._Element:
    el = etree.SubElement(parent, tag)
    el.text = text or ""
    return el

def _set_or_create(parent: etree._Element, tag: str, value: str):
    el = parent.find(tag)
    if el is None:
        el = etree.SubElement(parent, tag)
    el.text = value

def _update_field(el: etree._Element, tag: str, new_val: str) -> bool:
    """
    Update a field only if new_val is non-empty and different.
    Never overwrites existing data with empty/None.
    Returns True if changed.
    """
    if not new_val or new_val.strip() in ("", "unknown", "0", "None"):
        return False
    child = el.find(tag)
    if child is None:
        etree.SubElement(el, tag).text = new_val
        return True
    if child.text != new_val:
        child.text = new_val
        return True
    return False

def resolve_type(vlan: str) -> str:
    _VLAN_TO_TYPE: dict[str, str] = {
        vlan_id: dtype
        for dtype, vlans in VLAN_TYPE_MAP.items()
        for vlan_id in vlans
    }
    return _VLAN_TO_TYPE.get(vlan.strip(), "")

def ping(ip: str, timeout: int = 1) -> bool:
    """Fast ping — returns True if host responds."""
    flag = "-n" if os.name == "nt" else "-c"
    wait = "-w" if os.name == "nt" else "-W"
    try:
        result = subprocess.run(
            ["ping", flag, "1", wait, str(timeout), ip],
            capture_output=True,
            timeout=timeout + 1
        )
        return result.returncode == 0
    except Exception:
        return False


# ─── Scan mode ────────────────────────────────────────────────────────────────

class ScanMode(Enum):
    FULL = "full"
    NEW  = "new"
    TAGS = "tags"

def ask_scan_mode() -> ScanMode:
    print("\nScan mode:")
    print("  [1] Full scan  — update all devices + tags")
    print("  [2] New only   — collect all, only process new MACs")
    print("  [3] Tags only  — skip collection, refresh tags on existing devices")
    choice = input("Select [1/2/3]: ").strip()
    return {
        "1": ScanMode.FULL,
        "2": ScanMode.NEW,
        "3": ScanMode.TAGS,
    }.get(choice, ScanMode.FULL)


# ─── Data model ───────────────────────────────────────────────────────────────

@dataclass
class RawDevice:
    ip:          str
    mac:         str
    vlan:        str
    switch:      str  = ""
    switch_port: str  = ""
    hostname:    str  = ""
    rack:        str  = ""
    online:      bool = True
    serial:      str  = ""
    second_ip:   str  = ""
    type:        str  = field(default="", init=False)
    tags:        set  = field(default_factory=set, init=False)

    def __post_init__(self):
        self.type = resolve_type(self.vlan)


# ─── Collection ───────────────────────────────────────────────────────────────

def _ssh_shell(host: str, username: str, password: str, port: int) -> tuple:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, port, username, password)
    shell = client.invoke_shell()
    time.sleep(2)
    shell.recv(100_000)
    return shell, client


def collect_firewall(host: str, username: str, password: str, port: int) -> list[RawDevice]:
    """SSH into firewall, extract IP / MAC / VLAN from ARP table."""
    devices = []
    client  = None
    try:
        shell, client = _ssh_shell(host, username, password, port)
        shell.send("config vdom\n");     time.sleep(2)
        shell.send("edit 1_internal\n"); time.sleep(2)
        shell.send("get sys arp\n");     time.sleep(2.5)
        output = shell.recv(100_000).decode()

        pattern = (
            r"(192\.168\.[0-9]{1,3}\.[0-9]{1,3})"
            r"\s+[0-9]{1,8}"
            r"\s+([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}"
            r":[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})"
            r"\s+vl([0-9]{4})"
        )
        for ip, mac, vlan in re.findall(pattern, output):
            devices.append(RawDevice(ip=ip, mac=mac.upper(), vlan=vlan))

    except Exception as e:
        print(f"[!] Firewall error ({host}): {e}")
    finally:
        if client:
            client.close()

    return devices


def collect_extreme(host: str, devices: list[RawDevice], username: str, password: str, port: int) -> None:
    """SSH into Extreme switch, cross-reference MACs, fill switch + port."""
    client = None
    try:
        shell, client = _ssh_shell(host, username, password, port)
        shell.send("\n");                       time.sleep(1)
        shell.send("config terminal\n");        time.sleep(1)
        shell.send("terminal more disable\n");  time.sleep(1)
        shell.send("show i-sid mac-address-entry | exclude Port\n")
        time.sleep(1.5)
        shell.send("terminal more enable\n");   time.sleep(1)
        output = shell.recv(10_000).decode()

        pattern = (
            r"[0-9]{8}\s+learned\s+"
            r"((?:[0-9a-f]{2}:){5}[0-9a-f]{2})"
            r"\s+.{1,5}:(1\/\/\b\d{1,2}\b)"
        )
        seen: set[str] = set()
        mac_port: list[tuple[str, str]] = []
        for mac, port_str in re.findall(pattern, output):
            mac_u = mac.upper()
            if mac_u not in seen:
                mac_port.append((mac_u, port_str))
                seen.add(mac_u)

        rack         = RACK_MAPPING.get(host, "")
        switch_label = f"{host}_{rack}" if rack else host

        for device in devices:
            for mac, port_str in mac_port:
                if device.mac == mac:
                    device.switch      = switch_label
                    device.switch_port = port_str
                    device.rack        = rack
                    break

    except Exception as e:
        print(f"[!] Extreme error ({host}): {e}")
    finally:
        if client:
            client.close()


def resolve_hostname(device: RawDevice) -> None:
    """Ping + reverse DNS. Sets online=False if unreachable."""
    if not ping(device.ip):
        device.online   = False
        device.hostname = device.ip
        return
    try:
        device.hostname = socket.gethostbyaddr(device.ip.strip())[0]
    except Exception:
        device.hostname = device.ip


def collect_serial_and_second_nic(device: RawDevice) -> None:
    """
    WinRM via Invoke-Command — same approach as original powershell script.

    Filters (all must pass):
      - VLAN must be in SERIAL_NIC_VLAN_WHITELIST
      - Hostname must start with C0 or W (case insensitive)
      - Hostname must be resolved (not equal to IP string)
      - Device must respond to ping

    Collects in a single Invoke-Command round trip:
      - BIOS serial number
      - Second NIC IP (any IP that is not the primary from firewall)
      - Location folder tags (same LOCATION_TAG_MAP used elsewhere)
    """

    # ── Filter: VLAN ──────────────────────────────────────────────────────────
    if device.vlan not in SERIAL_NIC_VLAN_WHITELIST:
        return

    # ── Filter: hostname resolved ─────────────────────────────────────────────
    if not device.hostname or device.hostname == device.ip:
        print(f"[~] {device.ip} — hostname not resolved, skipping WinRM")
        return

    # ── Filter: name prefix (case insensitive) ────────────────────────────────
    if not any(device.hostname.upper().startswith(p.upper()) for p in SERIAL_NIC_NAME_PREFIXES):
        return

    # ── Filter: ping before opening WinRM connection ──────────────────────────
    if not ping(device.ip):
        device.online = False
        print(f"[~] {device.ip} ({device.hostname}) — offline, skipping WinRM")
        return

    # ── Build folder check block ──────────────────────────────────────────────
    folder_checks = "".join([
        f"if (Test-Path '{path}') {{ $folders += '{tag}' }}; "
        for path, tag in LOCATION_TAG_MAP.items()
    ])

    # ── Single bundled powershell scriptblock ─────────────────────────────────
    ps_script = (
        "$serial = (Get-WmiObject Win32_BIOS).SerialNumber.Trim(); "
        "$ips = (Get-NetIPAddress -AddressFamily IPv4 "
        "        | Where-Object { $_.IPAddress -notlike '127.*' -and "
        "                         $_.IPAddress -notlike '169.*' } "
        "        | Select-Object -ExpandProperty IPAddress) -join ','; "
        "$folders = @(); "
        f"{folder_checks}"
        "Write-Output ('SERIAL:' + $serial); "
        "Write-Output ('IPS:' + $ips); "
        "Write-Output ('FOLDERS:' + ($folders -join ','))"
    )

    try:
        result = subprocess.run(
            [
                "powershell", "-Command",
                f"Invoke-Command -ComputerName {device.hostname} "
                f"-ScriptBlock {{ {ps_script} }}"
            ],
            capture_output=True,
            timeout=30
        )
        output = result.stdout.decode()

        for line in output.splitlines():
            line = line.strip()

            if line.startswith("SERIAL:"):
                val = line.replace("SERIAL:", "").strip()
                if val:
                    device.serial = val

            elif line.startswith("IPS:"):
                all_ips   = [ip.strip() for ip in line.replace("IPS:", "").split(",") if ip.strip()]
                other_ips = [ip for ip in all_ips if ip != device.ip]
                if other_ips:
                    device.second_ip = other_ips[0]

            elif line.startswith("FOLDERS:"):
                val = line.replace("FOLDERS:", "").strip()
                if val:
                    for tag in val.split(","):
                        tag = tag.strip()
                        if tag:
                            device.tags.add(tag)

    except subprocess.TimeoutExpired:
        print(f"[!] WinRM timeout for {device.ip} ({device.hostname})")
        device.online = False
    except Exception as e:
        print(f"[!] WinRM collection failed for {device.ip} ({device.hostname}): {e}")
        device.online = False


# ─── Pipeline wrappers (no lambdas) ───────────────────────────────────────────

def _collect_extreme_wrapper(args: tuple) -> None:
    host, devices, username, password, port = args
    collect_extreme(host, devices, username, password, port)

def _resolve_hostname_wrapper(device: RawDevice) -> None:
    resolve_hostname(device)

def _collect_serial_wrapper(device: RawDevice) -> None:
    collect_serial_and_second_nic(device)


def run_collection(username: str, password: str, port: int) -> list[RawDevice]:
    # Step 1 — firewall
    print("[→] Collecting from firewall...")
    devices = collect_firewall(FIREWALL_HOST, username, password, port)
    print(f"    {len(devices)} devices found")

    # Step 2 — switches in parallel
    print("[→] Collecting switch port data...")
    extreme_args = [(h, devices, username, password, port) for h in EXTREME_IPS]
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        pool.map(_collect_extreme_wrapper, extreme_args)

    for d in devices:
        if not d.switch:
            d.switch      = "unknown"
            d.switch_port = "unknown"

    # Step 3 — hostname resolution in parallel
    print("[→] Resolving hostnames...")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        pool.map(_resolve_hostname_wrapper, devices)

    # Step 4 — serial / second NIC / location folders via WinRM in parallel
    print("[→] Collecting serial / second NIC / location folders (WinRM)...")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        pool.map(_collect_serial_wrapper, devices)

    print(f"[✓] Collection complete — {len(devices)} devices")
    return devices


# ─── Tag collector ────────────────────────────────────────────────────────────

class TagCollector:
    """
    Each collect_* method returns a set of tag strings for one device.
    Location tags are already collected inside the bundled WinRM call
    during collection so they live in dev.tags before this runs.
    Add new tag sources by adding a method and registering in collect_all().
    """

    def collect_all(self, dev: RawDevice) -> set[str]:
        tags: set[str] = set(dev.tags)  # preserve tags already set in collection
        collectors = [
            self.collect_printer_model,
            self.collect_switch_rack,
        ]
        for collector in collectors:
            try:
                tags |= collector(dev)
            except Exception as e:
                print(f"[!] {collector.__name__} failed for {dev.ip}: {e}")
        return tags

    def collect_printer_model(self, dev: RawDevice) -> set[str]:
        if dev.vlan not in PRINTER_VLAN_WHITELIST:
            return set()

        try:
            response = requests.get(
                f"http://{dev.ip}",
                verify=False,
                timeout=5
            )
            content = response.text
            for pattern, tag in PRINTER_MODEL_MAP.items():
                if pattern.lower() in content.lower():
                    return {tag}
            return set()

        except Exception as e:
            print(f"[!] Printer model check failed for {dev.ip}: {e}")
            dev.online = False
            return set()

    def collect_switch_rack(self, dev: RawDevice) -> set[str]:
        if not dev.switch or dev.switch == "unknown":
            return set()
        parts = dev.switch.split("_")
        if len(parts) < 2:
            return set()
        rack = parts[1].strip()
        return {f"rack:{rack}"}


# ─── XML manager ──────────────────────────────────────────────────────────────

class XMLInventoryManager:
    """
    Merges RawDevice records into a persistent XML file.
    Unique key : MAC address (case-insensitive).
    Never deletes — absent devices are left untouched.
    Never overwrites existing data with empty values.
    """

    def __init__(self, path: str, collector: TagCollector):
        self.path      = Path(path)
        self.collector = collector
        self._load_or_create()

    def _load_or_create(self):
        if self.path.exists():
            self.tree = etree.parse(str(self.path))
            self.root = self.tree.getroot()
            print(f"[✓] Loaded: {self.path}")
        else:
            self.root = etree.Element("network")
            self.root.set("schema-version", "1.0")
            self.root.set("generated", _now())
            etree.SubElement(self.root, "meta")
            self.tree = etree.ElementTree(self.root)
            print(f"[+] Created: {self.path}")

    # ── Merge ─────────────────────────────────────────────────────────────────

    def merge(self, devices: list[RawDevice], mode: ScanMode = ScanMode.FULL) -> dict:
        index: dict[str, etree._Element] = {
            el.findtext("mac", "").upper(): el
            for el in self.root.findall("device")
        }

        stats = {"added": 0, "updated": 0, "unchanged": 0, "skipped": 0}

        for dev in devices:
            mac = dev.mac.upper()

            if mode == ScanMode.NEW:
                if mac in index:
                    stats["skipped"] += 1
                    continue
                dev.tags = self.collector.collect_all(dev)
                self.root.append(self._build(dev))
                stats["added"] += 1

            elif mode == ScanMode.FULL:
                dev.tags = self.collector.collect_all(dev)
                if mac in index:
                    changed = self._update(index[mac], dev)
                    stats["updated" if changed else "unchanged"] += 1
                else:
                    self.root.append(self._build(dev))
                    stats["added"] += 1

            elif mode == ScanMode.TAGS:
                if mac not in index:
                    stats["skipped"] += 1
                    continue
                dev.tags = self.collector.collect_all(dev)
                changed  = self._merge_tags(index[mac], dev)
                if changed:
                    status = index[mac].find("xml_change_status")
                    if status is None:
                        etree.SubElement(index[mac], "xml_change_status").text = f"modified:{_now()}"
                    else:
                        status.text = f"modified:{_now()}"
                stats["updated" if changed else "unchanged"] += 1

        self._update_meta(stats, len(self.root.findall("device")))
        self._save()

        print(
            f"[✓] Merge done ({mode.value}) — "
            f"added: {stats['added']}, "
            f"updated: {stats['updated']}, "
            f"unchanged: {stats['unchanged']}, "
            f"skipped: {stats['skipped']}"
        )
        return stats

    # ── Build new device ──────────────────────────────────────────────────────

    def _build(self, dev: RawDevice) -> etree._Element:
        el = etree.Element("device")
        el.set("id", str(uuid.uuid4())[:8])

        _sub(el, "ip",                dev.ip)
        _sub(el, "mac",               dev.mac)
        _sub(el, "vlan",              dev.vlan)
        _sub(el, "last-vlan",         "")
        _sub(el, "switch",            dev.switch)
        _sub(el, "switch-port",       dev.switch_port)
        _sub(el, "hostname",          dev.hostname)
        _sub(el, "rack",              dev.rack)
        _sub(el, "type",              dev.type)
        _sub(el, "serial",            dev.serial)
        _sub(el, "second-ip",         dev.second_ip)
        _sub(el, "last-ip",           "")
        _sub(el, "files-path",        "")
        _sub(el, "first-seen",        _now())
        _sub(el, "tags",              ",".join(sorted(dev.tags)))
        _sub(el, "tags-history",      "")
        _sub(el, "xml_change_status", f"added:{_now()}")

        return el

    # ── Update existing device ────────────────────────────────────────────────

    def _update(self, el: etree._Element, dev: RawDevice) -> bool:
        if not dev.online:
            print(f"[~] {dev.ip} offline — skipping update")
            return False

        changed = False

        # ── IP change history (DHCP) ──────────────────────────────────────────
        current_ip = el.findtext("ip", "").strip()
        if current_ip and current_ip != dev.ip.strip():
            last_ip_el = el.find("last-ip")
            if last_ip_el is None:
                last_ip_el = etree.SubElement(el, "last-ip")
            existing = [
                v.strip()
                for v in (last_ip_el.text or "").split(",")
                if v.strip()
            ]
            if current_ip not in existing:
                existing.insert(0, current_ip)
            last_ip_el.text = ",".join(existing)
            changed = True
            print(f"[!] IP change detected for {dev.mac}: {current_ip} → {dev.ip}")

        # ── VLAN change history ───────────────────────────────────────────────
        current_vlan = el.findtext("vlan", "").strip()
        if current_vlan and current_vlan != dev.vlan.strip():
            last_vlan_el = el.find("last-vlan")
            if last_vlan_el is None:
                last_vlan_el = etree.SubElement(el, "last-vlan")
            existing = [
                v.strip()
                for v in (last_vlan_el.text or "").split(",")
                if v.strip()
            ]
            if current_vlan not in existing:
                existing.insert(0, current_vlan)
            last_vlan_el.text = ",".join(existing)
            changed = True
            print(f"[!] VLAN change detected for {dev.mac}: {current_vlan} → {dev.vlan}")

        # ── Standard fields — never overwrite with empty ──────────────────────
        fields = {
            "ip":          dev.ip,
            "mac":         dev.mac,
            "vlan":        dev.vlan,
            "switch":      dev.switch,
            "switch-port": dev.switch_port,
            "hostname":    dev.hostname,
            "rack":        dev.rack,
            "type":        dev.type,
            "serial":      dev.serial,
            "second-ip":   dev.second_ip,
        }
        for tag, new_val in fields.items():
            changed |= _update_field(el, tag, new_val)

        # ── Tags ──────────────────────────────────────────────────────────────
        tag_changed = self._merge_tags(el, dev)
        changed     = changed or tag_changed

        if changed:
            status = el.find("xml_change_status")
            if status is None:
                etree.SubElement(el, "xml_change_status").text = f"modified:{_now()}"
            else:
                status.text = f"modified:{_now()}"

        return changed

    # ── Tag merge ─────────────────────────────────────────────────────────────

    def _merge_tags(self, el: etree._Element, dev: RawDevice) -> bool:
        if not dev.online:
            return False

        tags_el    = el.find("tags")
        history_el = el.find("tags-history")

        if tags_el is None:
            tags_el = etree.SubElement(el, "tags")
        if history_el is None:
            history_el = etree.SubElement(el, "tags-history")

        existing_active: set[str] = {
            t.strip() for t in (tags_el.text or "").split(",") if t.strip()
        }
        existing_history: set[str] = {
            t.strip() for t in (history_el.text or "").split(",") if t.strip()
        }

        new_tags = set(dev.tags)

        # Unknown printer model — only on first contact with no match ever
        if dev.vlan in PRINTER_VLAN_WHITELIST and dev.online:
            model_tags     = {t for t in existing_active  if t.startswith("model:")}
            history_models = {t for t in existing_history if t.startswith("model:")}
            new_models     = {t for t in new_tags         if t.startswith("model:")}
            if not new_models and not model_tags and not history_models:
                new_tags = new_tags | {"model:unknown"}

        added   = new_tags - existing_active
        removed = existing_active - new_tags

        if not added and not removed:
            return False

        for tag_text in removed:
            existing_active.discard(tag_text)
            existing_history.add(tag_text)

        existing_active |= added

        tags_el.text    = ",".join(sorted(existing_active))
        history_el.text = ",".join(sorted(existing_history))

        return True

    # ── Meta ──────────────────────────────────────────────────────────────────

    def _update_meta(self, stats: dict, total: int):
        meta = self.root.find("meta")
        _set_or_create(meta, "total-devices",     str(total))
        _set_or_create(meta, "last-scan",         _now())
        _set_or_create(meta, "last-scan-added",   str(stats["added"]))
        _set_or_create(meta, "last-scan-updated", str(stats["updated"]))

    # ── Rebuild devices from XML (tags-only mode) ─────────────────────────────

    def devices_from_xml(self) -> list[RawDevice]:
        devices = []
        for el in self.root.findall("device"):
            dev = RawDevice(
                ip          = el.findtext("ip",          ""),
                mac         = el.findtext("mac",         ""),
                vlan        = el.findtext("vlan",        ""),
                switch      = el.findtext("switch",      ""),
                switch_port = el.findtext("switch-port", ""),
                hostname    = el.findtext("hostname",    ""),
                rack        = el.findtext("rack",        ""),
                serial      = el.findtext("serial",      ""),
                second_ip   = el.findtext("second-ip",   ""),
            )
            existing_tags = el.findtext("tags", "")
            if existing_tags:
                dev.tags = {t.strip() for t in existing_tags.split(",") if t.strip()}
            devices.append(dev)
        return devices

    # ── Save ──────────────────────────────────────────────────────────────────

    def _save(self):
        self.tree.write(
            str(self.path),
            pretty_print=True,
            xml_declaration=True,
            encoding="UTF-8",
        )


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")
    port     = 22   # used for firewall + switches (Paramiko SSH)

    mode      = ask_scan_mode()
    collector = TagCollector()
    manager   = XMLInventoryManager(XML_FILE, collector)

    if mode == ScanMode.TAGS:
        devices = manager.devices_from_xml()
    else:
        devices = run_collection(username, password, port)

    manager.merge(devices, mode=mode)
