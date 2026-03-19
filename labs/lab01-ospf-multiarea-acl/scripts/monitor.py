#!/usr/bin/env python3
"""
monitor.py — CCIE Lab Network Monitor
=======================================
Polls all 10 devices via EVE-NG console telnet every 5 minutes,
collects live data, writes docs/status.json, and git pushes to GitHub.

Run via cron:
  */5 * * * * cd /home/eve-linux/CCIE-Automation && python3 labs/lab01-ospf-multiarea-acl/scripts/monitor.py

Or manually:
  python3 labs/lab01-ospf-multiarea-acl/scripts/monitor.py
"""

import socket
import time
import json
import re
import subprocess
import os
from datetime import datetime, timezone

EVENG_IP   = "192.168.1.100"
REPO_ROOT  = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
STATUS_FILE = os.path.join(REPO_ROOT, "docs", "status.json")

# IAC telnet negotiation bytes
IAC_NEG = bytes([0xff,0xfd,0x01, 0xff,0xfd,0x03, 0xff,0xfd,0x00, 0xff,0xfb,0x00])

DEVICES = {
    "R1":  {"port": 38727, "type": "router"},
    "R2":  {"port": 54203, "type": "router"},
    "R3":  {"port": 41967, "type": "router", "enable_pw": "admin"},
    "R4":  {"port": 33599, "type": "router"},
    "Sw5": {"port": 46457, "type": "switch"},
    "Sw6": {"port": 57373, "type": "switch"},
    "Sw7": {"port": 48741, "type": "switch"},
    "Sw8": {"port": 48381, "type": "switch"},
    "Sw9": {"port": 34575, "type": "switch"},
    "Sw10":{"port": 49197, "type": "switch"},
}


def telnet_connect(port, timeout=15):
    """Connect and negotiate telnet options."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((EVENG_IP, port))
    time.sleep(1)
    try: s.recv(4096)
    except: pass
    s.send(IAC_NEG)
    time.sleep(1)
    try: s.recv(4096)
    except: pass
    return s

def read_all(s, wait=2.5):
    """Read all available data."""
    time.sleep(wait)
    out = b''
    while True:
        try:
            chunk = s.recv(8192)
            out += chunk
            time.sleep(0.2)
        except socket.timeout:
            break
    return out.decode('ascii', errors='ignore')

def send(s, cmd, wait=1.5):
    """Send command and read response."""
    s.send(cmd.encode() + b'\r\n')
    return read_all(s, wait)

def enable(s, pw=None):
    """Get into privileged exec mode."""
    send(s, '', 0.5)
    out = send(s, 'enable', 2)
    if 'Password' in out:
        p = pw or ''
        out2 = send(s, p, 1.5)
        if 'Bad secrets' in out2:
            send(s, 'admin', 1.5)
    send(s, 'terminal length 0', 0.8)
    send(s, 'no logging console', 0.5)
    time.sleep(1)
    send(s, '', 0.5)  # flush syslog


# ── PARSERS ────────────────────────────────────────────

def parse_ip_brief(output):
    """Parse 'show ip interface brief'."""
    interfaces = []
    for line in output.splitlines():
        m = re.match(r'\s*(GigabitEthernet\S+|Loopback\S+)\s+(\S+)\s+\S+\s+\S+\s+(\S+)\s+(\S+)', line)
        if m:
            interfaces.append({
                "name": m.group(1),
                "ip": m.group(2) if m.group(2) != 'unassigned' else None,
                "status": "up" if m.group(3) == "up" else "down",
                "protocol": "up" if m.group(4) == "up" else "down"
            })
    return interfaces

def parse_ospf_neighbors(output):
    """Parse 'show ip ospf neighbor'."""
    neighbors = []
    for line in output.splitlines():
        m = re.match(r'\s*(\d+\.\d+\.\d+\.\d+)\s+\d+\s+(\w+)/\w+\s+\S+\s+\S+\s+(\S+)', line)
        if m:
            neighbors.append({
                "neighbor_id": m.group(1),
                "state": m.group(2),
                "interface": m.group(3)
            })
    return neighbors

def parse_ospf_routes(output):
    """Count OSPF routes."""
    return len([l for l in output.splitlines() if re.match(r'\s*O\s', l) or re.match(r'\s*O IA', l)])

def parse_dhcp_pools(output):
    """Parse 'show ip dhcp pool' output."""
    pools = []
    current = None
    for line in output.splitlines():
        m = re.match(r'Pool (\S+) :', line)
        if m:
            if current: pools.append(current)
            current = {"name": m.group(1), "network": None, "leased": 0, "total": 0}
        if current:
            lm = re.match(r'\s*Leased addresses\s*:\s*(\d+)', line)
            if lm: current["leased"] = int(lm.group(1))
            tm = re.match(r'\s*Total addresses\s*:\s*(\d+)', line)
            if tm: current["total"] = int(tm.group(1))
            nm = re.search(r'(\d+\.\d+\.\d+\.\d+\s+-\s+\d+\.\d+\.\d+\.\d+)', line)
    if current: pools.append(current)
    return pools

def parse_switch_status(output):
    """Parse 'show interface status'."""
    interfaces = []
    for line in output.splitlines():
        m = re.match(r'\s*(Gi\S+)\s+\S*\s+(connected|notconnect|disabled)', line)
        if m:
            interfaces.append({"name": m.group(1), "status": m.group(2)})
    return interfaces


# ── COLLECTORS ─────────────────────────────────────────

def collect_router(name, port, enable_pw=None):
    """Collect data from a router."""
    print(f"  Polling {name}...")
    result = {"status": "down"}
    try:
        s = telnet_connect(port)
        enable(s, enable_pw)

        out_brief = send(s, 'show ip interface brief', 3)
        out_ospf  = send(s, 'show ip ospf neighbor', 3)
        out_route = send(s, 'show ip route ospf', 4)
        out_dhcp  = send(s, 'show ip dhcp pool', 4)

        interfaces = parse_ip_brief(out_brief)
        neighbors  = parse_ospf_neighbors(out_ospf)
        routes     = parse_ospf_routes(out_route)
        dhcp_pools = parse_dhcp_pools(out_dhcp)

        result = {
            "status": "up" if interfaces else "unknown",
            "interfaces": interfaces,
            "ospf_neighbors": neighbors,
            "ospf_routes": routes,
        }
        if dhcp_pools:
            result["dhcp_pools"] = dhcp_pools

        s.close()
        print(f"    {name}: {len(interfaces)} interfaces, {len(neighbors)} OSPF neighbors, {len(dhcp_pools)} DHCP pools")
    except Exception as e:
        print(f"    {name}: ERROR - {e}")
    return result

def collect_switch(name, port):
    """Collect data from a switch."""
    print(f"  Polling {name}...")
    result = {"status": "down"}
    try:
        s = telnet_connect(port)
        enable(s)
        out = send(s, 'show interface status', 3)
        interfaces = parse_switch_status(out)
        s.close()
        connected = [i for i in interfaces if i["status"] == "connected"]
        result = {
            "status": "up" if interfaces else "unknown",
            "interfaces": interfaces,
            "connected_ports": len(connected)
        }
        print(f"    {name}: {len(connected)}/{len(interfaces)} ports connected")
    except Exception as e:
        print(f"    {name}: ERROR - {e}")
    return result


# ── MAIN ───────────────────────────────────────────────

def main():
    print(f"\n{'='*55}")
    print(f"  CCIE Lab Monitor — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*55}")

    devices_status = {}

    print("\n[Phase 1] Polling Routers")
    for name in ["R1", "R2", "R3", "R4"]:
        d = DEVICES[name]
        devices_status[name] = collect_router(name, d["port"], d.get("enable_pw"))

    print("\n[Phase 2] Polling Switches")
    for name in ["Sw5", "Sw6", "Sw7", "Sw8", "Sw9", "Sw10"]:
        d = DEVICES[name]
        devices_status[name] = collect_switch(name, d["port"])

    # Write status.json
    status = {
        "_meta": {
            "last_updated": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
            "collector": "monitor.py",
            "interval_minutes": 5,
            "note": "Auto-updated by monitor.py on Ubuntu VM (192.168.1.103)"
        },
        "devices": devices_status
    }

    os.makedirs(os.path.dirname(STATUS_FILE), exist_ok=True)
    with open(STATUS_FILE, 'w') as f:
        json.dump(status, f, indent=2)
    print(f"\n  ✅ Written: {STATUS_FILE}")

    # Git push
    print("\n[Phase 3] Pushing to GitHub")
    try:
        subprocess.run(['git', 'add', 'docs/status.json'], cwd=REPO_ROOT, check=True)
        result = subprocess.run(['git', 'diff', '--staged', '--name-only'], cwd=REPO_ROOT,
                                capture_output=True, text=True)
        if 'status.json' in result.stdout:
            ts = datetime.now().strftime('%Y-%m-%d %H:%M')
            subprocess.run(['git', 'commit', '-m', f'monitor: update status.json [{ts}]'],
                          cwd=REPO_ROOT, check=True)
            subprocess.run(['git', 'push', 'origin', 'main'], cwd=REPO_ROOT, check=True)
            print("  ✅ Pushed to GitHub")
        else:
            print("  ℹ️  No changes to push")
    except subprocess.CalledProcessError as e:
        print(f"  ⚠️  Git error: {e}")

    up = sum(1 for d in devices_status.values() if d.get('status') == 'up')
    print(f"\n  Summary: {up}/{len(devices_status)} devices UP")
    print(f"{'='*55}\n")


if __name__ == "__main__":
    main()
