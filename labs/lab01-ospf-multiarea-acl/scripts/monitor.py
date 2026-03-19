#!/usr/bin/env python3
"""
monitor.py v3 — CCIE Lab Network Monitor
Polls all 10 devices in PARALLEL, writes status.json, git pushes.
Cron: */5 * * * * cd /home/eve-linux/CCIE-Automation && python3 labs/lab01-ospf-multiarea-acl/scripts/monitor.py
"""

import socket, time, json, re, subprocess, os
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed, wait, FIRST_EXCEPTION

EVENG_IP    = "192.168.1.100"
REPO_ROOT   = "/home/eve-linux/CCIE-Automation"
STATUS_FILE = os.path.join(REPO_ROOT, "docs", "status.json")

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

# ── TELNET HELPERS ─────────────────────────────────────

def connect(port, sock_timeout=5):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(sock_timeout)
    s.connect((EVENG_IP, port))
    time.sleep(0.5)
    try: s.recv(4096)  # discard IAC
    except: pass
    # IAC responses
    s.send(bytes([0xff,0xfd,0x01,0xff,0xfd,0x03,0xff,0xfd,0x00,0xff,0xfb,0x00]))
    time.sleep(0.5)
    try: s.recv(4096)
    except: pass
    return s

def read_prompt(s, expect='#', max_wait=8):
    """Read until expect char found or timeout."""
    buf = b''
    deadline = time.time() + max_wait
    while time.time() < deadline:
        try:
            buf += s.recv(4096)
            if expect.encode() in buf:
                break
        except socket.timeout:
            break
    return buf.decode('ascii', errors='ignore')

def cmd(s, command, wait=6):
    s.send(command.encode() + b'\r\n')
    return read_prompt(s, '#', wait)

def login(s, pw=None):
    """Wake up and get to priv exec."""
    s.send(b'\r\n')
    out = read_prompt(s, '#', 4)
    if '>' in out and '#' not in out:
        s.send(b'enable\r\n')
        out2 = read_prompt(s, '#', 4)
        if 'Password' in out2:
            s.send((pw or '').encode() + b'\r\n')
            read_prompt(s, '#', 4)
    cmd(s, 'terminal length 0', 3)
    # Quick suppress of syslog via one-line config
    s.send(b'no logging console\r\n')  # priv exec trick — harmless if fails
    time.sleep(0.5)
    try: s.recv(4096)
    except: pass


# ── PARSERS ────────────────────────────────────────────

def parse_interfaces(txt):
    ifaces = []
    for line in txt.splitlines():
        m = re.match(r'\s*(GigabitEthernet\S+)\s+(\S+)\s+\S+\s+\S+\s+(\w+)\s+(\w+)', line)
        if m and 'Interface' not in line:
            ifaces.append({"name": m.group(1),
                           "ip": None if m.group(2)=='unassigned' else m.group(2),
                           "status": m.group(3), "protocol": m.group(4)})
    return ifaces

def parse_neighbors(txt):
    nbrs = []
    for line in txt.splitlines():
        m = re.match(r'\s*(\d+\.\d+\.\d+\.\d+)\s+\d+\s+(\w+)/\w+\s+\S+\s+\S+\s+(\S+)', line)
        if m:
            nbrs.append({"neighbor_id": m.group(1), "state": m.group(2), "interface": m.group(3)})
    return nbrs

def parse_dhcp(txt):
    pools, cur = [], None
    for line in txt.splitlines():
        if re.match(r'Pool \S+ :', line):
            if cur: pools.append(cur)
            cur = {"name": re.match(r'Pool (\S+) :', line).group(1), "leased":0, "total":0}
        if cur:
            lm = re.match(r'\s*Leased addresses\s*:\s*(\d+)', line)
            if lm: cur["leased"] = int(lm.group(1))
            tm = re.match(r'\s*Total addresses\s*:\s*(\d+)', line)
            if tm: cur["total"] = int(tm.group(1))
    if cur: pools.append(cur)
    return pools

def parse_sw_status(txt):
    ifaces = []
    for line in txt.splitlines():
        m = re.match(r'\s*(Gi\S+)\s+\S*\s+(connected|notconnect|disabled)', line)
        if m: ifaces.append({"name": m.group(1), "status": m.group(2)})
    return ifaces


# ── COLLECTORS (run in threads) ─────────────────────────

def poll_router(name, port, pw=None):
    try:
        s = connect(port)
        login(s, pw)
        
        ifaces   = parse_interfaces(cmd(s, 'show ip interface brief', 6))
        nbrs     = parse_neighbors(cmd(s, 'show ip ospf neighbor', 6))
        routes   = len([l for l in cmd(s, 'show ip route ospf', 8).splitlines()
                        if re.match(r'\s*O[\s\*]', l)])
        pools    = parse_dhcp(cmd(s, 'show ip dhcp pool', 8))
        s.close()
        
        result = {"status": "up", "interfaces": ifaces,
                  "ospf_neighbors": nbrs, "ospf_routes": routes}
        if pools: result["dhcp_pools"] = pools
        print(f"  ✅ {name}: {len(ifaces)} ifaces, {len(nbrs)} OSPF, {len(pools)} DHCP")
        return name, result
    except Exception as e:
        print(f"  ❌ {name}: {e}")
        return name, {"status": "down", "error": str(e)}

def poll_switch(name, port):
    try:
        s = connect(port)
        login(s)
        ifaces = parse_sw_status(cmd(s, 'show interface status', 6))
        s.close()
        connected = sum(1 for i in ifaces if i["status"]=="connected")
        print(f"  ✅ {name}: {connected}/{len(ifaces)} connected")
        return name, {"status": "up", "interfaces": ifaces, "connected_ports": connected}
    except Exception as e:
        print(f"  ❌ {name}: {e}")
        return name, {"status": "down", "error": str(e)}


# ── MAIN ───────────────────────────────────────────────

def main():
    print(f"\n{'='*55}")
    print(f"  CCIE Lab Monitor — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*55}")
    
    devices_status = {}
    futures = {}
    
    # Submit all polls in parallel
    with ThreadPoolExecutor(max_workers=10) as ex:
        for name, d in DEVICES.items():
            if d["type"] == "router":
                f = ex.submit(poll_router, name, d["port"], d.get("enable_pw"))
            else:
                f = ex.submit(poll_switch, name, d["port"])
            futures[f] = name
        
        # Collect results with per-task 50s timeout
        done, pending = wait(list(futures.keys()), timeout=50)
        for f in done:
            try:
                name, result = f.result()
                devices_status[name] = result
            except Exception as e:
                name = futures[f]
                devices_status[name] = {"status": "down", "error": str(e)}
        for f in pending:
            name = futures[f]
            print(f"  ⏱  {name}: timed out")
            devices_status[name] = {"status": "unknown", "error": "timeout"}
    
    # Write status.json
    status = {
        "_meta": {
            "last_updated": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
            "collector": "monitor.py",
            "interval_minutes": 5,
        },
        "devices": devices_status
    }
    with open(STATUS_FILE, 'w') as f:
        json.dump(status, f, indent=2)
    
    # Git push
    try:
        subprocess.run(['git','add','docs/status.json'], cwd=REPO_ROOT,
                       capture_output=True, timeout=15)
        diff = subprocess.run(['git','diff','--staged','--name-only'], cwd=REPO_ROOT,
                              capture_output=True, text=True, timeout=10)
        if 'status.json' in diff.stdout:
            ts = datetime.now().strftime('%Y-%m-%d %H:%M')
            subprocess.run(['git','commit','-m',f'monitor: {ts}'],
                          cwd=REPO_ROOT, capture_output=True, timeout=15)
            subprocess.run(['git','push','origin','main'],
                          cwd=REPO_ROOT, capture_output=True, timeout=30)
            print(f"\n  📤 Pushed to GitHub")
        else:
            print(f"\n  ✓  No changes to push")
    except Exception as e:
        print(f"\n  ⚠️  Git: {e}")
    
    up = sum(1 for d in devices_status.values() if d.get('status')=='up')
    print(f"  {'='*45}")
    print(f"  Result: {up}/{len(DEVICES)} devices UP | {datetime.now().strftime('%H:%M:%S')}")
    print(f"{'='*55}\n")

if __name__ == "__main__":
    main()
