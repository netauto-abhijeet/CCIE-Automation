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

VPC_CONSOLES = {
    "VPC11": 37221,
    "VPC12": 56697,
    "VPC13": 46723,
    "VPC14": 56295,
    "VPC15": 33043,
    "VPC16": 60193,
}

# ── TELNET HELPERS ─────────────────────────────────────

def connect(port, sock_timeout=2):
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
    """Read until expect char found or deadline exceeded.
    NOTE: socket.timeout between chunks does NOT abort — we keep waiting
    until the full deadline, so multi-pool 'show ip dhcp pool' works."""
    buf = b''
    deadline = time.time() + max_wait
    while time.time() < deadline:
        try:
            buf += s.recv(4096)
            if expect.encode() in buf:
                break
        except socket.timeout:
            # IOS pauses between chunks (e.g. between DHCP pools).
            # Only stop if we already have the prompt OR deadline passed.
            if expect.encode() in buf:
                break
            # else: keep looping until deadline
    return buf.decode('ascii', errors='ignore')

def cmd(s, command, wait=6):
    s.send(command.encode() + b'\r\n')
    result = read_prompt(s, '#', wait)
    # Drain leftover prompt chars (double R3# etc.) so next cmd reads clean
    time.sleep(0.15)
    try: s.recv(4096)
    except: pass
    return result

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

# Known pool → subnet mapping (used to enrich status.json)
POOL_NETWORKS = {
    "IT_ADMIN": "192.168.1.0/24",
    "HR":       "192.168.2.0/24",
    "GUEST":    "192.168.3.0/24",
    "FINANCE":  "192.168.4.0/24",
    "OPS":      "192.168.5.0/24",
    "SERVERS":  "192.168.6.0/24",
}

def parse_dhcp(txt):
    pools, cur = [], None
    for line in txt.splitlines():
        m = re.match(r'Pool (\S+) :', line)
        if m:
            if cur: pools.append(cur)
            name = m.group(1)
            cur = {"name": name, "leased": 0, "total": 254,
                   "network": POOL_NETWORKS.get(name, "—")}
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


# ── REACHABILITY CHECK ─────────────────────────────────

def eveng_reachable(timeout=3):
    """Quick TCP check to EVE-NG SSH port. Fast exit when lab is off."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((EVENG_IP, 22))
        s.close()
        return True
    except Exception:
        return False


# ── COLLECTORS (run in threads) ─────────────────────────

def poll_router(name, port, pw=None):
    try:
        s = connect(port)
        login(s, pw)
        
        ifaces   = parse_interfaces(cmd(s, 'show ip interface brief', 6))
        nbrs     = parse_neighbors(cmd(s, 'show ip ospf neighbor', 6))
        routes   = len([l for l in cmd(s, 'show ip route ospf', 8).splitlines()
                        if re.match(r'\s*O[\s\*]', l)])
        pools    = parse_dhcp(cmd(s, 'show ip dhcp pool', 20))  # 3 pools × ~2s gap
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


def poll_vpc(name, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((EVENG_IP, port))
        time.sleep(0.3)
        try: s.recv(4096)
        except: pass
        s.send(b'\n')
        buf = b''
        deadline = time.time() + 3
        while time.time() < deadline:
            try:
                buf += s.recv(4096)
                if b'VPCS>' in buf: break
            except socket.timeout:
                if b'VPCS>' in buf: break
        s.send(b'show ip\n')
        buf = b''
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                buf += s.recv(4096)
                if b'VPCS>' in buf: break
            except socket.timeout:
                if b'VPCS>' in buf: break
        s.close()
        out = buf.decode('ascii', errors='ignore')
        ip, gw, mac = None, None, None
        for line in out.splitlines():
            m = re.match(r'\s*IP/MASK\s*:\s*(\S+)', line)
            if m and not m.group(1).startswith('0.'): ip = m.group(1)
            m = re.match(r'\s*GATEWAY\s*:\s*(\S+)', line)
            if m and not m.group(1).startswith('0.'): gw = m.group(1)
            m = re.match(r'\s*MAC\s*:\s*(\S+)', line)
            if m: mac = m.group(1)
        status = "up" if ip else "no_ip"
        print(f"  ✅ {name}: {ip or 'no IP'}")
        return name, {"status": status, "ip": ip, "gateway": gw, "mac": mac}
    except Exception as e:
        print(f"  ❌ {name}: {e}")
        return name, {"status": "down", "error": str(e)}


# ── MAIN ───────────────────────────────────────────────

def main():
    print(f"\n{'='*55}")
    print(f"  CCIE Lab Monitor — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*55}")
    
    # Quick host check — skip entire poll if EVE-NG is off
    if not eveng_reachable():
        print("  ⏭  EVE-NG unreachable — lab is off, skipping poll")
        print("  Last status.json kept unchanged (dashboard shows last known state)")
        print(f"{'='*55}\n")
        return

    devices_status = {}
    futures = {}

    # Submit all polls in parallel
    with ThreadPoolExecutor(max_workers=16) as ex:
        for name, d in DEVICES.items():
            if d["type"] == "router":
                f = ex.submit(poll_router, name, d["port"], d.get("enable_pw"))
            else:
                f = ex.submit(poll_switch, name, d["port"])
            futures[f] = name
        for vpc_name, vpc_port in VPC_CONSOLES.items():
            f = ex.submit(poll_vpc, vpc_name, vpc_port)
            futures[f] = vpc_name
        
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
    print(f"  Result: {up}/{len(DEVICES)+len(VPC_CONSOLES)} nodes UP | {datetime.now().strftime('%H:%M:%S')}")
    print(f"{'='*55}\n")

if __name__ == "__main__":
    main()
