#!/usr/bin/env python3
"""
Lab01 - OSPF Multi-Area + ACL Deploy Script
============================================
Scenario: Branch Office Security Policy

Topology:
  Area 0 (backbone): R1 (12.0.0.1) ↔ R2 (12.0.0.2) via 12.0.0.0/24
  Area 10:           R1 (13.0.0.1) ↔ R3 (13.0.0.3) via 13.0.0.0/24
  Area 20:           R2 (24.0.0.2) ↔ R4 (24.0.0.4) via 24.0.0.0/24

Access Networks (Area 10 — R3 serves DHCP):
  192.168.1.0/24  R3 Gi0/1 → Sw5 → VPC11  = IT/Admin
  192.168.2.0/24  R3 Gi0/2 → Sw6 → VPC12  = HR
  192.168.3.0/24  R3 Gi0/3 → Sw7 → VPC13  = Guest WiFi

Access Networks (Area 20 — R4 serves DHCP):
  192.168.4.0/24  R4 Gi0/1 → Sw8 → VPC14  = Finance
  192.168.5.0/24  R4 Gi0/2 → Sw9 → VPC15  = Servers/Operations
  192.168.6.0/24  R4 Gi0/3 → Sw10 → VPC16 = MGMT

Security Policy (ACLs):
  Standard ACL 10  → R4 Gi0/3 in  : Only IT (192.168.1.0) can reach MGMT
  Standard ACL 20  → R4 Gi0/1 in  : Only IT + HR can reach Finance
  Extended ACL 110 → R3 Gi0/3 in  : Guest blocked from IT_ADMIN (192.168.1.0)
  Extended ACL 120 → R3 Gi0/2 in  : HR blocked from Finance + MGMT Area20

Design Principles:
  - Switches are PURE L2 (no IP addresses, no routing, no DHCP)
  - DHCP pools run on routers (R3 for Area 10, R4 for Area 20)
  - Extended ACLs applied near SOURCE (R3 outbound subnets)
  - Standard ACLs applied near DESTINATION (R4 inbound to servers)

Telnet Access (via EVE-NG console ports):
  R1:38727, R2:54203, R3:41967, R4:33599
  Sw5:46457, Sw6:57373, Sw7:48741, Sw8:48381, Sw9:34575, Sw10:49197

IMPORTANT: Use socket with proper telnet IAC negotiation + \\r\\n line endings.
           telnetlib with just \\n does NOT work reliably for these vIOS devices.
"""

import socket
import time
import sys
from datetime import datetime

EVENG_IP = "192.168.1.100"

DEVICES = {
    "R1":  {"port": 38727, "type": "router"},
    "R2":  {"port": 54203, "type": "router"},
    "R3":  {"port": 41967, "type": "router"},
    "R4":  {"port": 33599, "type": "router"},
    "Sw5": {"port": 46457, "type": "switch"},
    "Sw6": {"port": 57373, "type": "switch"},
    "Sw7": {"port": 48741, "type": "switch"},
    "Sw8": {"port": 48381, "type": "switch"},
    "Sw9": {"port": 34575, "type": "switch"},
    "Sw10":{"port": 49197, "type": "switch"},
}

# ─────────────────────────────────────────────────
# ROUTER CONFIGURATIONS
# ─────────────────────────────────────────────────
ROUTER_CONFIGS = {

    "R1": [
        "hostname R1",
        "no ip domain-lookup",
        "no logging console",
        # Interfaces
        "interface GigabitEthernet0/0",
        " description AREA0-to-R2",
        " ip address 12.0.0.1 255.255.255.0",
        " no shutdown",
        "interface GigabitEthernet0/1",
        " description AREA10-to-R3",
        " ip address 13.0.0.1 255.255.255.0",
        " no shutdown",
        # OSPF
        "router ospf 10",
        " router-id 1.1.1.1",
        " network 12.0.0.0 0.0.0.255 area 0",
        " network 13.0.0.0 0.0.0.255 area 10",
    ],

    "R2": [
        "hostname R2",
        "no ip domain-lookup",
        "no logging console",
        # Interfaces
        "interface GigabitEthernet0/0",
        " description AREA0-to-R1",
        " ip address 12.0.0.2 255.255.255.0",
        " no shutdown",
        "interface GigabitEthernet0/1",
        " description AREA20-to-R4",
        " ip address 24.0.0.2 255.255.255.0",
        " no shutdown",
        # OSPF
        "router ospf 10",
        " router-id 2.2.2.2",
        " network 12.0.0.0 0.0.0.255 area 0",
        " network 24.0.0.0 0.0.0.255 area 20",
    ],

    "R3": [
        "hostname R3",
        "no ip domain-lookup",
        "no logging console",
        # Interfaces
        "interface GigabitEthernet0/0",
        " description AREA10-to-R1",
        " ip address 13.0.0.3 255.255.255.0",
        " no shutdown",
        "interface GigabitEthernet0/1",
        " description IT_ADMIN-Sw5",
        " ip address 192.168.1.1 255.255.255.0",
        " no shutdown",
        "interface GigabitEthernet0/2",
        " description HR-Sw6",
        " ip address 192.168.2.1 255.255.255.0",
        " ip access-group 120 in",
        " no shutdown",
        "interface GigabitEthernet0/3",
        " description Guest-Sw7",
        " ip address 192.168.3.1 255.255.255.0",
        " ip access-group 110 in",
        " no shutdown",
        # OSPF
        "router ospf 10",
        " network 13.0.0.0 0.0.0.255 area 10",
        " network 192.168.1.0 0.0.0.255 area 10",
        " network 192.168.2.0 0.0.0.255 area 10",
        " network 192.168.3.0 0.0.0.255 area 10",
        # DHCP for Area 10
        "ip dhcp excluded-address 192.168.1.1",
        "ip dhcp excluded-address 192.168.2.1",
        "ip dhcp excluded-address 192.168.3.1",
        "ip dhcp pool IT_ADMIN",
        " network 192.168.1.0 255.255.255.0",
        " default-router 192.168.1.1",
        " dns-server 8.8.8.8 8.8.4.4",
        " lease 1",
        "ip dhcp pool HR",
        " network 192.168.2.0 255.255.255.0",
        " default-router 192.168.2.1",
        " dns-server 8.8.8.8 8.8.4.4",
        " lease 1",
        "ip dhcp pool GUEST",
        " network 192.168.3.0 255.255.255.0",
        " default-router 192.168.3.1",
        " dns-server 8.8.8.8",
        " lease 1",
        # Extended ACLs (near source)
        "ip access-list extended 110",
        " remark GUEST blocked from IT_ADMIN",
        " deny ip 192.168.3.0 0.0.0.255 192.168.1.0 0.0.0.255",
        " permit ip any any",
        "ip access-list extended 120",
        " remark HR blocked from Finance and MGMT",
        " deny ip 192.168.2.0 0.0.0.255 192.168.4.0 0.0.0.255",
        " deny ip 192.168.2.0 0.0.0.255 192.168.6.0 0.0.0.255",
        " permit ip any any",
    ],

    "R4": [
        "hostname R4",
        "no ip domain-lookup",
        "no logging console",
        # Interfaces
        "interface GigabitEthernet0/0",
        " description AREA20-to-R2",
        " ip address 24.0.0.4 255.255.255.0",
        " no shutdown",
        "interface GigabitEthernet0/1",
        " description Finance-Sw8",
        " ip address 192.168.4.1 255.255.255.0",
        " ip access-group 20 in",
        " no shutdown",
        "interface GigabitEthernet0/2",
        " description Servers-Sw9",
        " ip address 192.168.5.1 255.255.255.0",
        " no shutdown",
        "interface GigabitEthernet0/3",
        " description MGMT-Sw10",
        " ip address 192.168.6.1 255.255.255.0",
        " ip access-group 10 in",
        " no shutdown",
        # OSPF
        "router ospf 10",
        " network 24.0.0.0 0.0.0.255 area 20",
        " network 192.168.4.0 0.0.0.255 area 20",
        " network 192.168.5.0 0.0.0.255 area 20",
        " network 192.168.6.0 0.0.0.255 area 20",
        # DHCP for Area 20
        "ip dhcp excluded-address 192.168.4.1",
        "ip dhcp excluded-address 192.168.5.1",
        "ip dhcp excluded-address 192.168.6.1",
        "ip dhcp pool FINANCE",
        " network 192.168.4.0 255.255.255.0",
        " default-router 192.168.4.1",
        " dns-server 8.8.8.8 8.8.4.4",
        " lease 1",
        "ip dhcp pool SERVERS",
        " network 192.168.5.0 255.255.255.0",
        " default-router 192.168.5.1",
        " dns-server 8.8.8.8 8.8.4.4",
        " lease 1",
        "ip dhcp pool MGMT",
        " network 192.168.6.0 255.255.255.0",
        " default-router 192.168.6.1",
        " dns-server 8.8.8.8 8.8.4.4",
        " lease 1",
        # Standard ACLs (near destination)
        "access-list 10 remark === MGMT PROTECTION: Only IT allowed ===",
        "access-list 10 permit 192.168.1.0 0.0.0.255",
        "access-list 10 deny   any",
        "access-list 20 remark === FINANCE PROTECTION: IT + HR allowed ===",
        "access-list 20 permit 192.168.1.0 0.0.0.255",
        "access-list 20 permit 192.168.2.0 0.0.0.255",
        "access-list 20 deny   any",
    ],
}

# ─────────────────────────────────────────────────
# SWITCH CONFIGURATION (Pure L2)
# ─────────────────────────────────────────────────
SWITCH_CONFIG_BASE = [
    "no ip routing",
    "spanning-tree mode rapid-pvst",
    "interface GigabitEthernet0/0",
    " switchport",
    " no shutdown",
    "interface GigabitEthernet0/1",
    " switchport",
    " no shutdown",
    "interface GigabitEthernet0/2",
    " switchport",
    " no shutdown",
    "interface GigabitEthernet0/3",
    " switchport",
    " no shutdown",
    "interface GigabitEthernet1/0",
    " switchport",
    " no shutdown",
    "interface GigabitEthernet1/1",
    " switchport",
    " no shutdown",
    "interface GigabitEthernet1/2",
    " switchport",
    " no shutdown",
    "interface GigabitEthernet1/3",
    " switchport",
    " no shutdown",
]

SWITCH_CONFIGS = {
    "Sw5":  ["hostname Sw5"]  + SWITCH_CONFIG_BASE,
    "Sw6":  ["hostname Sw6"]  + SWITCH_CONFIG_BASE,
    "Sw7":  ["hostname Sw7"]  + SWITCH_CONFIG_BASE,
    "Sw8":  ["hostname Sw8"]  + SWITCH_CONFIG_BASE,
    "Sw9":  ["hostname Sw9"]  + SWITCH_CONFIG_BASE,
    "Sw10": ["hostname Sw10"] + SWITCH_CONFIG_BASE,
}


# ─────────────────────────────────────────────────
# TELNET ENGINE (Socket-based with IAC negotiation)
# ─────────────────────────────────────────────────
IAC_RESPONSE = bytes([
    0xff, 0xfd, 0x01,   # IAC DO ECHO
    0xff, 0xfd, 0x03,   # IAC DO SUPPRESS GO AHEAD
    0xff, 0xfd, 0x00,   # IAC DO BINARY
    0xff, 0xfb, 0x00,   # IAC WILL BINARY
])

def connect(host, port, timeout=20):
    """Connect and negotiate telnet options."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.settimeout(2)
    time.sleep(1)
    try: s.recv(4096)
    except: pass
    s.send(IAC_RESPONSE)
    time.sleep(1)
    try: s.recv(4096)
    except: pass
    return s

def read_all(s, wait=2):
    """Read all available data from socket."""
    time.sleep(wait)
    out = b''
    while True:
        try:
            chunk = s.recv(4096)
            out += chunk
            time.sleep(0.2)
        except socket.timeout:
            break
    return out.decode('ascii', errors='ignore')

def send_cmd(s, cmd, wait=1.2):
    """Send a single command and read response."""
    s.send(cmd.encode() + b'\r\n')
    return read_all(s, wait)

def enable_device(s):
    """Get device into privileged exec mode."""
    # Wake
    send_cmd(s, '', 0.5)
    # Send enable
    out = send_cmd(s, 'enable', 1.5)
    if 'Password' in out:
        # Try empty password first, then 'admin'
        out2 = send_cmd(s, '', 1.5)
        if 'Bad secrets' in out2 or 'Password' in out2:
            out3 = send_cmd(s, 'admin', 1.5)
            if '#' not in out3:
                send_cmd(s, 'cisco', 1.5)
    # Confirm mode
    send_cmd(s, 'terminal length 0', 0.8)

def push_config(s, commands, delay=0.8):
    """Push config commands in global config mode."""
    send_cmd(s, 'conf t', 1.0)
    for cmd in commands:
        out = send_cmd(s, cmd, delay)
        # If we got kicked out of config mode somehow, re-enter
        if '#' in out and 'config' not in out and cmd.startswith('interface'):
            send_cmd(s, 'conf t', 1.0)
            send_cmd(s, cmd, delay)
    send_cmd(s, 'end', 1.0)

def save_config(s):
    """Save running config to NVRAM."""
    s.send(b'write memory\r\n')
    time.sleep(8)
    out = read_all(s, 1)
    return '[OK]' in out or 'OK' in out


# ─────────────────────────────────────────────────
# MAIN DEPLOY LOGIC
# ─────────────────────────────────────────────────
def deploy_device(name, port, config_cmds):
    """Deploy config to a single device. Returns (success, message)."""
    print(f"\n{'='*60}")
    print(f"  Deploying: {name} (port {port})")
    print(f"{'='*60}")
    try:
        s = connect(EVENG_IP, port)
        enable_device(s)
        push_config(s, config_cmds)
        saved = save_config(s)
        s.close()
        status = "✅ SAVED" if saved else "⚠️  NOT SAVED"
        print(f"  {name}: {status}")
        return True, status
    except Exception as e:
        print(f"  {name}: ❌ ERROR - {e}")
        return False, str(e)


def main():
    print("\n" + "="*60)
    print("  LAB01 OSPF MULTI-AREA + ACL DEPLOY")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60)

    results = {}

    # Phase 1: Routers
    print("\n[PHASE 1] Configuring Routers (R1 → R4)")
    for name in ["R1", "R2", "R3", "R4"]:
        dev = DEVICES[name]
        config = ROUTER_CONFIGS[name]
        ok, msg = deploy_device(name, dev["port"], config)
        results[name] = (ok, msg)

    # Phase 2: Switches  
    print("\n[PHASE 2] Configuring Switches (Sw5 → Sw10, Pure L2)")
    for name in ["Sw5", "Sw6", "Sw7", "Sw8", "Sw9", "Sw10"]:
        dev = DEVICES[name]
        config = SWITCH_CONFIGS[name]
        ok, msg = deploy_device(name, dev["port"], config)
        results[name] = (ok, msg)

    # Summary
    print("\n" + "="*60)
    print("  DEPLOY SUMMARY")
    print("="*60)
    all_ok = True
    for name, (ok, msg) in results.items():
        icon = "✅" if ok else "❌"
        print(f"  {icon} {name:6s}: {msg}")
        if not ok:
            all_ok = False

    print(f"\n  {'ALL DEVICES DEPLOYED SUCCESSFULLY' if all_ok else 'SOME DEVICES FAILED'}")
    print(f"  Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60)
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
