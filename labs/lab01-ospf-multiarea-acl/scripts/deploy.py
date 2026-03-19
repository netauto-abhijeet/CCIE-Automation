#!/usr/bin/env python3
"""
Lab01 - OSPF Multi-Area + ACL Deploy Script
============================================
Scenario: Branch Office Security Policy
  192.168.1.0/24  Sw5/VPC11  = IT/Admin      (Area 10)
  192.168.2.0/24  Sw6/VPC12  = HR            (Area 10)
  192.168.3.0/24  Sw7/VPC13  = Guest WiFi    (Area 10)
  192.168.4.0/24  Sw8/VPC14  = Finance       (Area 20)
  192.168.5.0/24  Sw9/VPC15  = Operations    (Area 20)
  192.168.6.0/24  Sw10/VPC16 = Servers       (Area 20)

ACL Policy:
  Standard ACL 10  → R4 Gi0/3 in  : Only IT can reach Servers
  Standard ACL 20  → R4 Gi0/1 in  : Only IT+HR can reach Finance
  Extended ACL 110 → R3 Gi0/3 in  : Guest blocked from ALL internal
  Extended ACL 120 → R3 Gi0/2 in  : HR blocked from Finance (192.168.4.0)
"""

from netmiko import ConnectHandler
from datetime import datetime
import time, sys, os

EVENG_IP = "192.168.1.100"

DEVICES = {
    "R1": {"port": 38727, "type": "router"},
    "R2": {"port": 54203, "type": "router"},
    "R3": {"port": 41967, "type": "router"},
    "R4": {"port": 33599, "type": "router"},
    "Sw5":  {"port": 46457, "type": "switch", "dhcp_net": "192.168.1.0", "gw": "192.168.1.1"},
    "Sw6":  {"port": 57373, "type": "switch", "dhcp_net": "192.168.2.0", "gw": "192.168.2.1"},
    "Sw7":  {"port": 48741, "type": "switch", "dhcp_net": "192.168.3.0", "gw": "192.168.3.1"},
    "Sw8":  {"port": 48381, "type": "switch", "dhcp_net": "192.168.4.0", "gw": "192.168.4.1"},
    "Sw9":  {"port": 34575, "type": "switch", "dhcp_net": "192.168.5.0", "gw": "192.168.5.1"},
    "Sw10": {"port": 49197, "type": "switch", "dhcp_net": "192.168.6.0", "gw": "192.168.6.1"},
}

ROUTER_CONFIGS = {
    "R1": [
        "hostname R1",
        "no ip domain-lookup",
        "username cisco privilege 15 secret cisco",
        "interface GigabitEthernet0/0",
        " description AREA0-to-R2",
        " ip address 12.0.0.1 255.255.255.0",
        " no shutdown",
        "interface GigabitEthernet0/1",
        " description AREA10-to-R3",
        " ip address 13.0.0.1 255.255.255.0",
        " no shutdown",
        "router ospf 10",
        " router-id 1.1.1.1",
        " network 12.0.0.0 0.0.0.255 area 0",
        " network 13.0.0.0 0.0.0.255 area 10",
        "line vty 0 4",
        " login local",
        " transport input telnet ssh",
    ],
    "R2": [
        "hostname R2",
        "no ip domain-lookup",
        "username cisco privilege 15 secret cisco",
        "interface GigabitEthernet0/0",
        " description AREA0-to-R1",
        " ip address 12.0.0.2 255.255.255.0",
        " no shutdown",
        "interface GigabitEthernet0/1",
        " description AREA20-to-R4",
        " ip address 24.0.0.2 255.255.255.0",
        " no shutdown",
        "router ospf 10",
        " router-id 2.2.2.2",
        " network 12.0.0.0 0.0.0.255 area 0",
        " network 24.0.0.0 0.0.0.255 area 20",
        "line vty 0 4",
        " login local",
        " transport input telnet ssh",
    ],
    "R3": [
        "hostname R3",
        "no ip domain-lookup",
        "username cisco privilege 15 secret cisco",
        "interface GigabitEthernet0/0",
        " description AREA10-to-R1",
        " ip address 13.0.0.3 255.255.255.0",
        " no shutdown",
        "interface GigabitEthernet0/1",
        " description IT-Admin-Sw5",
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
        "router ospf 10",
        " router-id 3.3.3.3",
        " network 13.0.0.0 0.0.0.255 area 10",
        " network 192.168.1.0 0.0.0.255 area 10",
        " network 192.168.2.0 0.0.0.255 area 10",
        " network 192.168.3.0 0.0.0.255 area 10",
        # Extended ACL 110 - Guest WiFi (Gi0/3 inbound)
        # Block Guest from ALL internal subnets
        "ip access-list extended 110",
        " remark === GUEST WIFI POLICY - Applied R3 Gi0/3 inbound ===",
        " deny   ip 192.168.3.0 0.0.0.255 192.168.1.0 0.0.0.255",
        " deny   ip 192.168.3.0 0.0.0.255 192.168.2.0 0.0.0.255",
        " deny   ip 192.168.3.0 0.0.0.255 192.168.4.0 0.0.0.255",
        " deny   ip 192.168.3.0 0.0.0.255 192.168.5.0 0.0.0.255",
        " deny   ip 192.168.3.0 0.0.0.255 192.168.6.0 0.0.0.255",
        " deny   ip 192.168.3.0 0.0.0.255 13.0.0.0 0.0.0.255",
        " deny   ip 192.168.3.0 0.0.0.255 24.0.0.0 0.0.0.255",
        " deny   ip 192.168.3.0 0.0.0.255 12.0.0.0 0.0.0.255",
        " permit ip any any",
        # Extended ACL 120 - HR (Gi0/2 inbound)
        # Block HR from reaching Finance (192.168.4.0)
        "ip access-list extended 120",
        " remark === HR POLICY - Applied R3 Gi0/2 inbound ===",
        " deny   ip 192.168.2.0 0.0.0.255 192.168.4.0 0.0.0.255",
        " deny   ip 192.168.2.0 0.0.0.255 192.168.6.0 0.0.0.255",
        " permit ip any any",
        "line vty 0 4",
        " login local",
        " transport input telnet ssh",
    ],
    "R4": [
        "hostname R4",
        "no ip domain-lookup",
        "username cisco privilege 15 secret cisco",
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
        " description Operations-Sw9",
        " ip address 192.168.5.1 255.255.255.0",
        " no shutdown",
        "interface GigabitEthernet0/3",
        " description Servers-Sw10",
        " ip address 192.168.6.1 255.255.255.0",
        " ip access-group 10 in",
        " no shutdown",
        "router ospf 10",
        " router-id 4.4.4.4",
        " network 24.0.0.0 0.0.0.255 area 20",
        " network 192.168.4.0 0.0.0.255 area 20",
        " network 192.168.5.0 0.0.0.255 area 20",
        " network 192.168.6.0 0.0.0.255 area 20",
        # Standard ACL 10 - Protect Servers (Gi0/3 inbound)
        # Only IT/Admin (192.168.1.0) can reach Servers
        "access-list 10 remark === SERVER PROTECTION - Applied R4 Gi0/3 inbound ===",
        "access-list 10 permit 192.168.1.0 0.0.0.255",
        "access-list 10 deny   any",
        # Standard ACL 20 - Protect Finance (Gi0/1 inbound)
        # Only IT (192.168.1.0) and HR (192.168.2.0) can reach Finance
        "access-list 20 remark === FINANCE PROTECTION - Applied R4 Gi0/1 inbound ===",
        "access-list 20 permit 192.168.1.0 0.0.0.255",
        "access-list 20 permit 192.168.2.0 0.0.0.255",
        "access-list 20 deny   any",
        "line vty 0 4",
        " login local",
        " transport input telnet ssh",
    ],
}

def connect_console(name, port):
    """Connect to device via EVE-NG telnet console"""
    device = {
        'device_type': 'cisco_ios_telnet',
        'host': EVENG_IP,
        'port': port,
        'username': '',
        'password': '',
        'secret': '',
        'timeout': 60,
        'global_delay_factor': 3,
        'session_log': f'/tmp/{name}_session.log',
    }
    return ConnectHandler(**device)

def push_config(name, port, commands, device_type):
    """Connect and push config to a device"""
    print(f"\n{'='*55}")
    print(f"  [{device_type.upper()}] {name}  →  {EVENG_IP}:{port}")
    print(f"{'='*55}")
    
    try:
        conn = connect_console(name, port)
        
        # Handle initial config dialog if present
        output = conn.send_command_timing("", delay_factor=2)
        if "initial configuration dialog" in output.lower():
            conn.send_command_timing("no\n", delay_factor=2)
        
        # Get into enable/config mode
        conn.send_command_timing("\n", delay_factor=1)
        conn.enable()
        
        # Push all commands
        output = conn.send_config_set(
            commands,
            cmd_verify=False,
            delay_factor=2,
            max_loops=1000,
        )
        
        # Save config
        conn.send_command_timing("end", delay_factor=1)
        save = conn.send_command_timing("write memory", delay_factor=3)
        conn.disconnect()
        
        print(f"  ✅ {name} — Config pushed & saved")
        return True
        
    except Exception as e:
        print(f"  ❌ {name} — FAILED: {e}")
        return False

def build_switch_commands(name, dhcp_net, gw):
    """Build switch config commands"""
    netmask = "255.255.255.0"
    return [
        f"hostname {name}",
        "no ip domain-lookup",
        "username cisco privilege 15 secret cisco",
        "ip routing",
        f"ip dhcp excluded-address {gw}",
        "ip dhcp pool LAN_POOL",
        f" network {dhcp_net} {netmask}",
        f" default-router {gw}",
        " dns-server 8.8.8.8",
        " lease 1",
        "interface GigabitEthernet0/0",
        " no switchport",
        f" ip address {gw} {netmask}",
        " no shutdown",
        "line vty 0 4",
        " login local",
        " transport input telnet ssh",
    ]

def main():
    start = datetime.now()
    print("\n" + "🚀 " * 20)
    print("  LAB01 - OSPF MULTI-AREA + ACL DEPLOYMENT")
    print("  Branch Office Security Policy")
    print("🚀 " * 20)
    
    results = {}
    
    # Deploy Routers
    print("\n📡 PHASE 1: Deploying Routers (IPs + OSPF + ACLs)")
    for name in ["R1", "R2", "R3", "R4"]:
        d = DEVICES[name]
        results[name] = push_config(name, d["port"], ROUTER_CONFIGS[name], "router")
        time.sleep(2)
    
    # Deploy Switches
    print("\n🔀 PHASE 2: Deploying Switches (DHCP Servers)")
    for name in ["Sw5", "Sw6", "Sw7", "Sw8", "Sw9", "Sw10"]:
        d = DEVICES[name]
        cmds = build_switch_commands(name, d["dhcp_net"], d["gw"])
        results[name] = push_config(name, d["port"], cmds, "switch")
        time.sleep(2)
    
    # Summary
    elapsed = (datetime.now() - start).seconds
    passed = sum(1 for v in results.values() if v)
    failed = sum(1 for v in results.values() if not v)
    
    print("\n" + "="*55)
    print("  📊 DEPLOYMENT SUMMARY")
    print("="*55)
    for device, status in results.items():
        icon = "✅" if status else "❌"
        dtype = DEVICES[device]["type"].upper()
        print(f"  {icon}  {device:<6}  [{dtype}]")
    print("="*55)
    print(f"  ✅ Passed: {passed}/10   ❌ Failed: {failed}/10")
    print(f"  ⏱  Time: {elapsed}s")
    print("="*55)
    
    print("\n📋 ACL POLICY APPLIED:")
    print("  Standard  ACL 10  → R4 Gi0/3 in  : Servers  — IT only")
    print("  Standard  ACL 20  → R4 Gi0/1 in  : Finance  — IT + HR only")
    print("  Extended  ACL 110 → R3 Gi0/3 in  : Guest    — blocked from all internal")
    print("  Extended  ACL 120 → R3 Gi0/2 in  : HR       — blocked from Finance + Servers")
    
    print("\n📋 VERIFY COMMANDS (run on routers after deploy):")
    print("  show ip ospf neighbor          ← check OSPF adjacencies")
    print("  show ip route ospf             ← check OSPF routes")
    print("  show access-lists              ← check ACL hit counts")
    print("  show ip interface gi0/3        ← check ACL applied on interface")

if __name__ == '__main__':
    main()
