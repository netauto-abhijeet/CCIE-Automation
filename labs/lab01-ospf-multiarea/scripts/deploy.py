#!/usr/bin/env python3
"""
Lab01 - OSPF Multi-Area Deploy Script
Connects via telnet console to each device and pushes config
"""

from nornir import InitNornir
from nornir_netmiko.tasks import netmiko_send_config
from nornir_utils.plugins.functions import print_result
from netmiko import ConnectHandler
import yaml, os

LAB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def deploy_router(host_name, host_data, group_data):
    """Push config to a router via telnet console"""
    print(f"\n{'='*50}")
    print(f"Connecting to {host_name} via telnet {host_data['hostname']}:{host_data['port']}")
    
    device = {
        'device_type': 'cisco_ios_telnet',
        'host': host_data['hostname'],
        'port': host_data['port'],
        'username': '',
        'password': '',
        'secret': 'cisco',
        'timeout': 30,
        'global_delay_factor': 2,
    }
    
    # Build config commands
    commands = [
        f"hostname {host_name}",
        "no ip domain-lookup",
        "username cisco privilege 15 secret cisco",
        "line vty 0 4",
        " login local",
        " transport input telnet",
        "exit",
    ]
    
    # Add interface IPs based on role
    d = host_data.get('data', {})
    
    if host_name == 'R1':
        commands += [
            "interface GigabitEthernet0/0",
            " ip address 12.0.0.1 255.255.255.0", " no shutdown", "exit",
            "interface GigabitEthernet0/1",
            " ip address 13.0.0.1 255.255.255.0", " no shutdown", "exit",
            "router ospf 10",
            " network 12.0.0.0 0.0.0.255 area 0",
            " network 13.0.0.0 0.0.0.255 area 10", "exit",
        ]
    elif host_name == 'R2':
        commands += [
            "interface GigabitEthernet0/0",
            " ip address 12.0.0.2 255.255.255.0", " no shutdown", "exit",
            "interface GigabitEthernet0/1",
            " ip address 24.0.0.2 255.255.255.0", " no shutdown", "exit",
            "router ospf 10",
            " network 12.0.0.0 0.0.0.255 area 0",
            " network 24.0.0.0 0.0.0.255 area 20", "exit",
        ]
    elif host_name == 'R3':
        commands += [
            "interface GigabitEthernet0/0",
            " ip address 13.0.0.3 255.255.255.0", " no shutdown", "exit",
            "interface GigabitEthernet0/1",
            " ip address 192.168.1.1 255.255.255.0", " no shutdown", "exit",
            "interface GigabitEthernet0/2",
            " ip address 192.168.2.1 255.255.255.0", " no shutdown", "exit",
            "interface GigabitEthernet0/3",
            " ip address 192.168.3.1 255.255.255.0", " no shutdown", "exit",
            "router ospf 10",
            " network 13.0.0.0 0.0.0.255 area 10",
            " network 192.168.1.0 0.0.0.255 area 10",
            " network 192.168.2.0 0.0.0.255 area 10",
            " network 192.168.3.0 0.0.0.255 area 10", "exit",
        ]
    elif host_name == 'R4':
        commands += [
            "interface GigabitEthernet0/0",
            " ip address 24.0.0.4 255.255.255.0", " no shutdown", "exit",
            "interface GigabitEthernet0/1",
            " ip address 192.168.4.1 255.255.255.0", " no shutdown", "exit",
            "interface GigabitEthernet0/2",
            " ip address 192.168.5.1 255.255.255.0", " no shutdown", "exit",
            "interface GigabitEthernet0/3",
            " ip address 192.168.6.1 255.255.255.0", " no shutdown", "exit",
            "router ospf 10",
            " network 24.0.0.0 0.0.0.255 area 20",
            " network 192.168.4.0 0.0.0.255 area 20",
            " network 192.168.5.0 0.0.0.255 area 20",
            " network 192.168.6.0 0.0.0.255 area 20", "exit",
        ]
    
    commands.append("end")
    commands.append("write memory")
    
    try:
        net_connect = ConnectHandler(**device)
        net_connect.enable()
        output = net_connect.send_config_set(commands, cmd_verify=False)
        net_connect.disconnect()
        print(f"✅ {host_name} - Config pushed successfully")
        return True
    except Exception as e:
        print(f"❌ {host_name} - Failed: {e}")
        return False


def deploy_switch(host_name, host_data):
    """Push config to a switch via telnet console"""
    print(f"\n{'='*50}")
    print(f"Connecting to {host_name} via telnet {host_data['hostname']}:{host_data['port']}")
    
    d = host_data.get('data', {})
    pool = d.get('dhcp_pool', '')
    gw = d.get('gateway', '')
    
    # Parse network from CIDR
    parts = pool.split('/')
    network = parts[0]
    prefix = int(parts[1]) if len(parts) > 1 else 24
    
    # Convert prefix to netmask
    import ipaddress
    net = ipaddress.IPv4Network(pool, strict=False)
    netmask = str(net.netmask)
    
    device = {
        'device_type': 'cisco_ios_telnet',
        'host': host_data['hostname'],
        'port': host_data['port'],
        'username': '',
        'password': '',
        'secret': 'cisco',
        'timeout': 30,
        'global_delay_factor': 2,
    }
    
    commands = [
        f"hostname {host_name}",
        "no ip domain-lookup",
        "username cisco privilege 15 secret cisco",
        f"ip dhcp excluded-address {gw}",
        "ip dhcp pool LAN_POOL",
        f" network {network} {netmask}",
        f" default-router {gw}",
        " dns-server 8.8.8.8",
        " lease 1",
        "exit",
        "interface GigabitEthernet0/0",
        " no switchport",
        f" ip address {gw} {netmask}",
        " no shutdown",
        "exit",
        "line vty 0 4",
        " login local",
        " transport input telnet",
        "exit",
        "end",
        "write memory",
    ]
    
    try:
        net_connect = ConnectHandler(**device)
        net_connect.enable()
        output = net_connect.send_config_set(commands, cmd_verify=False)
        net_connect.disconnect()
        print(f"✅ {host_name} - Config pushed successfully")
        return True
    except Exception as e:
        print(f"❌ {host_name} - Failed: {e}")
        return False


if __name__ == '__main__':
    print("🚀 Lab01 - OSPF Multi-Area Deployment")
    print("=" * 50)
    
    with open(f"{LAB_DIR}/inventory/hosts.yaml") as f:
        hosts = yaml.safe_load(f)
    
    routers = ['R1', 'R2', 'R3', 'R4']
    switches = ['Sw5', 'Sw6', 'Sw7', 'Sw8', 'Sw9', 'Sw10']
    
    results = {}
    
    print("\n📡 Deploying Routers...")
    for r in routers:
        results[r] = deploy_router(r, hosts[r], {})
    
    print("\n🔀 Deploying Switches...")
    for s in switches:
        results[s] = deploy_switch(s, hosts[s])
    
    print("\n" + "=" * 50)
    print("📊 DEPLOYMENT SUMMARY")
    print("=" * 50)
    for device, status in results.items():
        icon = "✅" if status else "❌"
        print(f"  {icon} {device}")
