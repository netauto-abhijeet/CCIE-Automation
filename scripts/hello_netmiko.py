#!/usr/bin/env python3
"""
Sample Netmiko script - connect to a device and run a command.
Replace host/credentials with your lab device.
"""
from netmiko import ConnectHandler

device = {
    'device_type': 'cisco_ios',
    'host': '192.168.1.1',    # <-- change to your device IP
    'username': 'cisco',
    'password': 'cisco',
}

with ConnectHandler(**device) as conn:
    output = conn.send_command('show version')
    print(output)
