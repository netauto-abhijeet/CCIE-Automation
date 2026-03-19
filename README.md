# CCIE Automation Class - Workspace

## Directory Structure
- **labs/**        → Lab exercises from class
- **assignments/** → Homework and assignments
- **scripts/**     → Python scripts and tools
- **configs/**     → Device configuration files
- **templates/**   → Jinja2 templates for config generation
- **inventory/**   → Device inventory (hosts.yaml, groups.yaml)
- **notes/**       → Study notes and documentation

## Quick Start
```bash
cd ~/CCIE-Automation
python3 script.py
```

## Key Packages Installed
- netmiko   — SSH to network devices (Cisco, Juniper, Arista...)
- napalm    — Multi-vendor network automation
- nornir    — Network automation framework
- pyats     — Cisco pyATS testing framework
- genie     — Cisco Genie parsers
- jinja2    — Config template engine
- ntc-templates — TextFSM templates for show commands
- ciscoconfparse — Parse/audit Cisco configs
- scapy     — Packet crafting
- ansible   — (install separately if needed)
