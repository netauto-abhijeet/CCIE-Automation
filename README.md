# CCIE Automation - Workspace

## Structure
```
labs/                        # One folder per lab - fully self-contained
  lab01-ospf-multiarea/      # OSPF 10 multi-area topology
    inventory/               # Device list and credentials
    templates/               # Jinja2 config templates
    configs/                 # Generated configs (auto-created)
    scripts/                 # deploy.py and other scripts
    README.md                # Lab description and instructions

assignments/                 # One folder per assignment
  assignment01-netmiko-basics/

notes/                       # Study notes (shared)
common/                      # Shared utilities reused across labs
```

## Quick Start
```bash
# Deploy Lab 01
cd labs/lab01-ospf-multiarea
python3 scripts/deploy.py
```
