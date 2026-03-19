# Lab 01 - OSPF Multi-Area

## Topology
- **OSPF Process:** 10
- **Area 0:** R1 ↔ R2 (12.0.0.0/24)
- **Area 10:** R1 ↔ R3 (13.0.0.0/24) → Sw5,Sw6,Sw7 → VPC11,12,13
- **Area 20:** R2 ↔ R4 (24.0.0.0/24) → Sw8,Sw9,Sw10 → VPC14,15,16

## Device Access (console via EVE-NG telnet)
| Device | Telnet Port |
|--------|-------------|
| R1 | 192.168.1.100:38727 |
| R2 | 192.168.1.100:54203 |
| R3 | 192.168.1.100:41967 |
| R4 | 192.168.1.100:33599 |
| Sw5 | 192.168.1.100:46457 |
| Sw6 | 192.168.1.100:57373 |
| Sw7 | 192.168.1.100:48741 |
| Sw8 | 192.168.1.100:48381 |
| Sw9 | 192.168.1.100:34575 |
| Sw10 | 192.168.1.100:49197 |

## How to Deploy
```bash
cd labs/lab01-ospf-multiarea
python3 scripts/deploy.py
```

## How to Verify
After deploy, connect to any router and run:
```
show ip ospf neighbor
show ip route ospf
```
