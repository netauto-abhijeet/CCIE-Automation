# Lab 01 - OSPF Multi-Area + ACL

## Scenario: Branch Office Security Policy

| Network | Switch | VPC | Department | Zone |
|---------|--------|-----|-----------|------|
| 192.168.1.0/24 | Sw5 | VPC11 | IT/Admin | Area 10 |
| 192.168.2.0/24 | Sw6 | VPC12 | HR | Area 10 |
| 192.168.3.0/24 | Sw7 | VPC13 | Guest WiFi | Area 10 |
| 192.168.4.0/24 | Sw8 | VPC14 | Finance | Area 20 |
| 192.168.5.0/24 | Sw9 | VPC15 | Operations | Area 20 |
| 192.168.6.0/24 | Sw10 | VPC16 | Servers | Area 20 |

## OSPF Design
- **Process:** OSPF 10
- **Area 0:** R1 ↔ R2 (12.0.0.0/24)
- **Area 10:** R1 ↔ R3 (13.0.0.0/24) — IT, HR, Guest LANs
- **Area 20:** R2 ↔ R4 (24.0.0.0/24) — Finance, Ops, Servers LANs

## ACL Policy
| ACL | Type | Applied | Policy |
|-----|------|---------|--------|
| 10  | Standard | R4 Gi0/3 in | Only IT can reach Servers |
| 20  | Standard | R4 Gi0/1 in | Only IT+HR can reach Finance |
| 110 | Extended | R3 Gi0/3 in | Guest blocked from all internal networks |
| 120 | Extended | R3 Gi0/2 in | HR blocked from Finance and Servers |

## Traffic Matrix
```
         IT   HR  Guest Finance  Ops  Servers
IT     →  ✅   ✅   ✅    ✅      ✅    ✅
HR     →  ✅   ✅   ✅    ❌      ✅    ❌
Guest  →  ❌   ❌   ✅    ❌      ❌    ❌
Finance→  ✅   ✅   ❌    ✅      ✅    ✅
Ops    →  ✅   ✅   ❌    ✅      ✅    ✅
Servers→  ✅   ✅   ❌    ✅      ✅    ✅
```

## How to Deploy
```bash
cd labs/lab01-ospf-multiarea-acl
python3 scripts/deploy.py
```

## How to Verify
```
R1# show ip ospf neighbor
R3# show access-lists
R4# show access-lists
R3# show ip interface gi0/3   (ACL 110 on Guest)
R4# show ip interface gi0/3   (ACL 10 on Servers)
```

## Console Ports (EVE-NG telnet)
| Device | Port | Role |
|--------|------|------|
| R1 | 38727 | ABR Area0/Area10 |
| R2 | 54203 | ABR Area0/Area20 |
| R3 | 41967 | Internal Area10 + ACL enforcement |
| R4 | 33599 | Internal Area20 + ACL enforcement |
| Sw5 | 46457 | IT DHCP 192.168.1.0/24 |
| Sw6 | 57373 | HR DHCP 192.168.2.0/24 |
| Sw7 | 48741 | Guest DHCP 192.168.3.0/24 |
| Sw8 | 48381 | Finance DHCP 192.168.4.0/24 |
| Sw9 | 34575 | Operations DHCP 192.168.5.0/24 |
| Sw10 | 49197 | Servers DHCP 192.168.6.0/24 |
