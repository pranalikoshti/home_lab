# Attack Scenarios and Results

All four attacks were run against pfSense (`192.168.100.1`) from Kali Linux (`192.168.100.14`). 
Times are from the lab run on July 10, 2026.

## Attack Results - Real Timings, Real Detections

| Attack | MITRE | Tool | Start time | First Suricata alert | MTTD | Detected |
|--------|-------|------|------------|----------------------|------|----------|
| Aggressive nmap scan | T1046 | `nmap -sS -sV -O` | 15:17:00 | 15:17:55 | 55 sec | Yes |
| Slow nmap scan | T1046 | `nmap -sS -T1 --scan-delay 5s` | 15:19:15 | - | Never | No (gap) |
| SSH brute force | T1110 | Hydra 241 tries/min | 15:38:54 | 15:39:11 | 17 sec | Yes |
| Web vulnerability scan | T1190 | Nikto | 15:43:14 | 15:43:20 | 6 sec | Yes |

* **Fastest detection:** Web scan at 6 seconds MTTD.
* **Slowest detection:** Aggressive nmap at 55 seconds MTTD.
* **Not detected:** Slow nmap - 0 Suricata alerts despite attack completing.

## Suricata Signatures Triggered

Real CVE-referenced signatures that fired during the Nikto web scan from the Emerging Threats rule set:

| Signature | CVE | Category |
|-----------|-----|----------|
| ET EXPLOIT Cisco ASA and Firepower Path Traversal | CVE-2020-3452 | Attempted Administrator Privilege Gain |
| ET EXPLOIT Cisco ASA/Firepower Unauthenticated File Read M3 | CVE-2020-3452 | Attempted User Privilege Gain |
| ET EXPLOIT F5 TMUI RCE vulnerability Attempt M1 | CVE-2020-5902 | Attempted Administrator Privilege Gain |
| ET EXPLOIT F5 TMUI RCE vulnerability Attempt M2 | CVE-2020-5902 | Attempted Administrator Privilege Gain |
| ET EXPLOIT Citrix Application Delivery | - | Attempted Administrator Privilege Gain |
| SURICATA HTTP Host header ambiguous | - | Generic Protocol Command Decode |
