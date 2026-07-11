# Home Lab: Network Defense
# pfSense + Suricata + Splunk

**Author:** Pranali Koshti | MS MIS, University at Buffalo, May 2026
**Stack:** pfSense CE 2.7 · Suricata 7 · Splunk Free · Kali Linux
**Platform:** VirtualBox 7 on Windows 11 (8 GB RAM)
**Cost:** $0

---

## Overview

A segmented virtual network security lab simulating enterprise network
defense. pfSense handles stateful firewall and routing. Suricata runs
signature-based IDS with Emerging Threats Open rule sets. All firewall
events and IDS alerts forward to Splunk via syslog UDP 514 for real-time
detection and dashboarding. Attacks simulated from Kali Linux with all
findings documented including a verified detection gap.

---

## Architecture

```
[Windows 11 host — 192.168.1.51]
  Splunk Free (localhost:8000)
    UDP 514 input receiving pfSense syslog

[VirtualBox]
  pfSense VM (WAN: 192.168.1.225, LAN: 192.168.100.1)
    Suricata IDS on LAN interface (em1)
    Emerging Threats Open rules (updated July 2026)
    Remote syslog forwarding to 192.168.1.51:514

  Kali Linux VM (192.168.100.14)
    Internal network: labnet (192.168.100.0/24)
    Tools: nmap, Hydra, Nikto
```

---

## Attack results - real timings, real detections

All four attacks were run against pfSense (192.168.100.1) from
Kali Linux (192.168.100.14). Times are from the lab run on July 10 2026.

| Attack | MITRE | Tool | Start time | First Suricata alert | MTTD | Detected |
|--------|-------|------|------------|----------------------|------|----------|
| Aggressive nmap scan | T1046 | nmap -sS -sV -O | 15:17:00 | 15:17:55 | 55 sec | Yes |
| Slow nmap scan | T1046 | nmap -sS -T1 --scan-delay 5s | 15:19:15 | - | Never | No (gap) |
| SSH brute force | T1110 | Hydra 241 tries/min | 15:38:54 | 15:39:11 | 17 sec | Yes |
| Web vulnerability scan | T1190 | Nikto | 15:43:14 | 15:43:20 | 6 sec | Yes |

**Fastest detection:** Web scan at 6 seconds MTTD.
**Slowest detection:** Aggressive nmap at 55 seconds MTTD.
**Not detected:** Slow nmap - 0 Suricata alerts despite attack completing.

---

## Key finding: the detection gap

### What happened

The slow nmap scan (nmap -sS -T1 --scan-delay 5s -p 1-100) completed
fully against pfSense. Every probe was logged by the pfSense firewall.
Suricata generated zero alerts.

The aggressive nmap scan with identical targets fired Suricata alerts
within 55 seconds.

The only difference: 5 seconds between probes instead of milliseconds.

### Why it happened

Suricata's Emerging Threats scan rules use threshold detection:
fire if X events occur within Y seconds. A 5-second delay between
probes means the connection rate never crosses any threshold.

The attack and the detection gap are two separate concepts:
- The attack still happened
- The firewall still logged every packet
- Suricata had no signature that matched the behavioral pattern

### How it was detected anyway

pfSense firewall logs showed traffic from 192.168.100.14 touching
multiple destination ports over the attack window. The Splunk behavioral
query below detected this without any Suricata signature.

### Remediation

A behavioral SPL query using distinct port count per source IP per
minute catches the slow scan regardless of connection rate:

```
index=pfsense "192.168.100.14,192.168.100.1"
| rex field=_raw ",(?:tcp|udp),\d+,192\.168\.100\.14,192\.168\.100\.1,\d+,(?P<dst_port>\d+),"
| bin _time span=1m
| stats dc(dst_port) as unique_ports, count by _time
| sort -_time
```

Any source IP touching more than 20 unique destination ports in one
minute is flagged regardless of the time between individual probes.
This query is saved as a scheduled alert in the lab Splunk instance.

---

## Suricata signatures triggered

Real CVE-referenced signatures that fired during the Nikto web scan:

| Signature | CVE | Category |
|-----------|-----|----------|
| ET EXPLOIT Cisco ASA and Firepower Path Traversal | CVE-2020-3452 | Attempted Administrator Privilege Gain |
| ET EXPLOIT Cisco ASA/Firepower Unauthenticated File Read M3 | CVE-2020-3452 | Attempted User Privilege Gain |
| ET EXPLOIT F5 TMUI RCE vulnerability Attempt M1 | CVE-2020-5902 | Attempted Administrator Privilege Gain |
| ET EXPLOIT F5 TMUI RCE vulnerability Attempt M2 | CVE-2020-5902 | Attempted Administrator Privilege Gain |
| ET EXPLOIT Citrix Application Delivery | - | Attempted Administrator Privilege Gain |
| SURICATA HTTP Host header ambiguous | - | Generic Protocol Command Decode |

These are real CVE signatures from the Emerging Threats rule set
matching real exploit probe patterns sent by Nikto.

---

## Custom Suricata rule

Written to catch nmap SYN scans that fall below ET threshold rules:

```
alert tcp any any -> $HOME_NET any (
    msg:"HOMELAB Custom: Possible nmap SYN scan";
    flags:S;
    threshold:type both, track by_src, count 20, seconds 3;
    classtype:attempted-recon;
    sid:9000001;
    rev:1;
)
```

Custom SSH brute force rule for volume-based detection:

```
alert tcp any any -> $HOME_NET 22 (
    msg:"CUSTOM SSH Brute Force Attempt";
    flow:to_server;
    threshold:type both, track by_src, count 10, seconds 60;
    sid:9999997;
    rev:1;
)
```

---

## Splunk SPL detection queries

pfSense filterlog format (comma-separated positional fields):
```
filterlog[PID]: rule,sub,anchor,tracker,iface,reason,action,
direction,ip_version,tos,ecn,ttl,id,offset,flags,proto_id,
proto,length,src_ip,dst_ip,src_port,dst_port,...
```

All queries use string matching on the known IP pair before regex
extraction, which works reliably with pfSense filterlog format.

### All traffic from Kali
```
index=pfsense "192.168.100.14"
| table _time, _raw
| sort -_time
```

### SSH brute force - connection count per minute to port 22
```
index=pfsense "192.168.100.14,192.168.100.1" ",22,"
| bin _time span=1m
| stats count by _time
| sort -_time
```

### Web scan - connection count per minute to port 80
```
index=pfsense "192.168.100.14,192.168.100.1" ",80,"
| bin _time span=1m
| stats count by _time
| sort -_time
```

### Port scan - unique ports touched per minute (catches slow scans)
```
index=pfsense "192.168.100.14,192.168.100.1"
| rex field=_raw ",tcp,\d+,192\.168\.100\.14,192\.168\.100\.1,\d+,(?P<dst_port>\d+),"
| where isnotnull(dst_port)
| bin _time span=1m
| stats dc(dst_port) as unique_ports, count by _time
| sort -_time
```

### Master threat timeline with automated scoring
```
index=pfsense "192.168.100.14,192.168.100.1"
| rex field=_raw ",(?:tcp|udp),\d+,192\.168\.100\.14,192\.168\.100\.1,\d+,(?P<dst_port>\d+),"
| bin _time span=1m
| stats count as total_connections,
        dc(dst_port) as unique_ports_scanned by _time
| eval threat_level=case(
    unique_ports_scanned > 20, "HIGH - possible port scan",
    total_connections > 50,    "MEDIUM - high connection rate",
    true(),                    "LOW - normal")
| sort -_time
```

---

## Repository structure

```
home-lab-network-defense/
├── configs/
│   ├── suricata_custom.rules       custom SYN scan + SSH brute force rules
│   └── pfsense_syslog_settings.md  remote log server configuration steps
├── splunk/
│   └── detection_queries.spl       all SPL searches above
├── docs/
│   ├── attack_scenarios.md         commands, timings, MTTD per attack
│   ├── detection_gap_analysis.md   slow scan gap finding and remediation
│   └── screenshots/
│       ├── suricata_alerts_nmap.png
│       ├── suricata_alerts_nikto_cve.png
│       ├── splunk_ssh_spike.png
│       ├── splunk_timeline_all_attacks.png
│       └── detection_gap_slow_scan.png
└── README.md
```

---

## Detection gap analysis summary

| Detection method | Fast scan | Slow scan | SSH brute force | Web scan |
|-----------------|-----------|-----------|-----------------|----------|
| Suricata signatures | Yes | No | Yes | Yes |
| pfSense firewall logs | Yes | Yes | Yes | Yes |
| Splunk behavioral SPL | Yes | Yes | Yes | Yes |

Suricata covers 3 of 4 attacks. The Splunk behavioral query covers all 4.
A complete detection stack requires both layers.

Signature detection answers: does this match a known pattern?
Behavioral detection answers: is this statistically anomalous?
These are different questions. Both layers are necessary.

---

## MITRE ATT&CK mapping

| Technique | ID | Attack used | Detected by |
|-----------|-----|-------------|-------------|
| Network Service Discovery | T1046 | nmap -sS -sV -O | Suricata ET SCAN + SPL |
| Network Service Discovery | T1046 | nmap -sS -T1 slow | SPL only (Suricata gap) |
| Brute Force | T1110 | Hydra SSH 241 tries/min | Suricata custom rule + SPL |
| Exploit Public-Facing Application | T1190 | Nikto web scan | Suricata ET EXPLOIT (CVE signatures) |

---

## Skills demonstrated

- pfSense stateful firewall configuration and rule logging
- Suricata IDS deployment with Emerging Threats Open rule sets
- Custom Suricata signature authoring (SYN scan threshold, SSH volume)
- Splunk syslog ingestion pipeline (pfSense UDP 514 to Splunk Free)
- Splunk SPL query authoring including regex extraction on pfSense filterlog format
- Behavioral anomaly detection using distinct port count per source IP
- Network segmentation using VirtualBox internal networking
- Offensive tooling: nmap, Hydra, Nikto
- MITRE ATT&CK technique mapping
- Detection gap identification and remediation documentation
- Real CVE signature triggering (CVE-2020-3452, CVE-2020-5902)

---

## Background

3 years as Network Security Engineer at Samsung Electronics including
incident response across 10,000+ network infrastructure nodes and IAM
design for enterprise-scale environments. This lab builds hands-on US
tool experience directly extending that background.

---

## Note on Zeek

Zeek behavioral analysis was planned as a phase 2 layer. Ubuntu Server
installation failed repeatedly in the VirtualBox environment due to ISO
corruption and apt configuration errors during install. The behavioral
SPL queries above provide equivalent detection coverage for the slow
scan gap. Zeek integration is documented as a future improvement.

---

## License

MIT
