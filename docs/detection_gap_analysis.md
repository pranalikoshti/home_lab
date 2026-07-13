# Detection Gap Analysis

## Summary
* **Signature detection answers:** Does this match a known pattern?
* **Behavioral detection answers:** Is this statistically anomalous?

Suricata covers 3 of 4 attacks in this lab. The Splunk behavioral query covers all 4. A complete detection stack requires both layers. Both are necessary.

## What Happened
The slow nmap scan (`nmap -sS -T1 --scan-delay 5s -p 1-100`) completed fully against pfSense. Every probe was logged by the pfSense firewall. **Suricata generated zero alerts.**

The aggressive nmap scan with identical targets fired Suricata alerts within 55 seconds. The only difference: 5 seconds between probes instead of milliseconds.

## Why It Happened
Suricata's Emerging Threats scan rules use threshold detection: fire if X events occur within Y seconds. A 5-second delay between probes means the connection rate never crosses any threshold.

The attack and the detection gap are two separate concepts:
1. The attack still happened.
2. The firewall still logged every packet.
3. Suricata had no signature that matched the behavioral pattern.

## How It Was Detected Anyway
pfSense firewall logs showed traffic from `192.168.100.14` touching multiple destination ports over the attack window. A Splunk behavioral query detected this without any Suricata signature.

## Remediation
A behavioral SPL query using distinct port count per source IP per minute catches the slow scan regardless of connection rate:

```spl
index=pfsense "192.168.100.14,192.168.100.1"
| rex field=_raw ",(?:tcp|udp),\d+,192\.168\.100\.14,192\.168\.100\.1,\d+,(?P<dst_port>\d+),"
| bin _time span=1m
| stats dc(dst_port) as unique_ports, count by _time
| sort -_time
