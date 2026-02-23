# 🍎 pwnapple

A Python-based security automation toolkit designed for Raspberry Pi devices. pwnapple simplifies various wireless security testing functions with an intuitive CLI interface.

## Features

### 🔍 Wireless Network Analysis
- **EAPOL/Handshake Capture**: Monitor and capture WPA/WPA2 handshakes for network analysis
- **EAP Identity Discovery**: Detect and log EAP identities from enterprise networks
- **Channel Hopping**: Automatic channel scanning across all WiFi channels (1-11)
- **Probe Request Monitoring**: Track devices searching for specific networks
- **Beacon Frame Analysis**: Discover SSIDs, BSSIDs, and MAC addresses of nearby access points

### ⚡ Active Attacks
- **Automated Deauthentication**: Continuous deauth attacks against detected networks
- **Target Management**: Automatic clearing of deauth targets every 30 seconds
- **Full Packet Logging**: Optional capture of all traffic, not just EAPOL frames

### 📺 Chromecast/DIAL Hijacking
- **Network-wide Discovery**: Automatically finds all Chromecasts and DIAL-enabled TVs
- **Video Broadcast**: Play custom YouTube videos on all discovered devices
- **Multi-device Support**: Simultaneously hijacks multiple targets

## Requirements

### Hardware
- Raspberry Pi (recommended)
- WiFi adapter capable of monitor mode
- Optional: Second WiFi adapter for simultaneous operations

### Dependencies
```bash
scapy
rich
typer
pychromecast
zeroconf
pylaunch
aircrack-ng
