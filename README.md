# python-INFOsec
A number of python scripts for pulling and tracing through networks and systems

# Overview

## IP Scanner

A multithreaded network scanner that discovers active hosts on a network based on IP range. More of an experiment to see if I could make AngryIP in python.

**Features:**
- Multithreaded scanning for faster results (configurable thread count)
- Hostname resolution for discovered devices
- Optional port scanning (top 20 common ports)
- Ordered results sorted by IP address
- Real-time progress indicator

**Output:** Results are stored to **active_hosts.txt**

**Usage:**
```powershell
# Basic scan
.\ipscanner.py 192.168.1.0/24

# Scan with port detection
.\ipscanner.py 192.168.1.0/24 -p

# Scan with custom thread count
.\ipscanner.py 192.168.1.0/24 -t=50

# Full scan with ports and more threads
.\ipscanner.py 192.168.1.0/24 -p -t=50

# Help
.\ipscanner.py --help
```

**Requirements:**
- Python 3.x
- `python-nmap` package
- Nmap installed on the host machine

## BT Scanner

A Bluetooth Low Energy (BLE) scanner that discovers nearby Bluetooth devices.

**Features:**
- Asynchronous scanning for fast device discovery
- Device name and MAC address detection
- Optional detailed information (RSSI signal strength, manufacturer data, services)
- Configurable scan duration
- Sorted results by device name

**Output:** Results are stored to **active_bt.txt**

**Usage:**
```powershell
# Basic scan (10 seconds)
.\btscanner.py

# Quick scan (5 seconds)
.\btscanner.py -t=5

# Detailed scan with RSSI and manufacturer info
.\btscanner.py -d

# Extended detailed scan
.\btscanner.py -t=20 -d

# Help
.\btscanner.py --help
```

**Requirements:**
- Python 3.x
- `bleak` package (Bluetooth Low Energy library)
- Bluetooth adapter enabled on the host machine

## WiFi SSID Scanner

A WiFi network scanner that discovers available wireless networks with signal strength and security information.

**Features:**
- Scans for all available WiFi networks (SSIDs)
- Signal strength with quality ratings (Excellent/Good/Fair/Weak)
- Visual signal strength bars
- Security type detection (Open, WPA, WPA2, etc.)
- MAC address (BSSID) and frequency information
- Detects hidden networks
- Sorted by signal strength (strongest first)

**Output:** Results are stored to **active_ssids.txt**

**Usage:**
```powershell
# Basic scan (5 seconds)
.\ssidscanner.py

# Detailed scan with MAC, security, and frequency
.\ssidscanner.py -d

# Extended scan
.\ssidscanner.py -t=10 -d

# Help
.\ssidscanner.py --help
```

**Requirements:**
- Python 3.x
- `pywifi` and `comtypes` packages
- WiFi adapter enabled on the host machine
- Administrator privileges recommended for best results
