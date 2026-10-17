# TCP Port Scanner

A simple multi-threaded TCP port scanner written in Python (Syntecxhub Project 1).

## Features
- Scan a **single port** or a **range of ports**
- **Multi-threading** (`ThreadPoolExecutor`) for fast scanning
- Reports **open / closed / timeout** results
- Logs every result to a file (`scan_results.log`)
- Handles exceptions (bad hostname, invalid ports, Ctrl+C, socket errors)
- Shows the common service name for open ports (http, ssh, ...)

## Requirements
- Python 3.9+ (no external libraries)

## Usage
```bash
# Scan ports 1-1024 (default)
python port_scanner.py 127.0.0.1

# Single port
python port_scanner.py scanme.nmap.org -p 80

# Port range
python port_scanner.py scanme.nmap.org -s 1 -e 1000

# More threads, shorter timeout, show closed ports too
python port_scanner.py 127.0.0.1 -s 1 -e 5000 -t 200 --timeout 0.5 --show-all
```

### Options
| Option | Description | Default |
|---|---|---|
| `host` | Target hostname or IP | required |
| `-p, --port` | Scan a single port | - |
| `-s, --start` | Start port | 1 |
| `-e, --end` | End port | 1024 |
| `-t, --threads` | Number of threads | 100 |
| `--timeout` | Timeout per port (seconds) | 1.0 |
| `-l, --log` | Log file | scan_results.log |
| `--show-all` | Print closed/timeout ports | off |

## Example output
```
-------------------------------------------------------
Target : scanme.nmap.org (45.33.32.156)
Ports  : 1-1024 (1024 ports)
Threads: 100 | Timeout: 1.0s
-------------------------------------------------------
Port 22    OPEN     ssh
Port 80    OPEN     http
-------------------------------------------------------
Done in 11.20s | open: 2, closed: 0, timeout: 1022, errors: 0
```

## How it works
1. Creates a TCP socket for each port with a timeout.
2. `connect_ex()` returns `0` if the port is open.
3. Connection refused = closed, no reply before the timeout = timeout (likely filtered by a firewall).
4. A thread pool scans many ports at once.

## Disclaimer
For educational purposes only. Scan only systems you own or have explicit permission to test.
(`scanme.nmap.org` is a host that allows test scans.)
