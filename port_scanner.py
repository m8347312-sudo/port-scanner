#!/usr/bin/env python3
"""
TCP Port Scanner
- Scan a single port or a range of ports on a host
- Multi-threaded for speed
- Reports open / closed / timeout (filtered)
- Logs results to a file and handles exceptions

Use only on hosts you own or have permission to scan.
"""

import argparse
import errno
import logging
import socket
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

OPEN, CLOSED, TIMEOUT, ERROR = "OPEN", "CLOSED", "TIMEOUT", "ERROR"

print_lock = threading.Lock()


def setup_logging(log_file: str) -> None:
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
    )


def scan_port(ip: str, port: int, timeout: float) -> tuple[int, str]:
    """Try to connect to ip:port and return (port, status)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((ip, port))
        if result == 0:
            return port, OPEN
        if result == errno.ECONNREFUSED:
            return port, CLOSED
        return port, CLOSED
    except socket.timeout:
        return port, TIMEOUT
    except OSError as e:
        logging.error("Error scanning port %d: %s", port, e)
        return port, ERROR
    finally:
        sock.close()


def get_service(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def parse_ports(args) -> list[int]:
    if args.port is not None:
        start = end = args.port
    else:
        start, end = args.start, args.end
    if not (1 <= start <= 65535 and 1 <= end <= 65535):
        raise ValueError("Ports must be between 1 and 65535")
    if start > end:
        raise ValueError("Start port must be <= end port")
    return list(range(start, end + 1))


def main() -> int:
    parser = argparse.ArgumentParser(description="Simple multi-threaded TCP port scanner")
    parser.add_argument("host", help="Target hostname or IP (e.g. 127.0.0.1 or scanme.nmap.org)")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-p", "--port", type=int, help="Scan a single port")
    parser.add_argument("-s", "--start", type=int, default=1, help="Start of port range (default 1)")
    parser.add_argument("-e", "--end", type=int, default=1024, help="End of port range (default 1024)")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Number of threads (default 100)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Timeout per port in seconds (default 1)")
    parser.add_argument("-l", "--log", default="scan_results.log", help="Log file (default scan_results.log)")
    parser.add_argument("--show-all", action="store_true", help="Print closed/timeout ports too")
    args = parser.parse_args()

    setup_logging(args.log)

    try:
        ports = parse_ports(args)
    except ValueError as e:
        print(f"[!] {e}")
        return 1

    try:
        ip = socket.gethostbyname(args.host)
    except socket.gaierror:
        print(f"[!] Cannot resolve hostname: {args.host}")
        logging.error("Cannot resolve hostname: %s", args.host)
        return 1

    print("-" * 55)
    print(f"Target : {args.host} ({ip})")
    print(f"Ports  : {ports[0]}-{ports[-1]} ({len(ports)} ports)")
    print(f"Threads: {args.threads} | Timeout: {args.timeout}s")
    print(f"Started: {datetime.now():%Y-%m-%d %H:%M:%S}")
    print("-" * 55)
    logging.info("Scan started on %s (%s) ports %d-%d", args.host, ip, ports[0], ports[-1])

    counts = {OPEN: 0, CLOSED: 0, TIMEOUT: 0, ERROR: 0}
    start_time = datetime.now()

    try:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = [executor.submit(scan_port, ip, p, args.timeout) for p in ports]
            for future in as_completed(futures):
                port, status = future.result()
                counts[status] += 1
                logging.info("Port %d: %s", port, status)
                if status == OPEN or args.show_all:
                    with print_lock:
                        print(f"Port {port:<5} {status:<8} {get_service(port)}")
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        logging.warning("Scan interrupted by user")
        return 130

    duration = (datetime.now() - start_time).total_seconds()
    print("-" * 55)
    print(
        f"Done in {duration:.2f}s | open: {counts[OPEN]}, closed: {counts[CLOSED]}, "
        f"timeout: {counts[TIMEOUT]}, errors: {counts[ERROR]}"
    )
    logging.info("Scan finished in %.2fs | %s", duration, counts)
    return 0


if __name__ == "__main__":
    sys.exit(main())
