#!/usr/bin/env python3
"""
async_scan.py

Authorized scanner for web services using masscan for fast port discovery.

Features:
- Fast port scanning using masscan
- CIDR / range / single IP input
- Progress bar
- JSON / TEXT output
- Optional split output (80 + 443)
- Reverse DNS PTR lookup
- HTTP title grabbing
- HTTPS certificate CN + SAN extraction
"""

import argparse
import asyncio
import ipaddress
import json
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Tuple, Set, Optional

try:
    from tqdm import tqdm
except ImportError:
    print("[!] Missing dependency: tqdm")
    print("Install: pip install tqdm")
    sys.exit(1)

try:
    import aiohttp
except ImportError:
    print("[!] Missing dependency: aiohttp")
    print("Install: pip install aiohttp")
    sys.exit(1)


DEFAULT_PORTS = (80, 443)


# ----------------------------
# INPUT PARSING
# ----------------------------
def parse_ip_range(line: str) -> List[str]:
    line = line.strip()

    if not line or line.startswith("#"):
        return []

    if "/" in line:
        net = ipaddress.ip_network(line, strict=False)
        return [str(ip) for ip in net.hosts()]

    if "-" in line:
        start, end = line.split("-", 1)
        start_ip = ipaddress.ip_address(start.strip())
        end_ip = ipaddress.ip_address(end.strip())

        if start_ip.version != end_ip.version:
            raise ValueError(f"Mixed IP versions in range: {line}")

        start_int = int(start_ip)
        end_int = int(end_ip)

        if end_int < start_int:
            raise ValueError(f"Invalid range (end < start): {line}")

        return [str(ipaddress.ip_address(i)) for i in range(start_int, end_int + 1)]

    ipaddress.ip_address(line)
    return [line]


def load_targets(filename: str) -> List[str]:
    path = Path(filename)

    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {filename}")

    targets: List[str] = []
    for line in path.read_text().splitlines():
        targets.extend(parse_ip_range(line))

    seen: Set[str] = set()
    unique_targets: List[str] = []
    for ip in targets:
        if ip not in seen:
            seen.add(ip)
            unique_targets.append(ip)

    return unique_targets


# ----------------------------
# MASSCAN PORT SCANNING
# ----------------------------
def check_masscan_installed() -> str:
    """Check if masscan is installed and return the path."""
    import shutil
    
    # Try to find masscan in PATH
    masscan_path = shutil.which("masscan")
    if masscan_path:
        return masscan_path
    
    # Try common installation paths
    common_paths = [
        "/usr/bin/masscan",
        "/usr/local/bin/masscan",
        "/snap/bin/masscan",
        "/opt/masscan/bin/masscan"
    ]
    
    for path in common_paths:
        if Path(path).exists():
            return path
    
    return None


def run_masscan(targets: List[str], ports: Tuple[int, ...], rate: int = 10000) -> Dict[str, List[int]]:
    """
    Run masscan to scan ports and return results.
    Returns: { "ip": [open_ports] }
    """
    masscan_path = check_masscan_installed()
    if not masscan_path:
        print("[!] Error: masscan is not installed or not in PATH")
        print("Install masscan:")
        print("  Ubuntu/Debian: sudo apt-get install masscan")
        print("  macOS: brew install masscan")
        print("  From source: https://github.com/robertdavidgraham/masscan")
        sys.exit(1)

    # Create temporary directory (more reliable permissions with sudo)
    temp_dir = tempfile.mkdtemp(prefix="masscan_")
    targets_file = Path(temp_dir) / "targets.txt"
    output_file = Path(temp_dir) / "output.json"

    try:
        # Write targets file
        with open(targets_file, 'w') as f:
            for target in targets:
                f.write(target + '\n')

        ports_str = ','.join(str(p) for p in ports)

        cmd = [
            masscan_path,
            "-iL", str(targets_file),
            "-p", ports_str,
            "-oJ", str(output_file),
            "--rate", str(rate),
        ]

        print(f"[+] Running masscan (found at {masscan_path})...")
        
        try:
            result = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=None)
        except subprocess.CalledProcessError as e:
            # Try with sudo if it fails (common for raw socket access)
            print("[!] Masscan requires root privileges, attempting with sudo...")
            cmd = ["sudo"] + cmd
            try:
                result = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=None, stdin=subprocess.DEVNULL)
            except subprocess.CalledProcessError as e:
                error_msg = e.stderr if e.stderr else e.stdout if e.stdout else str(e)
                print(f"[!] Masscan error: {error_msg}", file=sys.stderr)
                raise

        # Parse JSON output
        results: Dict[str, List[int]] = {}
        
        if not output_file.exists():
            print("[!] Warning: No output file generated. Masscan may have found no open ports.", file=sys.stderr)
            return results
            
        try:
            with open(output_file, 'r') as f:
                output_text = f.read().strip()
            
            # Handle NDJSON format (newline-delimited JSON)
            if not output_text:
                return results
            
            for line in output_text.split('\n'):
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                    
                    # Each entry has format: {"ip": "...", "ports": [{"port": ..., "proto": ..., "status": ...}, ...]}
                    if "ip" in entry and "ports" in entry:
                        ip = entry["ip"]
                        open_ports = []
                        
                        for port_info in entry["ports"]:
                            if port_info.get("status") == "open":
                                open_ports.append(port_info.get("port"))
                        
                        if open_ports:
                            results[ip] = sorted(open_ports)
                
                except json.JSONDecodeError as e:
                    # Skip malformed lines
                    pass

        except Exception as e:
            print(f"[!] Error parsing masscan output: {e}", file=sys.stderr)

        return results

    finally:
        # Cleanup temp directory
        import shutil as sh
        sh.rmtree(temp_dir, ignore_errors=True)


# ----------------------------
# PTR RESOLVE
# ----------------------------
def reverse_dns_lookup(ip: str) -> Optional[str]:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except Exception:
        return None


def resolve_ptr_domains(results: List[Dict], max_workers: int = 200) -> None:
    from concurrent.futures import ThreadPoolExecutor, as_completed

    ips = [r["ip"] for r in results]

    with tqdm(total=len(ips), desc="Resolving PTR", unit="ip") as pbar:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_map = {executor.submit(reverse_dns_lookup, ip): ip for ip in ips}

            ip_to_domain = {}
            for future in as_completed(future_map):
                ip = future_map[future]
                try:
                    domain = future.result()
                except Exception:
                    domain = None

                ip_to_domain[ip] = domain
                pbar.update(1)

    for r in results:
        r["ptr_domain"] = ip_to_domain.get(r["ip"])


# ----------------------------
# TITLE GRAB
# ----------------------------
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def extract_title(html: str) -> Optional[str]:
    match = TITLE_RE.search(html)
    if not match:
        return None

    title = match.group(1).strip()
    title = re.sub(r"\s+", " ", title)
    return title[:200] if title else None


async def fetch_http_title(ip: str, use_https: bool, timeout: float) -> Optional[str]:
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{ip}/"

    try:
        client_timeout = aiohttp.ClientTimeout(total=timeout)
        connector = aiohttp.TCPConnector(ssl=False)  # we handle cert separately
        async with aiohttp.ClientSession(timeout=client_timeout, connector=connector) as session:
            async with session.get(url, allow_redirects=True) as resp:
                if resp.status >= 400:
                    return None

                text = await resp.text(errors="ignore")
                return extract_title(text)

    except Exception:
        return None


# ----------------------------
# SSL CERT INFO
# ----------------------------
def get_cert_info(ip: str, timeout: float) -> Dict:
    """
    Fetch certificate info using ssl socket.
    Returns:
      { "cn": str|None, "san": [domains] }
    """
    info = {"cn": None, "san": []}

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((ip, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert()

        # CN
        subject = cert.get("subject", [])
        for item in subject:
            for key, value in item:
                if key.lower() == "commonname":
                    info["cn"] = value

        # SAN
        san = cert.get("subjectAltName", [])
        domains = []
        for entry in san:
            if len(entry) == 2 and entry[0].lower() == "dns":
                domains.append(entry[1])

        info["san"] = sorted(set(domains))

    except Exception:
        pass

    return info


def resolve_cert_info(results: List[Dict], timeout: float, max_workers: int = 100) -> None:
    """
    Blocking SSL handshake, so use thread pool.
    Only runs for IPs that have port 443 open.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    targets = [r["ip"] for r in results if r.get("has_443")]

    with tqdm(total=len(targets), desc="Fetching SSL Cert", unit="ip") as pbar:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_map = {
                executor.submit(get_cert_info, ip, timeout): ip
                for ip in targets
            }

            cert_map = {}
            for future in as_completed(future_map):
                ip = future_map[future]
                try:
                    cert_map[ip] = future.result()
                except Exception:
                    cert_map[ip] = {"cn": None, "san": []}

                pbar.update(1)

    for r in results:
        if r.get("has_443"):
            cert = cert_map.get(r["ip"], {"cn": None, "san": []})
            r["ssl_cn"] = cert.get("cn")
            r["ssl_san"] = cert.get("san", [])
        else:
            r["ssl_cn"] = None
            r["ssl_san"] = []


# ----------------------------
# SCANNING CORE
# ----------------------------
def scan_with_masscan(targets: List[str], ports: Tuple[int, ...], rate: int) -> List[Dict]:
    """
    Run masscan and convert results to internal format.
    """
    masscan_results = run_masscan(targets, ports, rate=rate)

    results = []
    for ip, open_ports in masscan_results.items():
        results.append({
            "ip": ip,
            "open_ports": open_ports,
            "has_web": bool(open_ports),
            "has_80": 80 in open_ports,
            "has_443": 443 in open_ports,
            "ptr_domain": None,
            "http_title": None,
            "https_title": None,
            "ssl_cn": None,
            "ssl_san": []
        })

    return results


# ----------------------------
# POST PROCESSING
# ----------------------------
async def grab_titles(results: List[Dict], timeout: float, workers: int = 200) -> None:
    """
    Grab titles using aiohttp concurrently.
    """
    sem = asyncio.Semaphore(workers)

    async def task_http(entry: Dict):
        async with sem:
            entry["http_title"] = await fetch_http_title(entry["ip"], use_https=False, timeout=timeout)

    async def task_https(entry: Dict):
        async with sem:
            entry["https_title"] = await fetch_http_title(entry["ip"], use_https=True, timeout=timeout)

    jobs = []

    for r in results:
        if r.get("has_80"):
            jobs.append(task_http(r))
        if r.get("has_443"):
            jobs.append(task_https(r))

    with tqdm(total=len(jobs), desc="Grabbing Titles", unit="req") as pbar:
        async def wrapped(coro):
            try:
                await coro
            finally:
                pbar.update(1)

        await asyncio.gather(*(wrapped(j) for j in jobs))


# ----------------------------
# OUTPUT
# ----------------------------
def save_json(path: str, data: List[Dict]) -> None:
    payload = {
        "total_found": len(data),
        "results": sorted(data, key=lambda x: x["ip"])
    }
    Path(path).write_text(json.dumps(payload, indent=4) + "\n")


def save_text(path: str, data: List[Dict]) -> None:
    lines = []
    for entry in sorted(data, key=lambda x: x["ip"]):
        ports_str = ",".join(str(p) for p in entry["open_ports"])
        ptr = entry.get("ptr_domain") or "-"
        http_t = entry.get("http_title") or "-"
        https_t = entry.get("https_title") or "-"
        cn = entry.get("ssl_cn") or "-"

        lines.append(f"{entry['ip']} {ports_str} PTR:{ptr} HTTP:{http_t} HTTPS:{https_t} CN:{cn}")

    Path(path).write_text("\n".join(lines) + ("\n" if lines else ""))


def save_output(path: str, fmt: str, data: List[Dict]) -> None:
    if fmt == "json":
        save_json(path, data)
    else:
        save_text(path, data)


def build_split_name(base_output: str, suffix: str) -> str:
    p = Path(base_output)
    return str(p.with_name(f"{p.stem}_{suffix}{p.suffix}"))


# ----------------------------
# MAIN
# ----------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Fast scanner for 80/443 using masscan + PTR + HTTP titles + SSL CN/SAN."
    )

    parser.add_argument("-i", "--input", required=True, help="Input file with targets")
    parser.add_argument("-o", "--output", required=True, help="Output file")

    parser.add_argument("--ports", default="80,443",
                        help="Comma-separated ports (default: 80,443)")

    parser.add_argument("--rate", type=int, default=10000,
                        help="Masscan rate (packets per second, default: 10000)")

    parser.add_argument("--format", choices=["json", "text"], default="json",
                        help="Output format (default: json)")

    parser.add_argument("--split-output", action="store_true",
                        help="Save separate files for port 80 and 443")

    parser.add_argument("--save-combined", action="store_true",
                        help="If split output enabled, also save combined output")

    # Domain resolving
    parser.add_argument("--resolve-domains", action="store_true",
                        help="Reverse DNS PTR lookup")

    parser.add_argument("--dns-workers", type=int, default=200,
                        help="Thread workers for PTR lookup (default: 200)")

    # Title grab
    parser.add_argument("--grab-titles", action="store_true",
                        help="Grab HTTP/HTTPS <title> tags")

    parser.add_argument("--title-workers", type=int, default=200,
                        help="Concurrency for title grabbing (default: 200)")

    parser.add_argument("--title-timeout", type=float, default=2.0,
                        help="Timeout for title grabbing (default: 2.0)")

    # SSL cert info
    parser.add_argument("--grab-cert", action="store_true",
                        help="Extract SSL certificate CN + SAN from port 443")

    parser.add_argument("--cert-workers", type=int, default=100,
                        help="Thread workers for SSL certificate grabbing (default: 100)")

    parser.add_argument("--cert-timeout", type=float, default=3.0,
                        help="Timeout for certificate grabbing (default: 3.0)")

    args = parser.parse_args()

    try:
        ports = tuple(int(p.strip()) for p in args.ports.split(",") if p.strip())
        if not ports:
            raise ValueError("No ports provided.")

        targets = load_targets(args.input)
        if not targets:
            print("[!] No valid targets found.", file=sys.stderr)
            sys.exit(1)

        print(f"[+] Targets loaded: {len(targets)}")
        print(f"[+] Ports: {ports}")
        print(f"[+] Masscan rate: {args.rate} pps")
        print(f"[+] Format: {args.format}")
        print("")

        results = scan_with_masscan(targets, ports, rate=args.rate)

        print(f"\n[+] Found {len(results)} hosts with open ports.")

        if args.resolve_domains and results:
            resolve_ptr_domains(results, max_workers=args.dns_workers)

        if args.grab_titles and results:
            asyncio.run(grab_titles(results, timeout=args.title_timeout, workers=args.title_workers))

        if args.grab_cert and results:
            resolve_cert_info(results, timeout=args.cert_timeout, max_workers=args.cert_workers)

        # OUTPUT
        if args.split_output:
            results_80 = [r for r in results if r.get("has_80")]
            results_443 = [r for r in results if r.get("has_443")]

            out80 = build_split_name(args.output, "80")
            out443 = build_split_name(args.output, "443")

            save_output(out80, args.format, results_80)
            save_output(out443, args.format, results_443)

            print(f"[+] Saved port 80 file: {out80} ({len(results_80)} hosts)")
            print(f"[+] Saved port 443 file: {out443} ({len(results_443)} hosts)")

            if args.save_combined:
                save_output(args.output, args.format, results)
                print(f"[+] Saved combined file: {args.output} ({len(results)} hosts)")
        else:
            save_output(args.output, args.format, results)
            print(f"[+] Saved output file: {args.output} ({len(results)} hosts)")

        print("\n[+] Done.")

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.", file=sys.stderr)
        sys.exit(130)

    except Exception as e:
        print(f"[!] Fatal error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
