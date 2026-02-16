# async_scan.py

A fast and authorized port scanner for discovering hosts with open HTTP/HTTPS ports (80/443) using **masscan** for rapid port discovery, with advanced reconnaissance capabilities.

## Features

- **Masscan-powered Scanning**: Ultra-fast port scanning using the masscan tool
- **Flexible Input**: Supports CIDR notation, IP ranges, and single IPs
- **Multiple Output Formats**: JSON and text output formats
- **Split Output**: Optionally save separate result files for port 80 and port 443
- **Reverse DNS Lookup**: Resolve hostnames from IP addresses (PTR records)
- **HTTP Title Grabbing**: Extract `<title>` tags from HTTP/HTTPS responses
- **SSL Certificate Extraction**: Extract Common Name (CN) and Subject Alternative Names (SAN) from HTTPS certificates
- **Progress Tracking**: Real-time progress bars for all operations

## Requirements

- Python 3.7+
- **masscan** - Ultra-fast port scanner (must be installed separately)
- `aiohttp` - Async HTTP client library
- `tqdm` - Progress bar library

## Installation

### 1. Install Masscan

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install masscan
```

**macOS (with Homebrew):**
```bash
brew install masscan
```

**From Source:**
```bash
git clone https://github.com/robertdavidgraham/masscan
cd masscan
make
sudo make install
```

### 2. Install Python Dependencies

Using Virtual Environment (Recommended):
```bash
# Create and activate virtual environment
python3 -m venv virtual
source virtual/bin/activate

# Install dependencies
pip install aiohttp tqdm
```

Or directly:
```bash
pip install aiohttp tqdm
```

## Usage

### Basic Scanning

```bash
python3 async_scan.py -i targets.txt -o results.json
```

### Command-Line Options

#### Required Arguments

- `-i, --input FILE` - Input file containing target IPs/ranges (required)
- `-o, --output FILE` - Output file path (required)

#### Scan Options

- `--ports PORTS` - Comma-separated ports to scan (default: `80,443`)
- `--rate RATE` - Masscan scan rate in packets per second (default: `10000`)
  - Lower values (1000-5000) for stealthy/stable scans
  - Higher values (50000-100000) for aggressive scans

#### Output Options

- `--format {json,text}` - Output format (default: `json`)
- `--split-output` - Save separate files for port 80 and port 443
- `--save-combined` - When using split output, also save combined results

#### DNS Resolution

- `--resolve-domains` - Perform reverse DNS (PTR) lookups for discovered IPs
- `--dns-workers N` - Thread workers for DNS lookups (default: `200`)

#### Title Grabbing

- `--grab-titles` - Extract HTTP/HTTPS page titles
- `--title-workers N` - Concurrency level for title grabbing (default: `200`)
- `--title-timeout SECONDS` - Timeout for title requests (default: `2.0`)

#### SSL Certificate Extraction

- `--grab-cert` - Extract SSL certificate CN and SAN from HTTPS services
- `--cert-workers N` - Thread workers for certificate extraction (default: `100`)
- `--cert-timeout SECONDS` - Timeout for certificate operations (default: `3.0`)

## Examples

### Example 1: Basic Port Scan

```bash
python3 async_scan.py -i targets.txt -o results.json
```

Scans targets for open ports 80 and 443 with default settings.

### Example 2: Full Reconnaissance

```bash
python3 async_scan.py \
  -i targets.txt \
  -o results.json \
  --resolve-domains \
  --grab-titles \
  --grab-cert
```

Performs complete reconnaissance: port scanning, DNS resolution, title extraction, and certificate grabbing.

### Example 3: Aggressive Scan with Split Output

```bash
python3 async_scan.py \
  -i targets.txt \
  -o results.json \
  --rate 100000 \
  --split-output \
  --grab-titles
```

Fast aggressive scan with split output files for ports 80 and 443.

### Example 4: Stealthy Scan

```bash
python3 async_scan.py \
  -i targets.txt \
  -o results.txt \
  --ports 80,443,8080,8443 \
  --format text \
  --rate 1000
```

Slow, stealthy scan on multiple ports with lower rate.

### Example 5: Custom Ports with Certificate Extraction

```bash
python3 async_scan.py \
  -i targets.txt \
  -o results.json \
  --ports 80,443,8080,8443 \
  --grab-cert \
  --grab-titles \
  --cert-timeout 5.0
```

Scan custom ports and extract both certificates and titles with extended timeout.

## Input File Format

The input file should contain one target per line. Supported formats:

```
# Single IP
192.168.1.1

# CIDR notation
192.168.1.0/24
10.0.0.0/8

# IP range
192.168.1.1-192.168.1.255

# Comments (ignored)
# This is a comment
10.20.30.40
```

## Output Format

### JSON Output

```json
{
    "total_found": 2,
    "results": [
        {
            "ip": "192.168.1.1",
            "open_ports": [80, 443],
            "has_web": true,
            "has_80": true,
            "has_443": true,
            "ptr_domain": "webserver.example.com",
            "http_title": "Welcome to Apache",
            "https_title": "My Secure Site",
            "ssl_cn": "webserver.example.com",
            "ssl_san": ["webserver.example.com", "www.example.com"]
        }
    ]
}
```

### Text Output

```
192.168.1.1 80,443 PTR:webserver.example.com HTTP:Welcome to Apache HTTPS:My Secure Site CN:webserver.example.com
```

## Performance Tuning

### For Large Target Lists

Use aggressive rate to speed up scanning:

```bash
python3 async_scan.py -i targets.txt -o results.json --rate 50000
```

### For Unreliable Networks

Lower the rate to prevent packet loss:

```bash
python3 async_scan.py -i targets.txt -o results.json --rate 1000
```

### For Extended Timeouts

Increase title and certificate timeouts for slow servers:

```bash
python3 async_scan.py -i targets.txt -o results.json \
  --grab-titles --grab-cert \
  --title-timeout 5.0 --cert-timeout 5.0
```

## Error Handling

The scanner handles various error conditions gracefully:

- **Masscan not found**: Script checks for masscan installation and provides install instructions
- **Network timeouts**: Treated as closed ports
- **SSL/TLS errors**: Continues scanning without certificate info
- **DNS resolution failures**: Marked as None in output
- **Invalid IP formats**: Skipped with error reporting

## Masscan Rate Guidelines

- **1,000 pps**: Stealthy, targets single gateway (slow networks)
- **10,000 pps** (default): Balanced, good for most networks
- **50,000 pps**: Aggressive, enterprise networks
- **100,000+ pps**: Very aggressive, local networks only

## Notes

- **Authorization**: Ensure you have authorization before scanning any networks or systems
- **Root Privileges**: Masscan may require root/sudo on some systems for raw socket access
- **Rate Limiting**: Network administrators may block high-rate scans. Adjust rate accordingly
- **DNS Lookups**: PTR resolution may be slow on large result sets
- **Certificates**: Certificate extraction only works for servers with valid SSL configurations

## Advantages Over Manual Scanning

- **Speed**: 100x+ faster than manual socket scanning
- **Efficiency**: Optimized C implementation vs. Python
- **Scalability**: Can scan large networks quickly
- **Flexibility**: Adjustable rate for different network conditions
- **Reliability**: Proven tool in security industry

## License

For authorized use only. Ensure compliance with all applicable laws and network policies.
