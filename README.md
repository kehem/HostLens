# async_scan.py

An authorized asynchronous web service scanner for discovering hosts with open HTTP/HTTPS ports (80/443) with advanced reconnaissance capabilities.

## Features

- **Async Port Scanning**: High-performance concurrent port scanning with configurable worker threads
- **Flexible Input**: Supports CIDR notation, IP ranges, and single IPs
- **Multiple Output Formats**: JSON and text output formats
- **Split Output**: Optionally save separate result files for port 80 and port 443
- **Reverse DNS Lookup**: Resolve hostnames from IP addresses (PTR records)
- **HTTP Title Grabbing**: Extract `<title>` tags from HTTP/HTTPS responses
- **SSL Certificate Extraction**: Extract Common Name (CN) and Subject Alternative Names (SAN) from HTTPS certificates
- **Progress Tracking**: Real-time progress bars for all operations

## Requirements

- Python 3.7+
- `aiohttp` - Async HTTP client library
- `tqdm` - Progress bar library

## Installation

### Using Virtual Environment (Recommended)

```bash
# Create and activate virtual environment
python3 -m venv virtual
source virtual/bin/activate

# Install dependencies
pip install aiohttp tqdm
```

### Direct Installation

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
- `--timeout SECONDS` - Connection timeout in seconds (default: `2.0`)
- `-w, --workers N` - Number of async workers for port scanning (default: `500`)

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

#### SSL Certificate Extraction

- `--grab-cert` - Extract SSL certificate CN and SAN from HTTPS services
- `--cert-workers N` - Thread workers for certificate extraction (default: `100`)

## Examples

### Example 1: Basic Port Scan

```bash
python3 async_scan.py -i targets.txt -o results.json
```

Scans targets for open ports 80 and 443.

### Example 2: Scan with All Enhancements

```bash
python3 async_scan.py \
  -i targets.txt \
  -o results.json \
  --resolve-domains \
  --grab-titles \
  --grab-cert \
  --timeout 3.0 \
  -w 1000
```

Performs full reconnaissance: port scanning, DNS resolution, title extraction, and certificate grabbing.

### Example 3: Split Output by Port

```bash
python3 async_scan.py \
  -i targets.txt \
  -o results.json \
  --split-output \
  --save-combined \
  --grab-titles
```

Creates `results_80.json`, `results_443.json`, and `results.json` with titles grabbed.

### Example 4: High-Speed Scan with Custom Ports

```bash
python3 async_scan.py \
  -i targets.txt \
  -o results.txt \
  --ports 80,443,8080,8443 \
  --format text \
  -w 2000 \
  --timeout 1.0
```

Scans multiple ports with text output and aggressive timing.

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

Increase the number of workers to scan faster:

```bash
python3 async_scan.py -i targets.txt -o results.json -w 2000
```

### For Unreliable Networks

Increase timeout to allow slower connections:

```bash
python3 async_scan.py -i targets.txt -o results.json --timeout 5.0
```

### For Resource-Constrained Systems

Reduce workers and title grabbing concurrency:

```bash
python3 async_scan.py -i targets.txt -o results.json -w 200 --title-workers 50
```

## Error Handling

The scanner handles various error conditions gracefully:

- **Invalid IP formats**: Skips invalid entries and reports errors
- **Network timeouts**: Treats as closed ports
- **SSL/TLS errors**: Continues scanning without certificate info
- **DNS resolution failures**: Marks as None in output

## Notes

- **Authorization**: Ensure you have authorization before scanning any networks or systems
- **Rate Limiting**: Network administrators may rate-limit requests. Adjust timeouts and workers accordingly
- **DNS Lookups**: PTR resolution may be slow on large result sets; reduce `--dns-workers` if DNS queries fail
- **Certificates**: Certificate extraction only works for servers with valid SSL configurations

## License

For authorized use only. Ensure compliance with all applicable laws and network policies.
