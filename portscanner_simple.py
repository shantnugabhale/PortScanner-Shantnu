import socket
import argparse
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

def parse_ports(port_string):
    """Parse ports from '1-100', '22,80,443', or single '80'."""
    if "-" in port_string:
        start, end = port_string.split("-", 1)
        return list(range(int(start), int(end) + 1))
    if "," in port_string:
        return [int(p.strip()) for p in port_string.split(",") if p.strip()]
    return [int(port_string)]

def scan_port(ip, port, timeout=1.0, retries=1, grab_banner=False):
    """Return (port, state, banner_or_error)."""
    for attempt in range(retries + 1):
        try:
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                sock.settimeout(1.0)
                banner = None
                if grab_banner:
                    try:
                        banner = sock.recv(1024).decode(errors='ignore').strip()
                    except Exception:
                        banner = None
                return (port, 'open', banner)
        except ConnectionRefusedError as e:
            return (port, 'closed', str(e))
        except socket.timeout:
            continue
        except OSError as e:
            last_err = e
            continue
    return (port, 'filtered', str(last_err) if 'last_err' in locals() else 'timeout')

def run_scan(target, ports, threads=100, timeout=1.0, retries=1, grab_banner=False):
    """Run threaded scan and return result dict."""
    ip = socket.gethostbyname(target)
    results = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_port, ip, p, timeout, retries, grab_banner): p for p in ports}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as e:
                p = futures[future]
                results.append((p, 'error', str(e)))
    output = {'target': target, 'ip': ip, 'results': []}
    for port, state, info in sorted(results, key=lambda x: x[0]):
        output['results'].append({'port': port, 'state': state, 'info': info})
    return output

def main():
    parser = argparse.ArgumentParser(description="Simple TCP port scanner")
    parser.add_argument('target', help='IP or domain to scan')
    parser.add_argument('ports', help='Port range (e.g. 1-1024 or 22,80,443)')
    parser.add_argument('--threads', type=int, default=200, help='Number of threads')
    parser.add_argument('--timeout', type=float, default=1.0, help='Timeout per port')
    parser.add_argument('--retries', type=int, default=1, help='Retries per port')
    parser.add_argument('--banner', action='store_true', help='Grab banner on open ports')
    parser.add_argument('--out', help='Save results to JSON file')
    args = parser.parse_args()

    ports = parse_ports(args.ports)
    print(f"[+] Scanning {args.target} ({len(ports)} ports)...")
    start = time.time()
    results = run_scan(args.target, ports, threads=args.threads, timeout=args.timeout, retries=args.retries, grab_banner=args.banner)
    elapsed = time.time() - start

    open_ports = [r for r in results['results'] if r['state'] == 'open']
    print(f"[+] Done in {elapsed:.2f}s — Open ports: {len(open_ports)}")
    for r in open_ports:
        print(f"  - {r['port']} open  info: {r['info']}")

    if args.out:
        with open(args.out, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"[+] Results saved to {args.out}")

if __name__ == '__main__':
    main()