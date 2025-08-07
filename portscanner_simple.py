import socket
import argparse
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import time


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