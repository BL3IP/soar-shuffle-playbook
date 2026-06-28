"""auto_enrich_contain - a SOAR playbook: enrich a suspicious IP, decide, and contain.

Mirrors the Shuffle workflow in docs/workflow-design.md (Webhook -> HTTP enrich -> condition ->
block/notify). Enrichment uses Shodan InternetDB (free, keyless). The decision logic is pure and
unit-tested; the network call is injectable so tests are deterministic and offline.

Usage:
    python auto_enrich_contain.py 185.220.101.50
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.request

RISKY_PORTS = {23, 445, 3389, 3306, 6379, 5900}
BAD_TAGS = {"malware", "c2", "compromised", "tor", "scanner", "botnet"}


def enrich_ip(ip: str) -> dict:
    """Live enrichment via Shodan InternetDB (keyless). Fails soft to an empty result."""
    try:
        req = urllib.request.Request(
            f"https://internetdb.shodan.io/{ip}",
            headers={"User-Agent": "soar-playbook/1.0", "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode())
        return {"ip": ip, "ports": data.get("ports", []), "tags": data.get("tags", []),
                "vulns": data.get("vulns", []), "hostnames": data.get("hostnames", [])}
    except Exception:  # noqa: BLE001 - enrichment must never crash the playbook
        return {"ip": ip, "ports": [], "tags": [], "vulns": [], "hostnames": []}


def decide(enrichment: dict) -> dict:
    """Pure decision logic. Returns a score, verdict, and human reasons."""
    score, reasons = 0, []
    if enrichment.get("vulns"):
        score += 3
        reasons.append(f"{len(enrichment['vulns'])} known CVE(s)")
    if set(t.lower() for t in enrichment.get("tags", [])) & BAD_TAGS:
        score += 2
        reasons.append("malicious reputation tag")
    if set(enrichment.get("ports", [])) & RISKY_PORTS:
        score += 1
        reasons.append("risky exposed port(s)")
    verdict = "CONTAIN" if score >= 3 else "INVESTIGATE" if score >= 1 else "MONITOR"
    return {"score": score, "verdict": verdict, "reasons": reasons}


def run_playbook(alert: dict, enricher=enrich_ip) -> dict:
    ip = alert["src_ip"]
    enrichment = enricher(ip)
    decision = decide(enrichment)
    actions = []
    if decision["verdict"] == "CONTAIN":
        actions = [
            {"action": "block_ip", "target": ip},
            {"action": "notify", "channel": "soc",
             "message": f"Auto-contained {ip}: {', '.join(decision['reasons'])}"},
        ]
    elif decision["verdict"] == "INVESTIGATE":
        actions = [{"action": "create_ticket", "target": ip,
                    "message": f"Investigate {ip}: {', '.join(decision['reasons'])}"}]
    return {"ip": ip, "enrichment": enrichment, "decision": decision, "actions": actions}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="auto_enrich_contain")
    ap.add_argument("ip")
    args = ap.parse_args(argv)
    result = run_playbook({"src_ip": args.ip})
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
