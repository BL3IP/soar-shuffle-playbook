# 19 — SOAR Automation (Shuffle) — Auto-Enrich & Contain

[![CI](https://github.com/BL3IP/soar-shuffle-playbook/actions/workflows/ci.yml/badge.svg)](https://github.com/BL3IP/soar-shuffle-playbook/actions/workflows/ci.yml)

A **Shuffle** SOAR platform deployed with Docker, plus an **auto-enrich → decide → contain**
playbook that enriches a suspicious IP and takes a containment action — the core of SOC automation.

## Goal
Stand up an open-source SOAR and build an alert-response playbook that automatically enriches an
indicator and decides whether to contain it — removing manual triage toil.

## What's inside
| Path | What it is |
|------|-----------|
| [`playbook/auto_enrich_contain.py`](./playbook/auto_enrich_contain.py) | The playbook logic (enrich + score + contain) |
| [`playbook/test_auto_enrich_contain.py`](./playbook/test_auto_enrich_contain.py) | pytest suite (deterministic) |
| [`docs/workflow-design.md`](./docs/workflow-design.md) | The Shuffle workflow design + import steps |
| [`artifacts/shuffle-deployment.txt`](./artifacts/shuffle-deployment.txt) | Proof: all Shuffle containers running |
| [`artifacts/playbook-run-example.json`](./artifacts/playbook-run-example.json) | A live CONTAIN run |

## Exact Setup Commands
```powershell
# 1) Deploy Shuffle (SOAR)
git clone https://github.com/Shuffle/Shuffle.git
wsl -d docker-desktop sysctl -w vm.max_map_count=262144   # for OpenSearch
cd Shuffle ; docker compose up -d                          # UI at https://localhost:3443

# 2) Run the playbook logic (and test it)
cd C:\Users\banlv\cyber\19-soar-automation
& "C:\Users\banlv\AppData\Local\Programs\Python\Python312\python.exe" -m venv .venv
.\.venv\Scripts\python.exe -m pip install pytest
.\.venv\Scripts\python.exe -m pytest playbook\ -q
.\.venv\Scripts\python.exe playbook\auto_enrich_contain.py 45.33.32.156
```

## Proof It Works
**Shuffle deployed** — all 4 containers Up, UI returns **HTTP 200** on `:3001`/`:3443`
([proof](./artifacts/shuffle-deployment.txt)):
```
shuffle-frontend   Up   0.0.0.0:3001->80, 0.0.0.0:3443->443
shuffle-backend    Up   0.0.0.0:5001->5001
shuffle-opensearch Up   0.0.0.0:9200->9200
shuffle-orborus    Up
```
**Playbook — 5/5 tests pass**, and live runs make real decisions from real enrichment:
```
45.33.32.156    -> CONTAIN      (score 3; 120 known CVEs) -> block_ip + notify SOC
185.220.100.240 -> INVESTIGATE  (score 2; tag 'tor')      -> create_ticket
8.8.8.8 / 1.1.1.1 -> MONITOR    (clean)                   -> no action
```

## Screenshots
See [`./screenshots/`](./screenshots). Add: the Shuffle UI (https://localhost:3443) and a playbook run.

## My Custom Extensions
- A **portable, unit-tested** playbook (enrich/score/contain) so the decision logic is developed and
  validated offline before wiring into Shuffle's UI apps.
- Real, keyless enrichment (Shodan InternetDB) drives live CONTAIN/INVESTIGATE/MONITOR verdicts.
- Full deployment runbook incl. the OpenSearch `vm.max_map_count` fix for Docker Desktop/WSL2.

## Resume Bullet Points
- Deployed the **Shuffle** open-source SOAR (Docker, 4-service stack incl. OpenSearch) and verified
  the platform end-to-end.
- Built and unit-tested an **auto-enrich-and-contain** playbook that scores live IP enrichment and
  triggers block/notify/ticket actions (5/5 tests; live CONTAIN on a host with 120 CVEs).
- Documented the equivalent Shuffle workflow (webhook → HTTP enrich → condition → contain).

## Next-Level Ideas
- Build the workflow natively in Shuffle and trigger it via webhook from the SIEM (project 01).
- Add real containment apps (firewall/EDR API) and an approval step for destructive actions.
- Feed the threat-intel brief (project 09) as a daily enrichment source.

---
status: ✅ complete & tested
```
✅ PROJECT COMPLETE & FULLY TESTED in its isolated folder. All works. Ready for portfolio.
```
