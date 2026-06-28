# SOAR Workflow Design — Auto-Enrich & Contain

The playbook ([`../playbook/auto_enrich_contain.py`](../playbook/auto_enrich_contain.py)) implements
the same logic as a Shuffle workflow. Mapping to Shuffle nodes:

```
[ Webhook trigger ]                # alert arrives with src_ip (from SIEM/EDR)
        |
[ HTTP node: enrich ]              # GET https://internetdb.shodan.io/{src_ip}
        |                          #   -> ports, tags, vulns, hostnames
[ Shuffle Tools: condition ]      # score: vulns(+3), malicious tag(+2), risky port(+1)
        |                          #   verdict = CONTAIN(>=3) / INVESTIGATE(>=1) / MONITOR(0)
   /----+----\
[CONTAIN]   [INVESTIGATE]          # branch on verdict
   |             |
[block_ip]   [create_ticket]       # firewall/EDR app  |  ticketing app
[notify SOC]                       # Slack/Teams/email app
```

## Importing into the live Shuffle
1. Deploy Shuffle: `docker compose up -d` (see README). Open `https://localhost:3443`, create the
   first admin user.
2. New Workflow → add a **Webhook** trigger.
3. Add an **HTTP** action: GET `https://internetdb.shodan.io/$exec.src_ip`.
4. Add a **condition** on `$enrich.vulns`, `$enrich.tags`, `$enrich.ports` (the scoring above).
5. On CONTAIN: add your firewall/EDR app's `block_ip` + a Slack/Teams `notify` action.
6. Save, copy the webhook URL, and POST a test alert:
   `curl -k -X POST <webhook-url> -d '{"src_ip":"45.33.32.156"}'`

The Python playbook lets you develop/test the exact decision logic offline before wiring it into
Shuffle's UI apps.
