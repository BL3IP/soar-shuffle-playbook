from auto_enrich_contain import decide, run_playbook


def test_decide_contain_on_vulns():
    d = decide({"vulns": ["CVE-2021-1234"], "tags": [], "ports": [3389]})
    assert d["verdict"] == "CONTAIN"
    assert d["score"] >= 3


def test_decide_monitor_on_clean():
    d = decide({"vulns": [], "tags": [], "ports": [443]})
    assert d["verdict"] == "MONITOR"
    assert d["score"] == 0


def test_decide_investigate_on_risky_port():
    d = decide({"vulns": [], "tags": [], "ports": [445]})
    assert d["verdict"] == "INVESTIGATE"


def test_run_playbook_contain_actions():
    bad = {"ip": "1.2.3.4", "ports": [3389], "tags": ["c2"], "vulns": ["CVE-2019-0708"], "hostnames": []}
    result = run_playbook({"src_ip": "1.2.3.4"}, enricher=lambda ip: bad)
    assert result["decision"]["verdict"] == "CONTAIN"
    actions = {a["action"] for a in result["actions"]}
    assert "block_ip" in actions and "notify" in actions


def test_run_playbook_monitor_no_actions():
    clean = {"ip": "8.8.8.8", "ports": [53, 443], "tags": [], "vulns": [], "hostnames": ["dns.google"]}
    result = run_playbook({"src_ip": "8.8.8.8"}, enricher=lambda ip: clean)
    assert result["decision"]["verdict"] == "MONITOR"
    assert result["actions"] == []
