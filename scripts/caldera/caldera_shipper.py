#!/usr/bin/env python3
"""
Caldera v5 -> Wazuh event-log shipper.

Polls the MITRE Caldera v2 REST API for operation event-logs and emits each
executed ability as a syslog line tagged `caldera`, in the exact format the
Wazuh `caldera-ttp-marker` decoder expects:

    CALDERA_TTP technique_id=<id> operation=<name> ability=<name> agent=<paw> status=<code>

Wazuh's logcollector already reads /var/log/syslog, so no <localfile> change is
needed. Deduplication is handled by a local state file keyed on
finished_timestamp|paw|ability_id.

This replaces the earlier "alert storm" approach (hardcoded logger loops) with
telemetry sourced from real operations run against a live Sandcat agent.

Environment (edit to match your install):
    CALDERA   - base URL of the Caldera server (loopback recommended)
    API_KEY   - api_key_red value from conf/local.yml
"""
import json
import os
import subprocess
import sys
import time
import urllib.request

CALDERA  = os.environ.get("CALDERA_URL", "http://127.0.0.1:8888")
API_KEY  = os.environ.get("CALDERA_API_KEY", "REPLACE_WITH_api_key_red")
STATE    = os.environ.get("CALDERA_STATE", "/opt/caldera-wazuh/state.json")
INTERVAL = int(os.environ.get("CALDERA_INTERVAL", "30"))


def api_get(path):
    req = urllib.request.Request(f"{CALDERA}{path}", headers={"KEY": API_KEY})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read().decode())


def api_post(path, body):
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        f"{CALDERA}{path}", data=data, method="POST",
        headers={"KEY": API_KEY, "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read().decode())


def load_state():
    try:
        with open(STATE) as f:
            return set(json.load(f))
    except Exception:
        return set()


def save_state(seen):
    tmp = STATE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(sorted(seen)[-5000:], f)
    os.replace(tmp, STATE)


def emit(ev):
    at = ev.get("attack_metadata")    or {}
    ag = ev.get("agent_metadata")     or {}
    ab = ev.get("ability_metadata")   or {}
    op = ev.get("operation_metadata") or {}
    msg = (
        f"CALDERA_TTP "
        f"technique_id={at.get('technique_id', 'T0000')} "
        f"operation={(op.get('operation_name') or 'unknown').replace(' ', '_')} "
        f"ability={(ab.get('ability_name') or 'unknown').replace(' ', '_')} "
        f"agent={ag.get('paw', 'unknown')} "
        f"status={ev.get('status', 'unknown')}"
    )
    subprocess.run(["logger", "-t", "caldera", msg], check=False)


def key(ev):
    ag = ev.get("agent_metadata") or {}
    ab = ev.get("ability_metadata") or {}
    return f"{ev.get('finished_timestamp')}|{ag.get('paw')}|{ab.get('ability_id')}"


def main():
    seen = load_state()
    while True:
        try:
            for op in api_get("/api/v2/operations"):
                # NOTE: v5 exposes event-logs via POST with an empty body,
                # not GET. A GET returns 405 Method Not Allowed.
                evs = api_post(f"/api/v2/operations/{op['id']}/event-logs", {})
                for ev in evs:
                    k = key(ev)
                    if k not in seen:
                        emit(ev)
                        seen.add(k)
            save_state(seen)
        except Exception as e:
            print(f"[shipper] {e}", file=sys.stderr, flush=True)
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
