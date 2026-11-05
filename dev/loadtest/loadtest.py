#!/usr/bin/env python3
# This file is part of Dependency-Track.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) OWASP Foundation. All Rights Reserved.
import argparse
import base64
import contextlib
import json
import os
import platform
import secrets
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
STATE = HERE / ".state"
RESULTS = HERE / "results"
DUMP = STATE / "osv.dump"
PROJECT = "dt-sbom-benchmark"
API = "http://127.0.0.1:18080/api"
READY = "http://127.0.0.1:19000/health/ready"
CANARY_VULN = "LOADTEST-CANARY"
CANARY_PURL = "pkg:npm/loadtest-canary@1.0.0"
OSV_CANARY_PURL = "pkg:npm/lodash@4.17.15"
CRITICAL_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
PERMISSIONS = (
    "BOM_UPLOAD",
    "POLICY_MANAGEMENT",
    "PORTFOLIO_MANAGEMENT",
    "PROJECT_CREATION_UPLOAD",
    "SYSTEM_CONFIGURATION",
    "VIEW_POLICY_VIOLATION",
    "VIEW_PORTFOLIO",
    "VIEW_VULNERABILITY",
    "VULNERABILITY_MANAGEMENT",
)
STEP_RATES = (1, 2, 4, 5.56)
NETSHOOT = "nicolaka/netshoot:v0.14@sha256:7f08c4aff13ff61a35d30e30c5c1ea8396eac6ab4ce19fd02d5a4b3b5d0d09a2"
WARMUP_SECONDS = 300
STEP_BACKLOG_SECONDS = 20
HOLD_BACKLOG_SECONDS = 60
BURST_TIMEOUT_SECONDS = 3 * 3600


def foreign_volumes(volumes, owned):
    return [] if owned else [v for v in volumes if v.startswith(f"{PROJECT}_")]


def join_runs(imports, analyses):
    analysis_by_token = {
        run["labels"]["bom_upload_token"]: run for run in analyses if "bom_upload_token" in run.get("labels", {})
    }
    sboms = []
    for run in imports:
        token = run["labels"]["bom_upload_token"]
        analysis = analysis_by_token.get(token)
        if run["status"] in ("FAILED", "CANCELLED") or (analysis and analysis["status"] in ("FAILED", "CANCELLED")):
            status = "FAILED"
        elif analysis and analysis["status"] == "COMPLETED":
            status = "COMPLETED"
        else:
            status = "MISSING"
        completed_at = analysis["completed_at"] if status == "COMPLETED" else None
        sboms.append(
            {
                "token": token,
                "status": status,
                "created_at": run["created_at"],
                "imported_at": run["completed_at"] if run["status"] == "COMPLETED" else None,
                "completed_at": completed_at,
                "latency": (completed_at - run["created_at"]) / 1000 if completed_at else None,
            }
        )
    return sboms


def _percentile(sorted_values, percent):
    if not sorted_values:
        return None
    return sorted_values[min(len(sorted_values) - 1, int(len(sorted_values) * percent / 100))]


def _latencies(sboms):
    values = sorted(s["latency"] for s in sboms if s["status"] == "COMPLETED")
    return {"p50": _percentile(values, 50), "p95": _percentile(values, 95), "p99": _percentile(values, 99)}


def _backlog_at(sboms, epoch_ms):
    arrived = sum(1 for s in sboms if s["created_at"] < epoch_ms)
    completed = sum(1 for s in sboms if s["status"] == "COMPLETED" and s["completed_at"] < epoch_ms)
    return arrived - completed


def evaluate_rate(sboms, start, seconds, rate, warmup_seconds, backlog_seconds, dropped, upload_failures):
    start_ms = start.timestamp() * 1000
    window_start = start_ms + warmup_seconds * 1000
    window_end = start_ms + seconds * 1000
    window_seconds = seconds - warmup_seconds

    in_window = [s for s in sboms if window_start <= s["created_at"] < window_end]
    failed = sum(1 for s in in_window if s["status"] == "FAILED")
    missing = sum(1 for s in in_window if s["status"] == "MISSING")
    completions = sum(
        1 for s in sboms if s["status"] == "COMPLETED" and window_start <= s["completed_at"] < window_end
    )
    imports = sum(1 for s in sboms if s.get("imported_at") and window_start <= s["imported_at"] < window_end)
    backlog_growth = _backlog_at(sboms, window_end) - _backlog_at(sboms, window_start)
    arrival_rate = len(in_window) / window_seconds
    backlog_limit = rate * backlog_seconds

    reasons = []
    if failed:
        reasons.append(f"{failed} failed SBOMs in the window")
    if missing:
        reasons.append(f"{missing} missing SBOMs in the window")
    if dropped:
        reasons.append(f"{dropped} dropped iterations")
    if upload_failures:
        reasons.append(f"{upload_failures} upload failures")
    if abs(arrival_rate - rate) > rate * 0.01:
        reasons.append(f"arrival rate {arrival_rate:.2f}/s is more than 1% from {rate}/s")
    if backlog_growth > backlog_limit:
        reasons.append(f"backlog grew by {backlog_growth}, limit is {backlog_limit:.0f}")

    return {
        "passed": not reasons,
        "reasons": reasons,
        "target_rate": rate,
        "arrived": len(in_window),
        "arrival_rate": arrival_rate,
        "completed_per_hour": completions / window_seconds * 3600,
        "imports_per_second": imports / window_seconds,
        "backlog_growth": backlog_growth,
        "failed": failed,
        "missing": missing,
        "dropped": dropped,
        "upload_failures": upload_failures,
        "latency_seconds": _latencies(in_window),
    }


def evaluate_burst(sboms, expected, upload_failures):
    completed = [s for s in sboms if s["status"] == "COMPLETED"]
    unfinished = len(sboms) - len(completed)
    first = min((s["created_at"] for s in sboms), default=0)
    last = max((s["completed_at"] for s in completed), default=first)
    drain_seconds = (last - first) / 1000

    reasons = []
    if len(sboms) != expected:
        reasons.append(f"{len(sboms)} SBOMs arrived, expected {expected}")
    if unfinished:
        reasons.append(f"{unfinished} SBOMs did not complete")
    if upload_failures:
        reasons.append(f"{upload_failures} upload failures")
    if drain_seconds > 3600:
        reasons.append(f"took {drain_seconds:.0f}s, over one hour")

    return {
        "passed": not reasons,
        "reasons": reasons,
        "arrived": len(sboms),
        "drain_seconds": drain_seconds,
        "completed_per_hour": len(completed) / drain_seconds * 3600 if drain_seconds else 0,
        "upload_failures": upload_failures,
        "latency_seconds": _latencies(sboms),
    }


def _state(name):
    return (STATE / name).read_text().strip()


def _save_state(name, value):
    STATE.mkdir(exist_ok=True)
    path = STATE / name
    path.touch(mode=0o600)
    path.write_text(value)


def _kek():
    if not (STATE / "kek").exists():
        _save_state("kek", base64.b64encode(secrets.token_bytes(32)).decode())
    return _state("kek")


def compose_command(*args):
    return [
        "docker",
        "compose",
        "-p",
        PROJECT,
        "-f",
        str(REPO / "dev/compose.yaml"),
        "-f",
        str(REPO / "dev/monitoring/compose.yaml"),
        "-f",
        str(HERE / "compose.yaml"),
        *args,
    ]


def compose_env():
    return os.environ | {"LOADTEST_KEK": _kek()}


def compose(*args, **kwargs):
    return subprocess.run(compose_command(*args), check=True, env=compose_env(), **kwargs)


def psql(sql, database="dtrack"):
    result = compose(
        "exec", "-T", "postgres", "psql", "-U", "dtrack", "-d", database, "-Atc", sql, capture_output=True, text=True
    )
    return result.stdout.strip()


def request(method, path, body=None, form=None, headers=None, key=True):
    headers = dict(headers or {})
    data = None
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if key:
        headers["X-Api-Key"] = _state("api-key")
    req = urllib.request.Request(f"{API}{path}", data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            raw = response.read().decode()
    except urllib.error.HTTPError as e:
        sys.exit(f"{method} {path} returned {e.code}: {e.read().decode()[:500]}")
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return raw


def wait_ready(timeout=300):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            # Health alone isn't enough: it stays UP when startup fails after the management server is listening.
            with urllib.request.urlopen(READY, timeout=5), urllib.request.urlopen(f"{API}/version", timeout=5):
                return
        except OSError:
            pass
        time.sleep(3)
    sys.exit(f"API server not ready after {timeout}s. Check: docker compose -p {PROJECT} logs apiserver")


def wait_token(token, timeout=300):
    deadline = time.time() + timeout
    while time.time() < deadline:
        status = request("GET", f"/v1/event/token/{token}").get("status")
        if status == "COMPLETED":
            return
        if status == "FAILED":
            sys.exit(f"Canary token {token} reported FAILED")
        time.sleep(2)
    sys.exit(f"Canary token {token} did not complete within {timeout}s")


def canary(purl, expected_vuln=None):
    name = f"loadtest-canary-{int(time.time())}"
    component = {
        "type": "library",
        "bom-ref": purl,
        "name": "canary",
        "version": "1.0.0",
        "purl": purl,
        "licenses": [{"license": {"id": "ISC"}}],
    }
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "components": [component]}
    uploaded = request(
        "PUT",
        "/v1/bom",
        {
            "projectName": name,
            "projectVersion": "1",
            "autoCreate": True,
            "bom": base64.b64encode(json.dumps(bom).encode()).decode(),
        },
    )
    wait_token(uploaded["token"])
    project = request("GET", f"/v1/project/lookup?name={name}&version=1")["uuid"]
    findings = request("GET", f"/v1/finding/project/{project}")
    violations = request("GET", f"/v1/violation/project/{project}")
    request("DELETE", f"/v1/project/{project}")

    vulns = {f["vulnerability"]["vulnId"] for f in findings}
    if not vulns or (expected_vuln and expected_vuln not in vulns):
        sys.exit(f"Canary {purl} expected findings ({expected_vuln or 'any'}), got: {sorted(vulns)}")
    if not violations:
        sys.exit(f"Canary {purl} expected a policy violation, got none")
    print(f"Canary passed: {len(findings)} findings, {len(violations)} violations")


def cmd_up(_):
    owner = STATE / "owner"
    volumes = subprocess.run(
        ["docker", "volume", "ls", "--format", "{{.Name}}"], check=True, capture_output=True, text=True
    ).stdout.split()
    foreign = foreign_volumes(volumes, owned=owner.exists())
    if foreign:
        sys.exit(f"Refusing to reuse volumes this script didn't create: {', '.join(foreign)}")
    _save_state("owner", PROJECT)
    RESULTS.mkdir(exist_ok=True)
    compose("up", "-d", "--wait", "postgres")
    compose("up", "-d", "apiserver", "prometheus", "grafana")
    wait_ready()
    print(f"Ready. API: {API}, Grafana: http://127.0.0.1:3000")


def cmd_down(_):
    if not (STATE / "owner").exists():
        sys.exit(f"Refusing to delete volumes this script didn't create. Check the {PROJECT} project by hand.")
    compose("--profile", "tools", "down", "-v", "--remove-orphans")
    for name in ("admin-password", "api-key", "owner"):
        (STATE / name).unlink(missing_ok=True)


def cmd_bootstrap(_):
    wait_ready()
    password = secrets.token_urlsafe(24)
    try:
        urllib.request.urlopen(
            urllib.request.Request(
                f"{API}/v1/user/forceChangePassword",
                data=urllib.parse.urlencode(
                    {"username": "admin", "password": "admin", "newPassword": password, "confirmPassword": password}
                ).encode(),
                method="POST",
            ),
            timeout=30,
        )
    except urllib.error.HTTPError as e:
        sys.exit(f"Refusing to bootstrap: admin/admin isn't awaiting a password change ({e.code}). Run 'down' first.")
    _save_state("admin-password", password)

    jwt = request("POST", "/v1/user/login", form={"username": "admin", "password": password}, key=False)
    bearer = {"Authorization": f"Bearer {jwt}"}
    team = request("PUT", "/v1/team", {"name": "loadtest"}, headers=bearer, key=False)["uuid"]
    _save_state("api-key", request("PUT", f"/v1/team/{team}/key", headers=bearer, key=False)["key"])
    for permission in PERMISSIONS:
        request("POST", f"/v1/permission/{permission}/team/{team}", headers=bearer, key=False)

    license_uuid = request("GET", "/v1/license/ISC")["uuid"]
    for name, condition in (
        ("license-isc", {"subject": "LICENSE", "operator": "IS", "value": license_uuid}),
        ("severity-critical", {"subject": "SEVERITY", "operator": "IS", "value": "CRITICAL"}),
    ):
        policy = request("PUT", "/v1/policy", {"name": name, "operator": "ANY", "violationState": "FAIL"})["uuid"]
        request("PUT", f"/v1/policy/{policy}/condition", condition)

    request(
        "PUT",
        "/v1/vulnerability",
        {
            "vulnId": CANARY_VULN,
            "cvssV3Vector": CRITICAL_VECTOR,
            "affectedComponents": [{"identityType": "PURL", "identity": CANARY_PURL, "versionType": "EXACT"}],
        },
    )
    psql('ALTER TABLE "COMPONENT" SET (autovacuum_vacuum_scale_factor = 0.02)')
    canary(CANARY_PURL, CANARY_VULN)


def cmd_mirror(args):
    path = "/v2/extension-points/vuln-data-source/extensions/osv/config"
    config = request("GET", path)["config"] | {"enabled": True, "ecosystems": ["npm", "Maven"]}
    request("PUT", path, {"config": config})
    request("POST", "/v2/vuln-data-sources/osv/mirror-runs")

    started = time.time()
    while True:
        latest = request("GET", "/v2/vuln-data-sources/osv/mirror-runs/latest")
        if latest["status"] == "COMPLETED":
            break
        if latest["status"] == "FAILED":
            sys.exit(f"OSV mirror failed: {latest.get('failure_reason')}")
        if time.time() - started > args.timeout_hours * 3600:
            sys.exit(f"OSV mirror still {latest['status']} after {args.timeout_hours}h")
        time.sleep(30)
    print(f"OSV mirror finished in {(time.time() - started) / 60:.0f} minutes")

    canary(OSV_CANARY_PURL)
    with DUMP.open("wb") as out:
        compose("exec", "-T", "postgres", "pg_dump", "-Fc", "-U", "dtrack", "dtrack", stdout=out)
    _save_state("osv-mirror-date", datetime.now(timezone.utc).isoformat())
    print(f"Wrote {DUMP}")


def restore():
    if not DUMP.exists():
        sys.exit("No dump found. Run 'mirror' first, or pass --no-restore.")
    compose("rm", "-sfv", "apiserver")
    subprocess.run(["docker", "volume", "rm", "-f", f"{PROJECT}_apiserver-data"], check=True, capture_output=True)
    psql("DROP DATABASE IF EXISTS dtrack WITH (FORCE)", database="postgres")
    psql("CREATE DATABASE dtrack", database="postgres")
    with DUMP.open("rb") as dump:
        compose("exec", "-T", "postgres", "pg_restore", "-U", "dtrack", "-d", "dtrack", "--no-owner", stdin=dump)
    psql("ANALYZE")
    compose("up", "-d", "apiserver")
    wait_ready()


def postgres_tc(*args):
    container = compose("ps", "-q", "postgres", capture_output=True, text=True).stdout.strip()
    command = ["docker", "run", "--rm", "--cap-add", "NET_ADMIN", "--network", f"container:{container}", NETSHOOT, "tc"]
    return subprocess.run([*command, *args], check=True, capture_output=True, text=True).stdout.strip()


def add_postgres_latency(milliseconds):
    # Delaying only PostgreSQL's replies adds the full amount to each round trip.
    postgres_tc("qdisc", "replace", "dev", "eth0", "root", "netem", "delay", f"{milliseconds}ms")


def remove_postgres_latency():
    postgres_tc("qdisc", "del", "dev", "eth0", "root")


def sample_stats(directory, stop):
    with (directory / "docker-stats.jsonl").open("a") as out:
        while not stop.wait(30):
            result = subprocess.run(
                ["docker", "stats", "--no-stream", "--format", "{{json .}}"], capture_output=True, text=True
            )
            timestamp = datetime.now(timezone.utc).isoformat()
            for line in result.stdout.splitlines():
                stat = json.loads(line)
                if stat["Name"].startswith(PROJECT):
                    keep = {"time": timestamp, "name": stat["Name"], "cpu": stat["CPUPerc"], "mem": stat["MemUsage"]}
                    out.write(json.dumps(keep) + "\n")
            out.flush()
            if platform.system() == "Darwin":
                therm = subprocess.run(["pmset", "-g", "therm"], capture_output=True, text=True).stdout
                with (directory / "therm.log").open("a") as log:
                    log.write(f"{timestamp}\n{therm}\n")


def fetch_runs(workflow, since_ms):
    runs = []
    page_token = None
    while True:
        query = {"workflow_name": workflow, "created_since": since_ms, "limit": 1000}
        if page_token:
            query["page_token"] = page_token
        page = request("GET", f"/v2/internal/workflow-runs?{urllib.parse.urlencode(query)}")
        runs.extend(page["items"])
        page_token = page.get("next_page_token")
        if not page_token:
            return runs


def fetch_sboms(since_ms):
    imports = [r for r in fetch_runs("import-bom", since_ms) if "bom_upload_token" in r.get("labels", {})]
    return join_runs(imports, fetch_runs("analyze-project", since_ms))


def wait_for_drain(since_ms, timeout):
    deadline = time.time() + timeout
    while True:
        sboms = fetch_sboms(since_ms)
        unfinished = sum(1 for s in sboms if s["status"] == "MISSING")
        if not unfinished or time.time() > deadline:
            return sboms
        print(f"Waiting for {unfinished} SBOMs to finish")
        time.sleep(15)


def verify_tokens(sboms):
    def status(token):
        return request("GET", f"/v1/event/token/{token}").get("status")

    with ThreadPoolExecutor(max_workers=4) as pool:
        statuses = list(pool.map(status, [s["token"] for s in sboms]))
    return sum(1 for s, reported in zip(sboms, statuses) if (s["status"] == "COMPLETED") != (reported == "COMPLETED"))


def record_metadata(directory, args):
    def inspect(service):
        cid = compose("ps", "-q", service, capture_output=True, text=True).stdout.strip()
        if not cid:
            return {"running": False}
        details = json.loads(
            subprocess.run(["docker", "inspect", cid], check=True, capture_output=True, text=True).stdout
        )[0]
        return {
            "image": details["Image"],
            "running": details["State"]["Running"],
            "oom_killed": details["State"]["OOMKilled"],
            "exit_code": details["State"]["ExitCode"],
            "restarts": details["RestartCount"],
        }

    tables = ("PROJECT", "COMPONENT", "VULNERABILITY", "VULNERABLESOFTWARE", "FINDINGATTRIBUTION", "POLICYVIOLATION")
    machine = subprocess.run(["docker", "info", "--format", "{{.NCPU}} {{.MemTotal}}"], capture_output=True, text=True)
    git = ["git", "-C", str(REPO)]
    mirror_date = STATE / "osv-mirror-date"
    metadata = {
        "args": {k: v for k, v in vars(args).items() if k != "func"},
        "git_commit": subprocess.run([*git, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip(),
        "git_dirty": bool(subprocess.run([*git, "status", "--porcelain"], capture_output=True, text=True).stdout),
        "host": platform.platform(),
        "docker_cpus_memory": machine.stdout.strip(),
        "apiserver": inspect("apiserver"),
        "postgres": inspect("postgres"),
        "postgres_version": psql("SHOW server_version"),
        "pg_settings": psql(
            "SELECT string_agg(name || '=' || setting, ', ') FROM pg_settings "
            "WHERE source NOT IN ('default', 'override')"
        ),
        "row_counts": {t: int(psql(f'SELECT count(*) FROM "{t}"')) for t in tables},
        "osv_mirror_date": mirror_date.read_text() if mirror_date.exists() else None,
    }
    (directory / "metadata.json").write_text(json.dumps(metadata, indent=2))
    return metadata


def run_k6(directory, env):
    env = {
        "API_KEY": _state("api-key"),
        "RESULTS_DIR": f"/results/{directory.relative_to(RESULTS)}",
        **{key: str(value) for key, value in env.items()},
    }
    flags = [item for key in env for item in ("-e", key)]
    # k6 exits non-zero when a threshold fails, which the report treats as a result rather than an error.
    command = compose_command("run", "--rm", *flags, "k6", "run", "--quiet", "/src/dev/loadtest/load.js")
    subprocess.run(command, env=compose_env() | env)
    summary = json.loads((directory / "k6-summary.json").read_text())["metrics"]

    def count(metric):
        return summary.get(metric, {}).get("values", {}).get("count", 0)

    return {"dropped": int(count("dropped_iterations")), "upload_failures": int(count("upload_failed"))}


def run_scenario(label, args, k6_env, drain_timeout, evaluate):
    directory = RESULTS / label
    directory.mkdir(parents=True)
    stop = threading.Event()
    sampler = threading.Thread(target=sample_stats, args=(directory, stop), daemon=True)
    sampler.start()
    since_ms = int(time.time() * 1000)
    try:
        k6 = run_k6(directory, k6_env | {"RUN_ID": label.replace("/", "-")})
        sboms = wait_for_drain(since_ms, drain_timeout)
    finally:
        stop.set()

    report = evaluate(sboms, k6)
    report["token_status_mismatches"] = verify_tokens(sboms)
    metadata = record_metadata(directory, args)
    if report["token_status_mismatches"]:
        report["reasons"].append(f"{report['token_status_mismatches']} tokens disagree with the status endpoint")
    if not metadata["apiserver"]["running"] or metadata["apiserver"]["oom_killed"]:
        report["reasons"].append("API server container crashed or ran out of memory")
    if not metadata["postgres"]["running"] or metadata["postgres"]["oom_killed"]:
        report["reasons"].append("PostgreSQL container crashed or ran out of memory")
    report["passed"] = not report["reasons"]
    (directory / "report.json").write_text(json.dumps(report, indent=2))
    (directory / "tokens.json").write_text(json.dumps(sboms))
    print(json.dumps(report, indent=2))
    return report


def run_rate(label, args, rate, minutes, backlog_seconds, drain_timeout):
    def evaluate(sboms, k6):
        start = datetime.fromtimestamp(min(s["created_at"] for s in sboms) / 1000, timezone.utc) if sboms else None
        if start is None:
            return {"passed": False, "reasons": ["no SBOMs arrived"], **k6}
        warmup = min(WARMUP_SECONDS, minutes * 60 / 3)
        return evaluate_rate(sboms, start, minutes * 60, rate, warmup, backlog_seconds, **k6)

    env = {
        "MODE": "rate",
        "RATE": rate,
        "MINUTES": minutes,
        "COMPONENTS": args.components,
        "VUS": args.vus,
        "POLLS": args.polls,
        "PROJECTS": args.projects,
    }
    return run_scenario(label, args, env, drain_timeout, evaluate)


def _label(kind, args):
    return f"{datetime.now().strftime('%Y%m%d-%H%M')}-{kind}-{args.components}c"


@contextlib.contextmanager
def postgres_latency(milliseconds):
    if not milliseconds:
        yield
        return
    add_postgres_latency(milliseconds)
    try:
        yield
    finally:
        remove_postgres_latency()


def cmd_step(args):
    if not args.no_restore:
        restore()
    base = _label("step", args)
    rates = [float(r) for r in args.rates.split(",")]
    last_pass = 0
    failed_rate = None
    with postgres_latency(args.pg_latency_ms):
        for rate in rates:
            report = run_rate(f"{base}/rate-{rate}", args, rate, args.minutes, STEP_BACKLOG_SECONDS, 300)
            if not report["passed"]:
                failed_rate = rate
                break
            last_pass = rate
        if failed_rate is not None and not args.no_refine:
            refined = round((last_pass + failed_rate) / 2, 2)
            if refined not in (last_pass, failed_rate):
                run_rate(f"{base}/rate-{refined}", args, refined, args.minutes, STEP_BACKLOG_SECONDS, 300)
    print(f"Highest listed rate passed: {last_pass}. Results: {RESULTS / base}")


def cmd_hold(args):
    if not args.no_restore:
        restore()
    with postgres_latency(args.pg_latency_ms):
        report = run_rate(_label(f"hold-{args.rate}", args), args, args.rate, args.minutes, HOLD_BACKLOG_SECONDS, 600)
    sys.exit(0 if report["passed"] else 1)


def cmd_burst(args):
    if not args.no_restore:
        restore()

    def evaluate(sboms, k6):
        return evaluate_burst(sboms, expected=args.count, upload_failures=k6["upload_failures"])

    env = {"MODE": "burst", "COUNT": args.count, "COMPONENTS": args.components, "VUS": args.burst_vus, "POLLS": 0}
    report = run_scenario(_label("burst", args), args, env, BURST_TIMEOUT_SECONDS, evaluate)
    sys.exit(0 if report["passed"] else 1)


def main():
    parser = argparse.ArgumentParser(description="Local Dependency-Track load test. See README.md.")
    commands = parser.add_subparsers(required=True)

    commands.add_parser("up", help="start PostgreSQL, the API server, and monitoring").set_defaults(func=cmd_up)
    commands.add_parser("down", help="stop everything and delete its volumes").set_defaults(func=cmd_down)
    bootstrap = commands.add_parser("bootstrap", help="prepare a fresh instance and run the canary")
    bootstrap.set_defaults(func=cmd_bootstrap)

    mirror = commands.add_parser("mirror", help="mirror OSV, run the canary, and write the dump")
    mirror.add_argument("--timeout-hours", type=float, default=6)
    mirror.set_defaults(func=cmd_mirror)

    def load_options(command):
        command.add_argument("--components", type=int, default=500)
        command.add_argument("--no-restore", action="store_true", help="keep the current database")

    def rate_options(command):
        load_options(command)
        command.add_argument("--vus", type=int, default=64)
        command.add_argument("--polls", type=int, default=12, help="status polls per upload")
        command.add_argument("--pg-latency-ms", type=float, default=0, help="delay added to each PostgreSQL round trip")
        command.add_argument("--projects", type=int, default=0, help="re-upload to this many projects, 5%% changed")

    step = commands.add_parser("step", help="raise the rate until one fails")
    rate_options(step)
    step.add_argument("--rates", default=",".join(str(r) for r in STEP_RATES))
    step.add_argument("--minutes", type=float, default=15)
    step.add_argument("--no-refine", action="store_true", help="skip the extra rate after a failure")
    step.set_defaults(func=cmd_step)

    hold = commands.add_parser("hold", help="hold one rate")
    rate_options(hold)
    hold.add_argument("--rate", type=float, required=True)
    hold.add_argument("--minutes", type=float, default=60)
    hold.set_defaults(func=cmd_hold)

    burst = commands.add_parser("burst", help="upload a fixed count as fast as possible, then wait for completion")
    load_options(burst)
    burst.add_argument("--count", type=int, default=20000)
    burst.add_argument("--burst-vus", type=int, default=16)
    burst.set_defaults(func=cmd_burst)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
