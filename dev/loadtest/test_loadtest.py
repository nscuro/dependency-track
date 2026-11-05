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
import unittest
from datetime import datetime, timedelta, timezone

from loadtest import evaluate_burst, evaluate_rate, foreign_volumes, join_runs

START = datetime(2026, 1, 1, tzinfo=timezone.utc)


def at(seconds):
    return int((START + timedelta(seconds=seconds)).timestamp() * 1000)


def run(token, created=0, completed=None, status="COMPLETED"):
    return {
        "labels": {"bom_upload_token": token} if token else {},
        "status": status,
        "created_at": at(created),
        "completed_at": at(completed) if completed is not None else None,
    }


def steady(seconds=900, rate=1, latency=30):
    tokens = [f"t{i}" for i in range(seconds * rate)]
    imports = [run(t, i / rate, i / rate + 1) for i, t in enumerate(tokens)]
    analyses = [run(t, i / rate + 1, i / rate + latency) for i, t in enumerate(tokens)]
    return join_runs(imports, analyses)


def evaluate(sboms, **overrides):
    args = {
        "start": START,
        "seconds": 900,
        "rate": 1,
        "warmup_seconds": 300,
        "backlog_seconds": 20,
        "dropped": 0,
        "upload_failures": 0,
    }
    return evaluate_rate(sboms, **(args | overrides))


class ImportThroughputTest(unittest.TestCase):
    def test_counts_imports_finished_inside_the_window(self):
        sboms = [
            {"token": "before", "status": "MISSING", "created_at": 0, "imported_at": 1_000, "completed_at": None},
            {"token": "inside", "status": "MISSING", "created_at": 0, "imported_at": 301_000, "completed_at": None},
            {"token": "unfinished", "status": "MISSING", "created_at": 0, "imported_at": None, "completed_at": None},
            {"token": "after", "status": "MISSING", "created_at": 0, "imported_at": 601_000, "completed_at": None},
        ]
        start = datetime.fromtimestamp(0, timezone.utc)
        report = evaluate_rate(sboms, start, 600, 1, 300, 20, 0, 0)
        self.assertAlmostEqual(1 / 300, report["imports_per_second"])


class ForeignVolumesTest(unittest.TestCase):
    def test_flags_existing_project_volumes_we_did_not_create(self):
        volumes = ["other_data", "dt-sbom-benchmark_postgres-data"]
        self.assertEqual(["dt-sbom-benchmark_postgres-data"], foreign_volumes(volumes, owned=False))

    def test_accepts_our_own_volumes(self):
        self.assertEqual([], foreign_volumes(["dt-sbom-benchmark_postgres-data"], owned=True))

    def test_ignores_other_projects(self):
        self.assertEqual([], foreign_volumes(["dtrack-dev_postgres-data"], owned=False))


class JoinRunsTest(unittest.TestCase):
    def test_records_when_the_import_finished(self):
        self.assertEqual(at(6), join_runs([run("a", 5, 6)], [])[0]["imported_at"])

    def test_has_no_import_time_for_unfinished_import(self):
        self.assertIsNone(join_runs([run("a", 5, None, status="RUNNING")], [])[0]["imported_at"])

    def test_uses_import_creation_and_analysis_completion(self):
        sbom = join_runs([run("a", 5, 6)], [run("a", 6, 40)])[0]
        self.assertEqual("COMPLETED", sbom["status"])
        self.assertEqual(35, sbom["latency"])

    def test_is_not_done_when_only_import_finished(self):
        sbom = join_runs([run("a", 5, 6)], [])[0]
        self.assertEqual("MISSING", sbom["status"])
        self.assertIsNone(sbom["latency"])

    def test_is_not_done_while_analysis_is_running(self):
        sbom = join_runs([run("a", 5, 6)], [run("a", 6, None, status="RUNNING")])[0]
        self.assertEqual("MISSING", sbom["status"])

    def test_reports_failed_import(self):
        sbom = join_runs([run("a", 5, 6, status="FAILED")], [])[0]
        self.assertEqual("FAILED", sbom["status"])

    def test_reports_failed_analysis(self):
        sbom = join_runs([run("a", 5, 6)], [run("a", 6, 9, status="FAILED")])[0]
        self.assertEqual("FAILED", sbom["status"])

    def test_ignores_analysis_without_token(self):
        sboms = join_runs([run("a", 5, 6)], [run("a", 6, 9), run(None, 7, 8)])
        self.assertEqual(1, len(sboms))


class EvaluateRateTest(unittest.TestCase):
    def test_passes_steady_run(self):
        result = evaluate(steady())
        self.assertTrue(result["passed"], result["reasons"])
        self.assertEqual(600, result["arrived"])
        self.assertAlmostEqual(3600, result["completed_per_hour"], delta=20)
        self.assertEqual(30, result["latency_seconds"]["p50"])

    def test_fails_when_backlog_grows(self):
        tokens = [f"t{i}" for i in range(900)]
        imports = [run(t, i, i + 1) for i, t in enumerate(tokens)]
        analyses = [run(t, i + 1, i * 1.1 + 1) for i, t in enumerate(tokens)]
        result = evaluate(join_runs(imports, analyses))
        self.assertFalse(result["passed"])
        self.assertIn("backlog", " ".join(result["reasons"]))

    def test_tolerates_backlog_growth_within_bound(self):
        tokens = [f"t{i}" for i in range(900)]
        imports = [run(t, i, i + 1) for i, t in enumerate(tokens)]
        analyses = [run(t, i + 1, i * 1.02 + 1) for i, t in enumerate(tokens)]
        result = evaluate(join_runs(imports, analyses))
        self.assertTrue(result["passed"], result["reasons"])

    def test_fails_on_failed_sbom_in_window(self):
        sboms = steady()
        sboms[500]["status"] = "FAILED"
        result = evaluate(sboms)
        self.assertFalse(result["passed"])
        self.assertIn("failed", " ".join(result["reasons"]))

    def test_ignores_failed_sbom_in_warmup(self):
        sboms = steady()
        sboms[10]["status"] = "FAILED"
        self.assertTrue(evaluate(sboms)["passed"])

    def test_fails_on_missing_sbom_in_window(self):
        sboms = steady()
        sboms[500]["status"] = "MISSING"
        sboms[500]["completed_at"] = None
        result = evaluate(sboms)
        self.assertFalse(result["passed"])
        self.assertIn("missing", " ".join(result["reasons"]))

    def test_fails_on_upload_failures_and_dropped_iterations(self):
        result = evaluate(steady(), dropped=1, upload_failures=1)
        self.assertFalse(result["passed"])
        self.assertIn("dropped", " ".join(result["reasons"]))
        self.assertIn("upload", " ".join(result["reasons"]))

    def test_fails_when_arrival_rate_misses_target(self):
        result = evaluate(steady(rate=1), rate=2, backlog_seconds=1000)
        self.assertFalse(result["passed"])
        self.assertIn("arrival", " ".join(result["reasons"]))


class EvaluateBurstTest(unittest.TestCase):
    def test_passes_when_all_complete_within_an_hour(self):
        result = evaluate_burst(steady(seconds=100), expected=100, upload_failures=0)
        self.assertTrue(result["passed"], result["reasons"])
        self.assertEqual(129, result["drain_seconds"])

    def test_fails_when_count_differs(self):
        result = evaluate_burst(steady(seconds=100), expected=101, upload_failures=0)
        self.assertFalse(result["passed"])
        self.assertIn("expected", " ".join(result["reasons"]))

    def test_fails_past_one_hour(self):
        result = evaluate_burst(steady(seconds=100, latency=3700), expected=100, upload_failures=0)
        self.assertFalse(result["passed"])
        self.assertIn("hour", " ".join(result["reasons"]))

    def test_fails_when_an_sbom_is_unfinished(self):
        sboms = steady(seconds=100)
        sboms[0]["status"] = "MISSING"
        sboms[0]["completed_at"] = None
        self.assertFalse(evaluate_burst(sboms, expected=100, upload_failures=0)["passed"])


if __name__ == "__main__":
    unittest.main()
