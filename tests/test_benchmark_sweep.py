"""Tests for benchmark/results_store.py, benchmark/sweep.py and runner wiring.

Following tests/test_benchmark_grading.py conventions: pure logic, no network.
Tests stay hermetic by pointing the results store at tmp_path, injecting
runner_fn into run_sweep, and stubbing the app subprocess/precheck for runner
tests. Flask-dependent behavior tests skip cleanly when flask is unavailable.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from benchmark import results_store, sweep
from benchmark.grading import BenchmarkGrader, GROUND_TRUTH

# Make benchmark/run_benchmark.py importable as `run_benchmark` (it's a
# script entry point, not a package module) — mirrors the sys.path insert
# the script itself does for the repo root.
_BENCH_DIR = Path(__file__).resolve().parent.parent / "benchmark"
if str(_BENCH_DIR) not in sys.path:
    sys.path.insert(0, str(_BENCH_DIR))


# ===================================================================
# Helpers
# ===================================================================


def _graded(findings, error=None, **kw):
    """Grade a synthetic finding set into a BenchmarkResult."""
    return BenchmarkGrader(GROUND_TRUTH).grade(findings, error=error, **kw)


def _tp_finding(vuln_class="sqli", url="/login"):
    return {"type": vuln_class, "url": url}


# ===================================================================
# results_store — save/load round-trip
# ===================================================================


class TestSaveLoadRoundTrip:
    def test_save_writes_json_file(self, tmp_path):
        result = _graded([_tp_finding()])
        path = results_store.save_result(
            result, model="model-a", provider="ollama", store_dir=tmp_path
        )
        assert path.exists()
        assert path.parent == tmp_path

    def test_repeat_runs_get_unique_filenames(self, tmp_path):
        """Back-to-back saves in the same millisecond must not overwrite."""
        result = _graded([_tp_finding()])
        paths = {
            results_store.save_result(result, model="m", store_dir=tmp_path)
            for _ in range(4)
        }
        assert len(paths) == 4  # all four persisted, none collided

    def test_record_fields_present(self, tmp_path):
        result = _graded([_tp_finding()])
        path = results_store.save_result(
            result, model="model-a", provider="ollama", store_dir=tmp_path
        )
        rec = json.loads(path.read_text())
        assert rec["model"] == "model-a"
        assert rec["provider"] == "ollama"
        assert rec["precision"] == pytest.approx(1.0)
        assert rec["recall"] == pytest.approx(0.1)
        assert rec["f1"] > 0
        assert rec["error"] is None
        assert "timestamp" in rec
        assert "result" in rec  # raw to_dict embedded

    def test_error_run_recorded(self, tmp_path):
        result = _graded([], error="no API key")
        path = results_store.save_result(
            result, model="model-b", provider="gemini", store_dir=tmp_path
        )
        rec = json.loads(path.read_text())
        assert rec["error"] == "no API key"
        assert rec["f1"] == 0.0

    def test_load_history_round_trip(self, tmp_path):
        r1 = _graded([_tp_finding()])
        r2 = _graded([_tp_finding(), _tp_finding("xss", "/search")])
        results_store.save_result(r1, model="a", store_dir=tmp_path)
        results_store.save_result(r2, model="b", store_dir=tmp_path)
        rows = results_store.load_history(store_dir=tmp_path)
        assert sorted(r["model"] for r in rows) == ["a", "b"]
        by_model = {r["model"]: r for r in rows}
        assert by_model["b"]["recall"] == pytest.approx(0.2)

    def test_load_history_skips_corrupt_files(self, tmp_path):
        good = _graded([_tp_finding()])
        results_store.save_result(good, model="ok", store_dir=tmp_path)
        bad = tmp_path / "garbage.json"
        bad.write_text("{ not json")
        rows = results_store.load_history(store_dir=tmp_path)
        assert len(rows) == 1
        assert rows[0]["model"] == "ok"

    def test_load_history_empty_dir(self, tmp_path):
        assert results_store.load_history(store_dir=tmp_path) == []

    def test_history_limit_respected(self, tmp_path):
        for i in range(5):
            results_store.save_result(_graded([]), model=f"m{i}", store_dir=tmp_path)
        rows = results_store.load_history(limit=3, store_dir=tmp_path)
        assert len(rows) == 3

    def test_filename_is_sanitized(self, tmp_path):
        result = _graded([])
        path = results_store.save_result(
            result, model="model/with spaces:name", store_dir=tmp_path
        )
        assert "/" not in path.name
        assert " " not in path.name
        assert ":" not in path.name


# ===================================================================
# results_store — format_history table
# ===================================================================


class TestFormatHistory:
    def test_empty_history_message(self):
        assert results_store.format_history([]) == "No benchmark history yet."

    def test_table_includes_model_and_scores(self, tmp_path):
        results_store.save_result(
            _graded([_tp_finding()]), model="model-x", store_dir=tmp_path
        )
        rows = results_store.load_history(store_dir=tmp_path)
        table = results_store.format_history(rows)
        assert "MODEL" in table
        assert "model-x" in table
        assert "RECALL" in table

    def test_error_runs_marked_err(self, tmp_path):
        results_store.save_result(
            _graded([], error="boom"), model="broken", store_dir=tmp_path
        )
        rows = results_store.load_history(store_dir=tmp_path)
        assert "ERR" in results_store.format_history(rows)

    def test_error_runs_sort_below_ok_runs(self, tmp_path):
        results_store.save_result(_graded([_tp_finding()]), model="ok", store_dir=tmp_path)
        results_store.save_result(_graded([], error="boom"), model="bad", store_dir=tmp_path)
        rows = results_store.load_history(store_dir=tmp_path)
        table = results_store.format_history(rows)
        assert table.index("ok") < table.index("bad")


# ===================================================================
# sweep — parse_models
# ===================================================================


class TestParseModels:
    def test_csv_split(self):
        assert sweep.parse_models("a,b,c") == ["a", "b", "c"]

    def test_strips_whitespace_and_empties(self):
        assert sweep.parse_models("  gemma2:9b , , llama3.2 ") == [
            "gemma2:9b",
            "llama3.2",
        ]

    def test_none_returns_empty(self):
        assert sweep.parse_models(None) == []

    def test_empty_string_returns_empty(self):
        assert sweep.parse_models("") == []


# ===================================================================
# sweep — aggregation math (offline via fake runner)
# ===================================================================


def _fake_run(error_for=None, hits_for=None):
    """Build a fake run_elengenix_benchmark replacement.

    ``hits_for`` maps model → number of ground-truth vulns to report (so
    recall/F1 follow deterministically). ``error_for`` models return an
    errored result instead.
    """
    error_for = error_for or set()
    hits_for = hits_for or {}
    calls = []

    def fn(target_url=None, max_steps=30, model=None, provider=None, **kw):
        calls.append(
            {
                "model": model,
                "provider": provider,
                "stealth": kw.get("stealth"),
                "flag": kw.get("flag"),
            }
        )
        if model in error_for:
            return _graded([], error=f"{model} failed")
        n = hits_for.get(model, 0)
        findings = [
            _tp_finding(g["vuln_class"], g["endpoint"]) for g in GROUND_TRUTH[:n]
        ]
        return _graded(findings)

    return fn, calls


class TestSweepAggregation:
    def test_run_sweep_calls_once_per_model(self):
        fake, calls = _fake_run(hits_for={"a": 5, "b": 8})
        sweeps = sweep.run_sweep(["a", "b"], persist=False, runner_fn=fake)
        assert [s.model for s in sweeps] == ["a", "b"]
        assert len(calls) == 2

    def test_sweep_passes_model_and_provider_to_runner(self):
        fake, calls = _fake_run(hits_for={"m1": 5})
        sweep.run_sweep(["m1"], provider="ollama", persist=False, runner_fn=fake)
        assert calls[0]["model"] == "m1"
        assert calls[0]["provider"] == "ollama"

    def test_sweep_defaults_to_stealth(self):
        """run_sweep defaults stealth=True and forwards it to the runner."""
        fake, calls = _fake_run(hits_for={"m1": 5})
        sweep.run_sweep(["m1"], persist=False, runner_fn=fake)
        assert calls[0]["stealth"] is True

    def test_sweep_forwards_loud_mode(self):
        fake, calls = _fake_run(hits_for={"m1": 5})
        sweep.run_sweep(["m1"], stealth=False, persist=False, runner_fn=fake)
        assert calls[0]["stealth"] is False

    def test_sweep_forwards_explicit_flag(self):
        fake, calls = _fake_run(hits_for={"m1": 5})
        sweep.run_sweep(["m1"], flag="FLAG-XYZ", persist=False, runner_fn=fake)
        assert calls[0]["flag"] == "FLAG-XYZ"

    def test_recall_and_f1_follow_hits(self):
        fake, _ = _fake_run(hits_for={"a": 5})
        s = sweep.run_sweep(["a"], persist=False, runner_fn=fake)[0]
        # 5/10 found, no false positives → precision 1.0, recall 0.5
        assert s.runs[0].recall() == pytest.approx(0.5)
        assert s.mean_f1() == pytest.approx(s.runs[0].f1())

    def test_error_run_isolated_from_ok_run(self):
        fake, _ = _fake_run(hits_for={"good": 5}, error_for={"bad"})
        sweeps = sweep.run_sweep(["good", "bad"], persist=False, runner_fn=fake)
        good = next(s for s in sweeps if s.model == "good")
        bad = next(s for s in sweeps if s.model == "bad")
        assert len(good.ok_runs) == 1
        assert len(bad.ok_runs) == 0
        assert bad.mean_f1() == 0.0
        assert bad.errors and "failed" in bad.errors[0]

    def test_all_errors_mean_f1_zero(self):
        fake, _ = _fake_run(error_for={"x", "y"})
        sweeps = sweep.run_sweep(["x", "y"], persist=False, runner_fn=fake)
        assert all(s.mean_f1() == 0.0 for s in sweeps)
        assert all(s.n_runs == 1 for s in sweeps)


# ===================================================================
# sweep — --repeat stats (mean/min/max across N runs of one model)
# ===================================================================


class TestRepeatStats:
    def test_repeat_invokes_runner_n_times(self):
        fake, calls = _fake_run(hits_for={"a": 5})
        s = sweep.run_sweep(["a"], repeat=3, persist=False, runner_fn=fake)[0]
        assert s.n_runs == 3
        assert len(calls) == 3

    def test_repeat_mean_min_max(self):
        # Make each of 3 runs find a different number of vulns via a queue.
        queue = iter([
            _graded([_tp_finding()]),                                   # 1/10
            _graded([_tp_finding(), _tp_finding("xss", "/search")]),    # 2/10
            _graded([_tp_finding(g["vuln_class"], g["endpoint"]) for g in GROUND_TRUTH[:5]]),  # 5/10
        ])

        def fn(target_url=None, max_steps=30, model=None, provider=None, **kw):
            return next(queue)

        s = sweep.run_sweep(["a"], repeat=3, persist=False, runner_fn=fn)[0]
        r1, r2, r3 = s.runs
        assert s.mean_f1() == pytest.approx((r1.f1() + r2.f1() + r3.f1()) / 3)
        assert s.min_f1() == pytest.approx(min(r1.f1(), r2.f1(), r3.f1()))
        assert s.max_f1() == pytest.approx(max(r1.f1(), r2.f1(), r3.f1()))

    def test_repeat_stats_serialise(self):
        fake, _ = _fake_run(hits_for={"a": 5})
        s = sweep.run_sweep(["a"], repeat=2, persist=False, runner_fn=fake)[0]
        d = s.to_dict()
        assert d["n_runs"] == 2
        assert d["n_ok"] == 2
        assert d["n_errors"] == 0
        assert "mean_f1" in d and "min_f1" in d and "max_f1" in d

    def test_repeat_less_than_one_clamps_to_one(self):
        fake, calls = _fake_run(hits_for={"a": 5})
        s = sweep.run_sweep(["a"], repeat=1, persist=False, runner_fn=fake)[0]
        assert s.n_runs == 1


# ===================================================================
# run_benchmark CLI — arg wiring & exit codes (heavy parts stubbed)
# ===================================================================


class TestCLIWiring:
    """Drive run_benchmark.main() with the scan runner stubbed so tests
    stay offline and fast. sys.argv is patched per-test."""

    @staticmethod
    def _invoke(argv, monkeypatch, tmp_path, *, findings_count=0, error=None):
        import run_benchmark as rb

        # Point persistence at tmp_path.
        monkeypatch.setattr(
            rb.results_store, "get_store_dir", lambda create=True: tmp_path
        )

        findings = [
            {"type": g["vuln_class"], "url": g["endpoint"]}
            for g in GROUND_TRUTH[:findings_count]
        ]

        def fake_single_run(target_url=None, max_steps=30, **kw):
            return _graded(findings, error=error)

        monkeypatch.setattr(rb, "run_elengenix_benchmark", fake_single_run)
        monkeypatch.setattr("sys.argv", ["run_benchmark.py"] + argv)

        return rb.main()

    # -- history ------------------------------------------------------
    def test_history_does_not_run_benchmark(self, monkeypatch, tmp_path, capsys):
        import run_benchmark as rb

        def should_not_be_called(**kw):  # pragma: no cover
            raise AssertionError("runner must not run for --history")

        monkeypatch.setattr(rb, "run_elengenix_benchmark", should_not_be_called)
        monkeypatch.setattr(
            rb.results_store, "get_store_dir", lambda create=True: tmp_path
        )
        monkeypatch.setattr("sys.argv", ["run_benchmark.py", "--history"])

        code = rb.main()
        assert code == 0
        out = capsys.readouterr().out
        assert "No benchmark history" in out

    # -- single run exit codes ---------------------------------------
    def test_single_run_finds_something_exits_0(self, monkeypatch, tmp_path):
        code = self._invoke([], monkeypatch, tmp_path, findings_count=3)
        assert code == 0

    def test_single_run_finds_nothing_exits_1(self, monkeypatch, tmp_path):
        code = self._invoke([], monkeypatch, tmp_path, findings_count=0)
        assert code == 1

    def test_single_run_error_exits_2(self, monkeypatch, tmp_path):
        code = self._invoke([], monkeypatch, tmp_path, error="no AI key")
        assert code == 2

    # -- sweep mode ---------------------------------------------------
    def test_sweep_all_errors_exits_2(self, monkeypatch, tmp_path):
        import run_benchmark as rb

        monkeypatch.setattr(
            rb.results_store, "get_store_dir", lambda create=True: tmp_path
        )
        real_run_sweep = sweep.run_sweep

        def fake_sweep_run(models, repeat=1, persist=False, **kw):
            return real_run_sweep(
                models, repeat=repeat, persist=False,
                runner_fn=_fake_run(error_for=set(models))[0],
            )

        monkeypatch.setattr(rb.sweep, "run_sweep", fake_sweep_run)
        monkeypatch.setattr(
            "sys.argv", ["run_benchmark.py", "--models", "a,b"]
        )
        assert rb.main() == 2

    def test_sweep_success_exits_0(self, monkeypatch, tmp_path):
        import run_benchmark as rb

        monkeypatch.setattr(
            rb.results_store, "get_store_dir", lambda create=True: tmp_path
        )
        real_run_sweep = sweep.run_sweep

        def fake_sweep_run(models, repeat=1, persist=False, **kw):
            return real_run_sweep(
                models, repeat=repeat, persist=False,
                runner_fn=_fake_run(hits_for={m: 3 for m in models})[0],
            )

        monkeypatch.setattr(rb.sweep, "run_sweep", fake_sweep_run)
        monkeypatch.setattr("sys.argv", ["run_benchmark.py", "--models", "a,b"])
        assert rb.main() == 0

    def test_sweep_parses_csv_models(self, monkeypatch, tmp_path, capsys):
        import run_benchmark as rb

        monkeypatch.setattr(
            rb.results_store, "get_store_dir", lambda create=True: tmp_path
        )
        seen = []
        real_run_sweep = sweep.run_sweep

        def fake_sweep_run(models, repeat=1, persist=False, **kw):
            seen.extend(models)
            return real_run_sweep(
                models, repeat=repeat, persist=False,
                runner_fn=_fake_run(hits_for={m: 1 for m in models})[0],
            )

        monkeypatch.setattr(rb.sweep, "run_sweep", fake_sweep_run)
        monkeypatch.setattr(
            "sys.argv",
            ["run_benchmark.py", "--models", " gemma2:9b , llama3.2 ", "--repeat", "2"],
        )
        rb.main()
        assert seen == ["gemma2:9b", "llama3.2"]

    def test_models_flag_without_names_exits_2(self, monkeypatch, tmp_path):
        import run_benchmark as rb

        monkeypatch.setattr(
            rb.results_store, "get_store_dir", lambda create=True: tmp_path
        )
        monkeypatch.setattr("sys.argv", ["run_benchmark.py", "--models", " , ,"])
        assert rb.main() == 2

    def test_loud_and_stealth_forwarded_to_runner(self, monkeypatch, tmp_path):
        """--loud (stealth=False) / --stealth reach run_elengenix_benchmark."""
        import run_benchmark as rb

        monkeypatch.setattr(
            rb.results_store, "get_store_dir", lambda create=True: tmp_path
        )
        seen = {}

        def fake(target_url=None, max_steps=30, **kw):
            seen.update(kw)
            return _graded([])

        monkeypatch.setattr(rb, "run_elengenix_benchmark", fake)
        monkeypatch.setattr("sys.argv", ["run_benchmark.py", "--loud"])
        rb.main()
        assert seen.get("stealth") is False

        monkeypatch.setattr("sys.argv", ["run_benchmark.py"])  # default = stealth
        rb.main()
        assert seen.get("stealth") is True

    def test_flag_forwarded_to_runner(self, monkeypatch, tmp_path):
        import run_benchmark as rb

        monkeypatch.setattr(
            rb.results_store, "get_store_dir", lambda create=True: tmp_path
        )
        seen = {}
        monkeypatch.setattr(
            rb,
            "run_elengenix_benchmark",
            lambda target_url=None, max_steps=30, **kw: (seen.update(kw) or _graded([])),
        )
        monkeypatch.setattr(
            "sys.argv", ["run_benchmark.py", "--flag", "ELENGENIX-FLAG-fixed"]
        )
        rb.main()
        assert seen.get("flag") == "ELENGENIX-FLAG-fixed"

    def test_provider_forwarded_to_single_run(self, monkeypatch, tmp_path):
        import run_benchmark as rb

        monkeypatch.setattr(
            rb.results_store, "get_store_dir", lambda create=True: tmp_path
        )
        seen = {}
        monkeypatch.setattr(
            rb,
            "run_elengenix_benchmark",
            lambda target_url=None, max_steps=30, **kw: (seen.update(kw) or _graded([])),
        )
        monkeypatch.setattr("sys.argv", ["run_benchmark.py", "--provider", "ollama"])
        rb.main()
        assert seen.get("provider") == "ollama"


# ===================================================================
# runner.py — stealth env, per-run FLAG pass-through, impact wiring
# (offline: subprocess + precheck stubbed; no real Flask app spawned)
# ===================================================================


class TestRunnerStealthAndFlag:
    """Verify the runner defaults to stealth, generates a per-run FLAG, and
    threads it to the grader — without executing a real scan. _run_canonical_scan
    and _precheck_scan_environment are stubbed; only VulnerableAppServer's env
    construction (subprocess.Popen) is faked."""

    @staticmethod
    def _patch_run(monkeypatch, captured_env):
        from benchmark import runner as br

        # Never actually precheck (needs AI key) — pretend env is fine.
        monkeypatch.setattr(br, "_precheck_scan_environment", lambda *a, **k: None)

        # Record the env the app subprocess would launch with.
        class _FakeProc:
            pid = 12345

            def terminate(self):
                pass

            def wait(self, timeout=None):
                return 0

            def kill(self):
                pass

        def fake_popen(cmd, env=None, **kw):
            captured_env.update(env or {})
            return _FakeProc()

        monkeypatch.setattr(br.subprocess, "Popen", fake_popen)
        # App "comes up" instantly.
        monkeypatch.setattr(
            br.VulnerableAppServer, "_wait_for_ready", lambda self, timeout=15.0: True
        )
        # The canonical scan returns nothing but exercises the flag grader path.
        monkeypatch.setattr(br, "_run_canonical_scan", lambda *a, **k: ([], 0, 0.0, None))
        return br

    def test_stealth_is_default(self, monkeypatch):
        env = {}
        br = self._patch_run(monkeypatch, env)
        br.run_elengenix_benchmark(max_steps=1)
        assert env.get("ELENGENIX_BENCH_STEALTH") == "1"

    def test_loud_disables_stealth(self, monkeypatch):
        env = {}
        br = self._patch_run(monkeypatch, env)
        br.run_elengenix_benchmark(max_steps=1, stealth=False)
        assert env.get("ELENGENIX_BENCH_STEALTH") == "0"

    def test_flag_generated_and_set_when_unspecified(self, monkeypatch):
        env = {}
        br = self._patch_run(monkeypatch, env)
        br.run_elengenix_benchmark(max_steps=1)
        flag = env.get("FLAG")
        assert flag, "a per-run FLAG must be generated and passed to the app"
        assert flag.startswith("ELENGENIX-FLAG-")

    def test_each_run_gets_a_distinct_flag(self, monkeypatch):
        env = {}
        br = self._patch_run(monkeypatch, env)
        seen = set()
        for _ in range(3):
            env.clear()
            br.run_elengenix_benchmark(max_steps=1)
            seen.add(env.get("FLAG"))
        assert len(seen) == 3, "flags must be random per run"

    def test_explicit_flag_respected(self, monkeypatch):
        env = {}
        br = self._patch_run(monkeypatch, env)
        br.run_elengenix_benchmark(max_steps=1, flag="ELENGENIX-FLAG-fixed")
        assert env.get("FLAG") == "ELENGENIX-FLAG-fixed"

    def test_flag_threaded_to_grader_impact(self, monkeypatch):
        """When the (stubbed) scan returns a sqli finding whose evidence holds
        the planted FLAG, impact must be proven — end-to-end threading check."""
        env = {}
        br = self._patch_run(monkeypatch, env)
        planted = {}

        real_scan = br._run_canonical_scan

        def scan_and_plant(*a, **k):
            planted["flag"] = env.get("FLAG")
            return ([{"type": "sqli", "url": "/login", "evidence": env.get("FLAG")}], 1, 0.1, None)

        monkeypatch.setattr(br, "_run_canonical_scan", scan_and_plant)
        result = br.run_elengenix_benchmark(max_steps=1)
        # threading worked iff the grader saw the same flag the app got
        assert result.impact_proven == ["sqli"]
        assert result.impact_rate == pytest.approx(1 / 3)
        _ = real_scan

    def test_target_url_mode_skips_flag_generation(self, monkeypatch):
        """External --target: we don't plant a flag, so no FLAG env is forced."""
        env = {}
        br = self._patch_run(monkeypatch, env)
        br.run_elengenix_benchmark(target_url="http://127.0.0.1:9", max_steps=1)
        assert "FLAG" not in env
        # server never started for external target
        assert "ELENGENIX_BENCH_STEALTH" not in env


# ===================================================================
# VulnerableAppServer — real (tiny) Flask checks for loud vs stealth
# ===================================================================

try:  # These spawn the real Flask app; skip cleanly when flask isn't installed.
    import flask  # noqa: F401

    _HAS_FLASK = True
except Exception:
    _HAS_FLASK = False

_needs_flask = pytest.mark.skipif(
    not _HAS_FLASK, reason="flask not installed — skipping live-app mode tests"
)


@_needs_flask
class TestVulnerableAppServerModes:
    """Spawn the real target app briefly to confirm loud shows hints and
    stealth hides them. Local-only, fast (single process each)."""

    @staticmethod
    def _fetch_index_and_login(url):
        import urllib.request
        import urllib.error

        idx = urllib.request.urlopen(url + "/", timeout=3).read().decode()
        req = urllib.request.Request(
            url + "/login",
            data=b"username=%27%20OR%201%3D1&password=x",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        try:
            login = urllib.request.urlopen(req, timeout=3).read().decode()
        except urllib.error.HTTPError as e:
            login = e.read().decode()
        return idx, login

    def test_loud_index_lists_vulns(self):
        from benchmark import runner as br

        with br.VulnerableAppServer(stealth=False) as srv:
            idx, login = self._fetch_index_and_login(srv.base_url)
        assert "vulnerabilities" in idx
        assert "SQL Injection" in idx
        # loud mode echoes the raw query in the failed-login response
        assert "query" in login

    def test_stealth_index_hides_vulns(self):
        from benchmark import runner as br

        with br.VulnerableAppServer(stealth=True) as srv:
            idx, login = self._fetch_index_and_login(srv.base_url)
        assert "SQL Injection" not in idx
        assert "vulnerabilities" not in idx
        # stealth suppresses the debug query echo
        assert "query" not in login

    def test_flag_planted_in_db_and_reachable_via_traversal(self):
        """The runner's FLAG must land where the app promises (flags table +
        traversal file), proving the impact path is really wired."""
        import os

        from benchmark import runner as br

        flag = br.generate_flag()
        with br.VulnerableAppServer(stealth=True, flag=flag) as srv:
            import urllib.request

            # path traversal outside the download base reads the planted flag
            body = urllib.request.urlopen(
                srv.base_url + "/download?file=../elengenix_flag.txt", timeout=3
            ).read().decode()
            assert flag in body
            # cleanup planted flag file
            try:
                os.remove("/tmp/elengenix_flag.txt")
            except OSError:
                pass


# ===================================================================
# Target-app behavior at the HTTP level (in-process Flask test client)
# Proves the STEALTH / FLAG env toggles the runner sets actually change
# the app's behavior — fast, no subprocess, offline. Skips without flask.
# ===================================================================


@_needs_flask
class TestTargetAppBehavior:
    """Import app.py fresh per case with the toggle env set, then drive it with
    Flask's test client. This is the direct proof of stealth/loud/flag wiring."""

    APP_PATH = Path(__file__).resolve().parent / "vulnerable_target" / "app.py"

    @staticmethod
    def _load_app_class(env):
        import importlib.util

        for k, v in env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = str(v)
        spec = importlib.util.spec_from_file_location(
            "vuln_target_app_under_test", TestTargetAppBehavior.APP_PATH
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_stealth_index_is_opaque(self):
        mod = self._load_app_class({"ELENGENIX_BENCH_STEALTH": "1", "FLAG": None})
        body = mod.app.test_client().get("/").get_data(as_text=True)
        assert "SQL Injection" not in body
        assert "vulnerabilities" not in body
        assert "elengenix-target" in body

    def test_loud_index_lists_vulns(self):
        mod = self._load_app_class({"ELENGENIX_BENCH_STEALTH": "0", "FLAG": None})
        body = mod.app.test_client().get("/").get_data(as_text=True)
        assert "SQL Injection" in body
        assert "vulnerabilities" in body

    def test_stealth_sqli_error_hides_query(self):
        """Stealth: failed login no longer debug-echoes the raw SQL query."""
        mod = self._load_app_class({"ELENGENIX_BENCH_STEALTH": "1", "FLAG": None})
        # invalid creds → 401 + no query echo
        resp = mod.app.test_client().post(
            "/login", data={"username": "nobody'", "password": "x"}
        )
        body = resp.get_data(as_text=True)
        assert resp.status_code == 401
        assert "SELECT" not in body
        assert "query" not in body

    def test_loud_sqli_error_echoes_query(self):
        mod = self._load_app_class({"ELENGENIX_BENCH_STEALTH": "0", "FLAG": None})
        resp = mod.app.test_client().post(
            "/login", data={"username": "nobody'", "password": "x"}
        )
        body = resp.get_data(as_text=True)
        assert resp.status_code == 401
        assert "SELECT" in body  # debug leak present in loud mode

    def test_flag_is_reachable_via_sqli_union(self):
        """The planted FLAG lives in the `flags` table; a UNION extraction via
        /login must surface it verbatim — the chain impact grading relies on."""
        flag = "ELENGENIX-FLAG-sqliunit123"
        mod = self._load_app_class(
            {"ELENGENIX_BENCH_STEALTH": "1", "FLAG": flag}
        )
        # UNION-select the flag row: users has 6 cols, flags.flag is col 2.
        payload = "' UNION SELECT 1, flag, 3, 4, 5, 6 FROM flags--"
        resp = mod.app.test_client().post(
            "/login", data={"username": payload, "password": "x"}
        )
        assert flag in resp.get_data(as_text=True)

    def test_flag_is_reachable_via_ssti(self):
        flag = "ELENGENIX-FLAG-ssti12345"
        mod = self._load_app_class({"ELENGENIX_BENCH_STEALTH": "1", "FLAG": flag})
        resp = mod.app.test_client().get("/render?template={{ FLAG }}")
        assert flag in resp.get_data(as_text=True)

    def test_flag_is_reachable_via_path_traversal(self):
        import urllib.parse

        flag = "ELENGENIX-FLAG-traversal1"
        mod = self._load_app_class({"ELENGENIX_BENCH_STEALTH": "1", "FLAG": flag})
        # Plant happens on first /download hit; traversal escapes to /tmp file.
        resp = mod.app.test_client().get(
            "/download?file=" + urllib.parse.quote("../elengenix_flag.txt")
        )
        body = resp.get_data(as_text=True)
        assert flag in body
        # cleanup the planted flag file
        try:
            os.remove("/tmp/elengenix_flag.txt")
        except OSError:
            pass
