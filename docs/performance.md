# Performance Testing and Regression Tracking

## Goal
Run repeatable benchmarks on the ESP device, persist every run, and compare
against previous results to verify whether changes improve or regress real
behavior.

## Primary Tool
- `tools/perf_regression.py`

This runner executes stress phases multiple times, stores raw and aggregated
metrics, and compares medians against the previous run.

## Built-in Reliability Guards
- Single-run lock file: prevents concurrent benchmark runs.
- Phase watchdog timeout: each phase has a maximum runtime budget.
- Heartbeat logs: periodic progress output during long phases.
- Pre-phase health probe: checks HTTP availability before each phase.
- Atomic JSON writes: avoids truncated/corrupted history artifacts.
- Partial-progress checkpoint: writes `latest.partial.json` while running.

## Default Output
Directory: `tools/perf_history/`

- `latest.json`: latest completed run (machine-readable)
- `perf_<timestamp>_<tag>.json`: full historical run
- `perf_<timestamp>_<tag>.md`: compact Markdown summary

## Profiles
- `c_static_only`: C-served static paths only (`/file`, `/static/large.txt`)
- `python_light`: low-cost Python-dispatched endpoints
- `python_heavy`: template-heavy Python-dispatched endpoints
- Legacy aliases still supported: `api`, `mixed`, `static`

## Recommended Baseline Command (COM14 device already running)
```powershell
python tools/perf_regression.py 192.168.0.135 `
  --profiles c_static_only,python_light,python_heavy `
  --runs 3 `
  --burst-duration 12 `
  --long-duration 30 `
  --heartbeat-ms 3000 `
  --hard-timeout-s 1800 `
  --tag baseline_isolated_v1
```

## Interpreting Results
- Use medians as the primary signal (`latest.json -> aggregated`).
- Watch `error_rate`, `p95_ms`, `p99_ms`, and `rps_ok`.
- Use per-path metrics to isolate bottlenecks inside each profile.
- Use `comparison_to_previous` to validate if a code change actually helped.

## Rule for Optimization Work
Never optimize for a specific test endpoint. Optimize shared runtime paths
(dispatch, scheduling, serialization, IPC, static serving internals) and use
these metrics only as regression gates.
