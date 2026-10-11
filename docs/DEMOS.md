# Synthetic, test-backed demonstrations

All three scenarios below are fabricated unit fixtures. They do not run `systemctl`, `journalctl`, or `df`, and they do not access a server. The example reports use the real report builder, rule engine and privacy allowlists. They are not FastVPS customer or VPS data.

## Reproduce

From a development checkout with its Python environment active:

```bash
python -m pytest -q -v tests/test_demos.py
python examples/synthetic_demos.py website-unavailable
python examples/synthetic_demos.py storage-pressure
python examples/synthetic_demos.py restart-loop
```

Each generator command prints a deterministic Markdown report to stdout. To create a new file without overwriting an existing one, pass `--output FILE`.

Actual test output from the Windows/Python 3.13.7 review run:

```text
tests\test_demos.py ...                                                  [100%]
3 passed in 0.27s
```

## Demo A — Website unavailable

The fixture reports a failed Nginx systemd state and no local listener on the explicitly selected port 8080. It produces `SVC-NGIN-001` and `WEB-001`.

Run `python -m pytest -q -v tests/test_demos.py::test_website_unavailable_demo_shows_service_and_listener_evidence`, then render with `python examples/synthetic_demos.py website-unavailable`. The sanitized full example is [website-unavailable.md](../examples/demos/website-unavailable.md).

The report gives a support engineer two useful guest-side observations without claiming why the daemon stopped. It recommends checking service state and bind settings before changing anything.

## Demo B — Storage pressure

The fixture sets a synthetic non-root ext4 mount to 92.0% available-capacity use. It produces the critical `STOR-005` finding and omits the mount path. Root storage remains a separate passing check.

Run `python -m pytest -q -v tests/test_demos.py::test_storage_pressure_demo_shows_index_without_mount_path`, then render with `python examples/synthetic_demos.py storage-pressure`. The sanitized full example is [storage-pressure.md](../examples/demos/storage-pressure.md).

The indexed mount observation directs the customer to local `df -hT`/`df -i` review and ownership investigation. It does not recommend deleting files or imply which application used the space.

## Demo C — Service restart loop

The fixture supplies three timestamped service-manager restart records, a failure transition and a nearby kernel OOM indicator. The analyzer orders these real fixture timestamps and produces a low-confidence OOM correlation plus a restart-loop hypothesis. Raw `MESSAGE` text—including the fabricated process ID—is not exported.

Run `python -m pytest -q -v tests/test_demos.py::test_restart_loop_demo_has_real_synthetic_timestamps_and_discards_logs`, then render with `python examples/synthetic_demos.py restart-loop`. The sanitized full example is [restart-loop.md](../examples/demos/restart-loop.md).

The timeline gives support a time range and event categories to compare with application monitoring or deployments. It explicitly states that temporal proximity does not establish causation.

## Output status

The test output above proves the synthetic fixture assertions and report rendering on the current Windows host. It does not verify Linux journald behavior, actual Nginx failure detection, filesystem exhaustion or OOM access. Use disposable Linux environments for those checks; never simulate a failure on the sponsored production VPS.
