# v0.3 scenario demonstrations

The checked-in reports below are deterministic synthetic fixtures. They contain no real host measurements, customer information or raw logs and are examples of the new support-handoff format.

## Reproduce the fixture reports

From a development checkout with the package installed:

```bash
python examples/troubleshoot_demos.py website-unavailable
python examples/troubleshoot_demos.py service-crash
python examples/troubleshoot_demos.py storage
```

Each command prints a sanitized Markdown report. Add `--output FILE` to create a new local report; an existing file is never overwritten. The sample outputs are [website unavailable](../examples/demos/troubleshoot-website-unavailable.md), [service crash/restart](../examples/demos/troubleshoot-service-crash.md), and [storage pressure](../examples/demos/troubleshoot-storage.md).

The fixtures demonstrate these limits:

- Website: one failed unit state, no listener on the selected port and one service failure event. These observations do not identify why the app failed or whether it is reachable publicly.
- Service: repeated restart-scheduling records and a nearby OOM event. Both explanations are labelled plausible; timing does not establish cause.
- Storage: high space and inode use with one service error record. The report explicitly avoids attributing the write problem to storage or recommending deletion.

## Live disposable loopback example

On WSL or another disposable Linux system, run:

```bash
python examples/troubleshoot_demos.py website-unavailable --live-local
```

This starts a temporary unprivileged HTTP service bound only to `127.0.0.1` on an operating-system-assigned port. The service deliberately returns HTTP 503 to one `HEAD /` request. FastVPS Doctor also performs its read-only selected-unit, listener, storage, resource and bounded-journal checks. The script shuts down the temporary service in a `finally` block. It does not change systemd configuration or contact an external host. Its report combines the live loopback observation with current host context, so use it only on a disposable Linux environment, review the report, and do not run this demo on the sponsored VPS.

The live demo is covered by a Linux integration test that starts a local service and verifies the HTTP status. The CI Docker matrix executes the test in isolated Ubuntu 24.04, Debian 12 and Debian 13 images. A WSL pass does not prove those GitHub jobs passed; the workflow remains pending until run in GitHub Actions.

## Prior v0.2 fixtures

Earlier general diagnostic examples remain available through [the synthetic demo script](../examples/synthetic_demos.py) and [their generated reports](../examples/demos/). They are retained as historical examples and do not exercise the v0.3 `troubleshoot` orchestration.

Never induce service crashes, OOM, filesystem exhaustion, permission changes, or network failures on the sponsored VPS. Use mocks or disposable containers/VMs for failure simulations.
