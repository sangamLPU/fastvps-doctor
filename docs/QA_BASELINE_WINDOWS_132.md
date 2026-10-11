# Archived QA baseline: Windows 11, 132 tests

**Baseline date:** 11 October 2026
**Status:** Historical Windows-only QA snapshot, retained for comparison. The later completed QA run is in [COMPLETE_QA_REPORT.md](COMPLETE_QA_REPORT.md).

## Recorded result

- Host: Windows 11 build 10.0.26300, CPython 3.13.7, 64-bit.
- Test result: **132 passed, 2 skipped** (134 collected).
- The skipped tests were opt-in Linux integration tests. WSL and Docker could not be accessed in that earlier execution context.
- Statement coverage: **92.1%** (1,839 statements, 145 missed); branch-inclusive coverage: **90%** (634 branches, 79 partial).
- Ruff lint, Ruff formatting, mypy, uv lock validation, source/wheel packaging, and pip-audit passed.
- Bandit reported four reviewed Low findings and no Medium or High findings.
- The Windows module entry point worked. The generated Windows console launcher failed with a uv trampoline path-resolution error. Later Linux wheel testing succeeded in WSL; that does not retroactively change the historical Windows result.
- No FastVPS VPS or external server was accessed.

The current, expanded Windows suite records **134 passed, 2 skipped**, reflecting two added regression tests. The current WSL Ubuntu 26.04/Python 3.14.4 run records **136 passed, 0 skipped**. See the complete report for the separate environment boundaries and current limitations.
