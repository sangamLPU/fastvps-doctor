# Installation

## Requirements

- Linux VPS running an Ubuntu LTS or Debian stable release.
- Python 3.11 or newer and a working virtual environment (`venv`).
- Internet access during installation to obtain Python dependencies. The installed core checks do not require a cloud service or routine Internet access.
- Root is not required for general diagnostics.

The compatibility target, based on official release pages checked 10 October 2026, is Ubuntu 24.04/26.04 LTS and Debian 12/13 with Python 3.11+. Ubuntu 22.04 provides Python 3.10 by default, so it needs a separately managed Python 3.11+ interpreter; that arrangement is not integration-verified yet. These are targets rather than a claim that this repository has passed on every listed release.

## Install from a checkout

Install Python tooling from your distribution, create an isolated environment, then install the project:

```bash
sudo apt install python3-venv python3-pip
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
fastvps-doctor --help
```

For development and tests:

```bash
python -m pip install '.[dev]'
```

Use your distribution's package-manager instructions if `python3-venv` is not available. Do not replace system Python or run `pip` against system site-packages.

## Uninstall

Deactivate and remove the virtual environment or uninstall the package from that environment:

```bash
python -m pip uninstall fastvps-doctor
```

The application does not install a daemon, create a background service, or write a configuration file. It reads optional thresholds from `~/.config/fastvps-doctor/config.toml` if present.

## Source verification

- [Ubuntu release cycle](https://ubuntu.com/about/release-cycle)
- [Ubuntu 26.04 release notes](https://documentation.ubuntu.com/release-notes/26.04/)
- [Debian releases](https://www.debian.org/releases/index.en.html)
- [Python packaging user guide](https://packaging.python.org/en/latest/guides/writing-pyproject-toml/)

