# Troubleshooting

## The command is not found

Activate the virtual environment used to install FastVPS Doctor, then check `python -m pip show fastvps-doctor`. Reinstall with `python -m pip install .` from the project checkout if needed.

## A check says skipped or unknown

This commonly means the operating system is not Linux, a program is not installed, the service manager is unavailable, or the current user cannot inspect a kernel interface. General diagnostics do not require root. Do not run the entire tool as root merely to remove a skipped status.

## A service is not listed

Only a fixed set of common executable names and service units is inspected. Custom paths and units may not be detected. Missing optional services are normal and are not treated as errors.

## The report says no major findings

This means only that this version's available checks did not match a rule. It is not an uptime guarantee, security assessment, performance benchmark or provider-side infrastructure check.

## An exported file already exists

Choose another output path. The report command intentionally refuses to overwrite files.

## A configuration validation finding appears

The validator's output is withheld to avoid copying paths or configuration details into reports. Run the service's read-only validator manually, review its output locally, and share only the relevant sanitized evidence.

