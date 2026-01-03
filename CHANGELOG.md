# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0] - 2026-01-03

### Initial Release
- Support for System V Shared Memory (`/proc/sysvipc/shm`) scanning and reaping.
- Support for POSIX Shared Memory (`/dev/shm`) scanning and reaping.
- Forensic `explain` command for auditability.
- PID reuse detection via start-time verification.
- Post-scan verification via `IPC_STAT` and `stat` before deletion.
- JSON output support for all commands.
- Configurable thresholds, minimum sizes, and allowlists.
- GitHub Actions CI with integration testing.
