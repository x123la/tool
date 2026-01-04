# Changelog

All notable changes to this project will be documented in this file.

## [0.2.0] - 2026-01-04

### Migrated to C11
- Completely rewritten in C11 for zero-dependency portability.
- Removed Zig toolchain requirement (now uses GCC/Clang).
- Implemented single-source architecture in `src/ghostshm.c`.
- Switched to standard `Makefile` build system.
- Optimized JSON streaming performance.

## [0.1.0] - 2026-01-03

### Initial Release (Zig)
- Support for System V and POSIX Shared Memory scanning.
- forensic `explain` command.
- PID reuse detection.
- JSON output support.
- GitHub Actions CI.
