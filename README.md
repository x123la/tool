# ghostshm

ghostshm is a Linux CLI for detecting and safely reaping orphaned shared memory
segments. It scans both System V shared memory and POSIX shared memory objects
under `/dev/shm`, then classifies each item with a conservative safety model.

## Features

- SysV and POSIX scanning with JSON output.
- Dry-run by default with TOCTOU revalidation on reap.
- PID reuse detection and conservative handling when `/proc` is partial.
- POSIX mapping detection to avoid false-orphan classification.

## Safety Model

ghostshm prefers "unknown" over false positives:
- If `/proc` visibility is partial, ambiguous items are marked `unknown`.
- If POSIX mapping detection is unavailable, items are marked `unknown` unless
  `--deep` is set.
- Reap always re-checks the segment just before deletion.

## Requirements

- Linux with `/proc` mounted.
- Access to `/proc/<pid>` entries improves accuracy.

## Install

```bash
make

# System-wide (may need sudo)
make install

# User-local (recommended)
make install PREFIX=$HOME/.local
```

Ensure `$HOME/.local/bin` is in your `PATH` to run:

```bash
ghostshm scan
```

## Usage

```bash
ghostshm scan
ghostshm scan --json
ghostshm explain sysv:12345
ghostshm explain /dev/shm/my_shm
ghostshm reap --yes
ghostshm reap --apply --threshold 3600
```

Common flags:
- `--sysv`, `--posix`: Target specific subsystem (default: both).
- `--threshold <seconds>`: Minimum age of segment in seconds. Default: `60`.
- `--min-bytes <n>`: Ignore segments smaller than this.
- `--json`: Output valid JSON for machine processing.
- `--verbose`: Show all segments, including `unknown`.
- `--yes` / `--apply`: Confirm reaping (no deletes without this).
- `--force`: Allow reaping `possible_orphan` and `risky_to_remove`.
- `--deep`: Allow POSIX `likely_orphan` without a successful mapping scan.

## Docs

- Development notes: `docs/DEVELOPMENT.md`
- Security reporting: `docs/SECURITY.md`
- Contributing guide: `CONTRIBUTING.md`

## License

MIT. See `LICENSE`.
