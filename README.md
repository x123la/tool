# ghostshm

ghostshm is a high-performance Linux CLI utility for detecting and safely reaping orphaned shared memory segments. It scans both System V non-file-backed shared memory (`/proc/sysvipc/shm`) and POSIX shared memory objects (files in `/dev/shm`), identifying segments that likely have no attached processes and are remnants of crashed or defunct applications.

Migrated from Zig to C11, `ghostshm` is now a single-binary utility with zero dependencies, designed for maximum reliability and minimal footprint.

## Safety Model

Safety is a primary design goal. `ghostshm` follows a conservative approach:
- **Dry-run by default**: Commands never delete data unless `--yes` (alias: `--apply`) is explicitly provided.
- **Verification**: Before any deletion, the tool re-validates the segment state (e.g., using `shmctl(IPC_STAT)` or `stat()`) to ensure no process attached between the scan and the reap.
- **Conservative Classification**: If the tool cannot fully scan `/proc` (e.g., due to permissions), it marks ambiguous items as `unknown`.
- **Private File Override**: For POSIX shared memory, if the user owns the file and it has private permissions (`0600`), the tool allows reaping even if `/proc` visibility is partial.
- **PID Reuse Protection**: Compares segment creation time against PID start times to avoid misidentifying recycled PIDs.

## Usage

```bash
# Scan for orphans (default view)
./ghostshm scan

# Scan and output JSON
./ghostshm scan --json

# Explain classification for a specific ID
./ghostshm explain sysv:12345
./ghostshm explain /dev/shm/my_shm

# Reap orphans (actual deletion)
./ghostshm reap --yes
./ghostshm reap --apply
```

### Common Flags
- `--threshold <seconds>`: Minimum age of segment in seconds. Default: `60`.
- `--min-bytes <n>`: Ignore segments smaller than this.
- `--json`: Output valid JSON for machine processing.
- `--verbose`: Show all segments, including those classified as unknown.
- `--deep`: Allow POSIX `likely_orphan` without a successful mapping scan.

## Build Instructions

Requires a standard C compiler (GCC or Clang).

```bash
make
```

The resulting binary `ghostshm` is statically linked by default (on Linux).

## Install

```bash
# System-wide (may need sudo)
make install

# User-local (recommended)
make install PREFIX=$HOME/.local
```

Ensure `$HOME/.local/bin` is in your `PATH` to run:

```bash
ghostshm scan
```

## License
MIT
