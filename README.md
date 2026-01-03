# ghostshm

ghostshm is a Linux CLI utility for detecting and safely reaping orphaned shared memory segments. It scans both System V non-file-backed shared memory (`/proc/sysvipc/shm`) and POSIX shared memory objects (files in `/dev/shm`), identifying segments that likely have no attached processes and are remnants of crashed or defunct applications.

## Safety Model

By default, `ghostshm` operates in a read-only **dry-run** mode.
- `scan` only lists items.
- `reap` prints a deletion plan but does NOT delete anything unless `--apply` is passed.
- Even with `--apply`, the tool requires an interactive confirmation (typing `DELETE`) unless `--yes` is specified.
- Use of color coding (Green=Likely Orphan, Yellow=Possible Orphan, Red=Risky) helps users quickly assess the state of their system.

## Build Instructions

```bash
zig build -Doptimize=ReleaseSafe
```

The resulting binary will be located in `zig-out/bin/ghostshm`.

## Usage Examples

**Scan for orphans (default view):**
```bash
ghostshm scan
```

**Scan and output JSON (for machine parsing):**
```bash
ghostshm scan --json
```

**Explain why a specific ID is classified as it is:**
```bash
ghostshm explain 1234
# OR for POSIX
ghostshm explain posix:/dev/shm/my_shm_file
```

**Reap (dry run - just shows what would happen):**
```bash
ghostshm reap
```

**Reap (actual deletion, interactive confirm):**
```bash
ghostshm reap --apply
```

**Reap (actual deletion, non-interactive):**
```bash
ghostshm reap --apply --yes
```

## Limitations

- **PID Reuse**: The tool attempts to detect PID reuse by checking start times against system boot time and segment creation times. However, extremely rapid PID reuse (within the same second tick) might theoretically race, though unlikely in practice for this use case.
- **Permission Limits**: The tool relies on scanning `/proc/<pid>/fd`. If run as a non-root user, it may not be able to list FDs of processes owned by other users. This results in "partial proc access" state, where the tool will degrade gracefully: it stays conservative and will refuse to classify POSIX objects as "likely orphans" if it cannot fully verify that no other process has them open.
