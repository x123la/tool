# ghostshm

ghostshm is a Linux CLI utility for detecting and safely reaping orphaned shared memory segments. It scans both System V non-file-backed shared memory (`/proc/sysvipc/shm`) and POSIX shared memory objects (files in `/dev/shm`), identifying segments that likely have no attached processes and are remnants of crashed or defunct applications.

## Safety Model

Safety is a primary design goal. `ghostshm` follows a conservative approach:
- **Dry-run by default**: Commands never delete data unless `--apply` is explicitly provided.
- **Verification**: Before any deletion, the tool re-validates the segment state (e.g., using `shmctl(IPC_STAT)` or `stat()`) to ensure no process attached between the scan and the reap.
- **Conservative Classification**: If the tool cannot fully scan `/proc` (e.g., due to permissions), it marks ambiguous items as `unknown` and refuses to reap them automatically.
- **Interactive Safeguard**: Even with `--apply`, users must type `DELETE` to confirm unless `--yes` is used.
- **PID Reuse Protection**: Compares segment creation time against PID start times to avoid misidentifying recycled PIDs.

## Usage

```bash
# Scan for orphans (default view)
ghostshm scan

# Scan and output JSON
ghostshm scan --json

# Explain classification for a specific ID
ghostshm explain 12345
ghostshm explain posix:/dev/shm/my_shm

# Reap orphans (actual deletion)
ghostshm reap --apply --yes
```

### Common Flags
- `--threshold <dur>`: Minimum age of segment (e.g., `30m`, `1h`, `0s`). Default: `30m`.
- `--min-bytes <n>`: Ignore segments smaller than this. Default: `64KB`.
- `--allow-owner <uid>`: Whitelist a specific user.
- `--allow-name <substring>`: Whitelist POSIX paths containing substring.
- `--allow-key <hex/dec>`: Whitelist specific SysV key.
- `--json`: Output valid JSON for machine processing.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0    | Success (No orphans found / All actions completed). |
| 1    | Orphans found (Scan / Reap dry-run). |
| 2    | Partial access / Uncertainty (Conservative mode) OR a deletion failed. |
| 64   | CLI usage error (Invalid flags, missing arguments). |
| 70   | System/Fatal error (Critical files unreadable). |

## JSON Schema (Simplified)

### Scan Mode
```json
{
  "now": 123456789,
  "items": [
    {
      "type": "sysv|posix",
      "id": 12345,
      "bytes": 1024,
      "classification": "likely_orphan|...",
      "recommendation": "reap|keep|review",
      "reasons": [...]
    }
  ],
  "summary": { ... }
}
```

### Reap Mode
```json
{
  "apply": true|false,
  "planned_deletions": [...],
  "results": [
    {
       "kind": "sysv|posix",
       "id": 12345,
       "attempted": true|false,
       "deleted": true|false,
       "error": null|"reason"
    }
  ],
  "deleted_count": 1,
  "failed_count": 0
}
```

## Build Instructions

Requires **Zig 0.13.0**.

```bash
zig build -Doptimize=ReleaseSafe
```

Binary is produced at `zig-out/bin/ghostshm`.

## License
MIT
