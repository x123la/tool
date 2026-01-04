# Development

## Build

```bash
make
```

## Install

```bash
make install
make install PREFIX=$HOME/.local
```

## Tests

```bash
make test
```

## Notes

- The CLI is Linux-only and expects `/proc` to be mounted.
- POSIX mapping detection uses `/proc/<pid>/map_files` when available and falls
  back to `/proc/<pid>/maps` when needed.
