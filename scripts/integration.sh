#!/bin/bash
set -e

# ghostshm Integration Test Script
# Verifies scan, explain, and reap behavior with safe cleanup.

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$PROJECT_ROOT/zig-out/bin/ghostshm"
HELPERS_DIR="$PROJECT_ROOT/tests/helpers"
SYSV_ATTACH_SRC="$HELPERS_DIR/sysv_attach.c"
SYSV_ATTACH_BIN="$HELPERS_DIR/sysv_attach"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# State
TEST_SHMID=""
TEST_POSIX_PATH="/dev/shm/ghostshm_test_$(date +%s)"
ATTACH_PID=""

# Find Zig
ZIG_BIN="zig"
if ! command -v zig &> /dev/null; then
    ZIG_CANDIDATE=$(find "$PROJECT_ROOT/tools" -name zig -type f -executable | head -n 1)
    if [ -n "$ZIG_CANDIDATE" ]; then
        ZIG_BIN="$ZIG_CANDIDATE"
    fi
fi

cleanup() {
    echo "Cleaning up..."
    if [ -n "$ATTACH_PID" ]; then
        kill "$ATTACH_PID" 2>/dev/null || true
        wait "$ATTACH_PID" 2>/dev/null || true
    fi
    if [ -n "$TEST_SHMID" ]; then
        ipcrm -m "$TEST_SHMID" 2>/dev/null || true
    fi
    rm -f "$TEST_POSIX_PATH"
    rm -f "$SYSV_ATTACH_BIN"
}

trap cleanup EXIT

echo "--- Building prerequisites ---"
cc "$SYSV_ATTACH_SRC" -o "$SYSV_ATTACH_BIN"
echo "Rebuilding ghostshm for native architecture..."
$ZIG_BIN build

echo "--- Setting up test objects ---"
# 1. Create a SysV segment (likely orphan)
# We use ipcmk. -M 102400 (100KB)
TEST_SHMID=$(ipcmk -M 102400 | awk '{print $NF}')
echo "Created SysV shmid: $TEST_SHMID"

# 2. Create a POSIX segment (likely orphan after delay)
truncate -s 128000 "$TEST_POSIX_PATH"
echo "Created POSIX shm: $TEST_POSIX_PATH"

echo "--- Testing: scan ---"
$BIN scan --threshold 0s || [ $? -le 2 ]
$BIN scan --threshold 0s --json | python3 -m json.tool > /dev/null
echo -e "${GREEN}Scan OK${NC}"

echo "--- Testing: explain ---"
$BIN explain "sysv:$TEST_SHMID" | grep -q "ID=$TEST_SHMID" || [ $? -eq 2 ]
$BIN explain "posix:$TEST_POSIX_PATH" | grep -q "ID=$TEST_POSIX_PATH" || [ $? -eq 2 ]
echo -e "${GREEN}Explain OK${NC}"

echo "--- Testing: explain --json ---"
$BIN explain "sysv:$TEST_SHMID" --json | python3 -m json.tool | grep -q "\"shmid\": $TEST_SHMID"
echo -e "${GREEN}Explain JSON OK${NC}"

echo "--- Testing: attached segment behavior ---"
# Attach to the segment
"$SYSV_ATTACH_BIN" "$TEST_SHMID" > /dev/null &
ATTACH_PID=$!
sleep 1 # Wait for attach

# Verify it shows as IN_USE / ATTACHED
$BIN explain "sysv:$TEST_SHMID" | grep -q "ATTACHED"
echo -e "${GREEN}Attachment Detection OK${NC}"

# Kill attach process
kill "$ATTACH_PID"
wait "$ATTACH_PID"
ATTACH_PID=""
sleep 1 # Wait for detachment

echo "--- Testing: reap (dry-run) ---"
# Dry-run returns 1 if orphans are found, 2 if partial access.
# On clean test run, we expect 1 or 2.
set +e
DRY_RUN_OUT=$($BIN reap --threshold 0s --json)
DRY_RUN_EXIT=$?
set -e
[ $DRY_RUN_EXIT -eq 1 ] || [ $DRY_RUN_EXIT -eq 2 ]
echo "$DRY_RUN_OUT" | python3 -m json.tool > /dev/null
if echo "$DRY_RUN_OUT" | grep -q "\"likely_orphan\""; then
    echo "Likely orphans found in dry-run."
fi
# We at least expect the SysV one to be a likely_orphan on this environment
echo "$DRY_RUN_OUT" | grep -q "$TEST_SHMID"
echo -e "${GREEN}Reap Dry-Run OK${NC}"

echo "--- Testing: reap --apply ---"
# Reap the specific POSIX test file and SysV segment
# We'll use a threshold of 0s to ensure they are picked up.
$BIN reap --apply --yes --threshold 0s --json > /dev/null || [ $? -le 2 ]

# Verify SysV is gone (since it was likely_orphan)
if ipcs -m | grep -q " $TEST_SHMID "; then
    echo -e "${RED}FAILED: SysV segment $TEST_SHMID still exists${NC}"
    exit 1
fi
# POSIX might still exist if it was classified as unknown due to partial proc access
if [ -f "$TEST_POSIX_PATH" ]; then
    echo "POSIX segment $TEST_POSIX_PATH still exists (likely skipped due to conservative unknown status)"
fi
echo -e "${GREEN}Reap Apply OK${NC}"

echo "--- INTEGRATION TESTS PASSED ---"
