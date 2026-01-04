#!/bin/bash
set -e
GF_BIN="./ghostshm"

echo "--- Building ---"
make

echo "--- Test 1: output noise reduction ---"
# Create small POSIX segment (10 bytes)
touch /dev/shm/ghostshm_test_noise
dd if=/dev/urandom of=/dev/shm/ghostshm_test_noise bs=1 count=10 status=none

# Run scan with min-bytes 100. Should NOT see it.
echo "Scanning (default verbose=false)..."
OUT=$($GF_BIN scan --min-bytes 100 --posix || true)
if echo "$OUT" | grep -q "ghostshm_test_noise"; then
    echo "FAIL: Found noisy item"
    exit 1
fi

# Run scan --verbose. Should see it.
echo "Scanning (verbose=true)..."
OUT=$($GF_BIN scan --min-bytes 100 --posix --verbose || true)
if ! echo "$OUT" | grep -q "ghostshm_test_noise"; then
    echo "FAIL: Did not find item with verbose"
    exit 1
fi
rm /dev/shm/ghostshm_test_noise
echo "Noise test PASS"


echo "--- Test 2: POSIX deadlock override ---"
# Create a private file (0600) owned by us.
p="/dev/shm/ghostshm_test_private"
touch $p
chmod 0600 $p
# Write enough data (> default min_bytes 64k)
dd if=/dev/urandom of=$p bs=1k count=100 status=none

# We need to simulate partial proc access.
# ...
# So we can just check if classification is likely_orphan when threshold=0.

echo "Scanning private posix file..."
OUT=$($GF_BIN scan --posix --threshold 0 --min-bytes 0 || true)
echo "$OUT"

if echo "$OUT" | grep "ghostshm_test_private" | grep -q "likely_orphan"; then
    echo "POSIX Override PASS"
else
    echo "FAIL: Private file was not classified as likely_orphan (likely stuck at unknown/review)"
    exit 1
fi
rm $p


echo "--- Test 3: SysV Key Parsing ---"
# Create SysV segment with key having high bit set (negative i32)
# Key: 0x80001234 = 2147488308
# Using C helper
${CC:-gcc} tests/helpers/create_shm_key.c -o tests/helpers/create_shm_key

SHMID=$(./tests/helpers/create_shm_key 0x80001234)
echo "Created SHMID $SHMID with key 0x80001234"

# Explain it
OUT=$($GF_BIN explain $SHMID || true)
echo "$OUT"

# Check if key is correct (should match our input key logic)
# ghostshm prints hex. 0x80001234
if echo "$OUT" | grep -q "0x80001234"; then
    echo "SysV Key Parse PASS"
else
    echo "FAIL: Key mismatch in explain output"
    ipcrm -m $SHMID
    exit 1
fi

ipcrm -m $SHMID
rm tests/helpers/create_shm_key

echo "--- ALL REGRESSION TESTS PASSED ---"
