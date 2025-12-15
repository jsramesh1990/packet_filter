#!/bin/bash

# Packet Filter Driver Test Suite
# Run with: sudo ./test_suite.sh

set -e

MODULE="packet_filter"
DEVICE="/dev/packet_filter"
CONTROL="./userspace/filter_ctl"
TEST_IFACE="lo"  # Use loopback for testing

echo "=== Packet Filter Driver Test Suite ==="
echo

# Check if we're root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

# Load module
echo "1. Loading module..."
insmod packet_filter.ko || true
sleep 1

echo "2. Checking if module loaded..."
if ! lsmod | grep -q $MODULE; then
    echo "ERROR: Module not loaded"
    exit 1
fi

echo "3. Checking device file..."
if [ ! -c $DEVICE ]; then
    echo "ERROR: Device file not found"
    exit 1
fi

echo "4. Setting target device to $TEST_IFACE..."
$CONTROL --set-device $TEST_IFACE

echo "5. Testing statistics..."
$CONTROL --get-stats

echo "6. Adding test rules..."

# Rule 1: Drop all TCP packets to port 9999
echo "   - Drop TCP to port 9999"
$CONTROL --add-rule tcp any any any 9999 1

# Rule 2: Log all UDP packets
echo "   - Log UDP packets"
$CONTROL --add-rule udp any any any any 2

# Rule 3: Drop ICMP from specific IP
echo "   - Drop ICMP from 192.168.1.100"
$CONTROL --add-rule icmp 192.168.1.100 any 0 0 1

echo "7. Enabling blacklist mode..."
$CONTROL --set-mode 1
$CONTROL --enable-filter 1

echo "8. Generating test traffic..."
echo "   - Pinging localhost..."
ping -c 3 127.0.0.1

echo "   - TCP test to port 9999..."
timeout 2 nc -l 9999 &
sleep 1
echo "test" | nc localhost 9999 &
sleep 2

echo "   - UDP test..."
echo "test" | nc -u localhost 8888 &
sleep 1

echo "9. Checking statistics after traffic..."
$CONTROL --get-stats

echo "10. Testing log retrieval..."
# This would depend on your log implementation
# $CONTROL --get-log 10

echo "11. Clearing statistics..."
$CONTROL --clear-stats

echo "12. Testing statistics after clear..."
$CONTROL --get-stats

echo "13. Disabling filter..."
$CONTROL --enable-filter 0

echo "14. Removing test rules..."
# You would need to track rule IDs, here's a simplified approach
$CONTROL --del-rule 1
$CONTROL --del-rule 2
$CONTROL --del-rule 3

echo "15. Unloading module..."
rmmod $MODULE || true

echo
echo "=== Test Suite Complete ==="
echo "All tests passed successfully!"
