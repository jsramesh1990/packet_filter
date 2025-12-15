#!/bin/bash

# Packet Filter Driver Loader Script
# Usage: sudo ./load_driver.sh [options]

set -e

MODULE_NAME="packet_filter"
MODULE_FILE="$MODULE_NAME.ko"
DEVICE_PATH="/dev/packet_filter"
CONTROL_TOOL="./userspace/filter_ctl"
MAJOR_NUMBER=0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${BLUE}=== Packet Filter Driver Loader ===${NC}"
    echo
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "This script must be run as root"
        exit 1
    fi
}

check_module_file() {
    if [ ! -f "$MODULE_FILE" ]; then
        print_error "Module file $MODULE_FILE not found"
        print_info "Try running 'make' first to build the module"
        exit 1
    fi
}

unload_module() {
    if lsmod | grep -q "^$MODULE_NAME"; then
        print_info "Unloading existing module..."
        rmmod "$MODULE_NAME" 2>/dev/null || true
        sleep 1
    fi
}

load_module() {
    print_info "Loading module..."
    insmod "$MODULE_FILE"
    
    # Wait for module to initialize
    sleep 2
    
    if ! lsmod | grep -q "^$MODULE_NAME"; then
        print_error "Failed to load module"
        return 1
    fi
    
    print_success "Module loaded successfully"
    return 0
}

check_device_file() {
    print_info "Checking device file..."
    
    # Wait for device to appear
    local count=0
    while [ ! -c "$DEVICE_PATH" ] && [ $count -lt 10 ]; do
        sleep 1
        count=$((count + 1))
    done
    
    if [ ! -c "$DEVICE_PATH" ]; then
        print_error "Device file $DEVICE_PATH not created"
        return 1
    fi
    
    # Get major number
    MAJOR_NUMBER=$(stat -c %t "$DEVICE_PATH" 2>/dev/null || echo "0")
    
    print_success "Device file created (major: 0x$MAJOR_NUMBER)"
    return 0
}

set_permissions() {
    print_info "Setting device permissions..."
    
    chmod 666 "$DEVICE_PATH" 2>/dev/null || true
    
    # Create udev rule if requested
    if [ "$1" = "--udev" ]; then
        print_info "Creating udev rule..."
        cat > /etc/udev/rules.d/99-packet-filter.rules << EOF
# Packet Filter Driver
KERNEL=="packet_filter", MODE="0666", GROUP="users"
EOF
        udevadm control --reload-rules
        udevadm trigger
    fi
    
    print_success "Permissions set"
}

test_driver() {
    print_info "Testing driver functionality..."
    
    if [ ! -x "$CONTROL_TOOL" ]; then
        print_warning "Control tool not found, skipping tests"
        return 0
    fi
    
    # Basic test
    if "$CONTROL_TOOL" --get-stats > /dev/null 2>&1; then
        print_success "Driver responds to commands"
    else
        print_error "Driver test failed"
        return 1
    fi
    
    # Set to loopback for testing
    "$CONTROL_TOOL" --set-device lo > /dev/null 2>&1 || true
    
    return 0
}

show_status() {
    print_info "Driver Status:"
    echo "    Module: $(lsmod | grep -q "^$MODULE_NAME" && echo "Loaded" || echo "Not loaded")"
    echo "    Device: $([ -c "$DEVICE_PATH" ] && echo "Present" || echo "Missing")"
    if [ -c "$DEVICE_PATH" ]; then
        echo "    Major: $(stat -c %t "$DEVICE_PATH" 2>/dev/null || echo "Unknown")"
    fi
    echo
}

cleanup() {
    print_info "Cleaning up..."
    
    # Remove device file if module not loaded
    if ! lsmod | grep -q "^$MODULE_NAME"; then
        rm -f "$DEVICE_PATH"
    fi
    
    # Remove udev rule if exists
    rm -f /etc/udev/rules.d/99-packet-filter.rules 2>/dev/null || true
}

usage() {
    echo "Usage: $0 [options]"
    echo
    echo "Options:"
    echo "  -h, --help      Show this help message"
    echo "  -l, --load      Load the driver (default)"
    echo "  -u, --unload    Unload the driver"
    echo "  -r, --reload    Reload the driver"
    echo "  -s, --status    Show driver status"
    echo "  -t, --test      Test driver after loading"
    echo "  --udev          Create udev rule for persistent permissions"
    echo "  --clean         Clean up device files and rules"
    echo
    echo "Examples:"
    echo "  $0 --load --test    Load and test driver"
    echo "  $0 --reload         Reload the driver"
    echo "  $0 --status         Show current status"
}

main() {
    local action="load"
    local do_test=0
    local do_udev=0
    local do_clean=0
    
    # Parse arguments
    while [ $# -gt 0 ]; do
        case $1 in
            -h|--help)
                usage
                exit 0
                ;;
            -l|--load)
                action="load"
                ;;
            -u|--unload)
                action="unload"
                ;;
            -r|--reload)
                action="reload"
                ;;
            -s|--status)
                action="status"
                ;;
            -t|--test)
                do_test=1
                ;;
            --udev)
                do_udev=1
                ;;
            --clean)
                do_clean=1
                ;;
            *)
                print_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
        shift
    done
    
    print_header
    
    check_root
    
    case $action in
        load)
            check_module_file
            unload_module
            load_module || exit 1
            check_device_file || exit 1
            [ $do_udev -eq 1 ] && set_permissions --udev || set_permissions
            [ $do_test -eq 1 ] && test_driver
            show_status
            ;;
            
        unload)
            print_info "Unloading driver..."
            unload_module
            cleanup
            print_success "Driver unloaded"
            ;;
            
        reload)
            check_module_file
            unload_module
            load_module || exit 1
            check_device_file || exit 1
            [ $do_udev -eq 1 ] && set_permissions --udev || set_permissions
            [ $do_test -eq 1 ] && test_driver
            show_status
            ;;
            
        status)
            show_status
            ;;
    esac
    
    if [ $do_clean -eq 1 ]; then
        cleanup
        print_success "Cleanup complete"
    fi
    
    echo
    print_success "Operation completed successfully"
}

# Handle script interruption
trap 'print_error "Interrupted"; cleanup; exit 1' INT TERM

main "$@"
