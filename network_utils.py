import socket
import netifaces
from scapy.all import ARP, arping, sr, conf

def get_primary_ipv4_interface():
    """
    Returns the primary (default) IPv4 network interface name, or None if not found.
    """
    try:
        default = netifaces.gateways().get('default', {})
        return default.get(netifaces.AF_INET, [None, None])[1]
    except Exception:
        return None

def get_ipv4_address(interface):
    """
    Returns the first IPv4 address assigned to the given interface, or None if not found.
    """
    addrs = netifaces.ifaddresses(interface)
    ipv4_info = addrs.get(netifaces.AF_INET)
    if ipv4_info and len(ipv4_info) > 0:
        return ipv4_info[0].get('addr')
    
    return None

def get_gateway_ip():
    """
    Returns the default gateway IP address for the primary IPv4 interface, or None if not found.
    """
    gws = netifaces.gateways()
    default = gws.get('default')
    if default and netifaces.AF_INET in default:
        return default[netifaces.AF_INET][0]
    
    return None

def get_network_prefix(ip_addr, cidr=24):
    """
    Returns the network prefix in CIDR notation for the given IPv4 address.
    Example: '192.168.1.42' -> '192.168.1.0/24'
    """
    octets = ip_addr.split('.')
    if len(octets) != 4:
        raise ValueError("Invalid IPv4 address format.")
    
    return f"{'.'.join(octets[:3])}.0/{cidr}"

def get_gateway_mac(gateway_ip, interface):
    """
    Resolves the MAC address of the gateway IP using ARP.
    """
    conf.verb = 0
    conf.iface = interface
    response, _ = sr(ARP(pdst=gateway_ip), timeout=7, verbose=0)

    if response:
        return response[0][1].hwsrc
    
    raise RuntimeError("Failed to resolve the gateway MAC address.")

def discover_hosts(local_ip, scan_timeout=2):
    """
    Scans the local network for connected devices.
    Returns a list of dicts: [{'name': ..., 'ip': ..., 'mac': ...}, ...]
    """
    subnet = get_network_prefix(local_ip)
    print("Searching for reachable targets in the network - this may take while...", end="", flush=True)
    
    host_list = []
    responses, _ = arping(subnet, timeout=scan_timeout, verbose=0)
    for _, reply in responses:
        address = reply.psrc
        mac_addr = reply.hwsrc
        
        try:
            hostname = socket.gethostbyaddr(address)[0]
        except Exception:
            hostname = "unknown hostname"

        host_list.append({'name': hostname, 'ip': address, 'mac': mac_addr})
    
    print(f"{len(host_list)} found")
    return host_list

if __name__ == "__main__":
    """
    Search for devices in the local network and prints their corresponding addresses to console.
    """
    interface = get_primary_ipv4_interface()
    if not interface:
        raise RuntimeError("Could not detect default network interface.")
    
    local_ip = get_ipv4_address(interface)
    devices = discover_hosts(local_ip)
    for device in devices:
        print(f"\t- Name: {device['name']}, IP: {device['ip']}, MAC: {device['mac']}")