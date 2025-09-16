#!/usr/bin/env python3
from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP
TIMEOUT = 10  # ثواني
def show(pkt):
    try:
        # Ethernet layer
        if pkt.haslayer(Ether):
            eth = pkt[Ether]
            eth_info = f"ETH {eth.src}->{eth.dst} type={hex(eth.type)}"
        else:
            eth_info = "ETH -"
        # IPv4 layer
        if pkt.haslayer(IP):
            ip = pkt[IP]
            ip_info = f"IP {ip.src}->{ip.dst} proto={ip.proto}"
        else:
            ip_info = "IP -"
        # Transport layer
        if pkt.haslayer(TCP):
            t = pkt[TCP]
            l4 = f"TCP sport={t.sport} dport={t.dport}"
        elif pkt.haslayer(UDP):
            u = pkt[UDP]
            l4 = f"UDP sport={u.sport} dport={u.dport}"
        elif pkt.haslayer(ICMP):
            ic = pkt[ICMP]
            l4 = f"ICMP type={ic.type} code={ic.code}"
        else:
            l4 = "L4 -"
        # Payload (أول 20 بايت بس)
        raw_data = bytes(pkt.payload)[:20]
        payload = raw_data.hex() if raw_data else "no data"
        print(f"{eth_info} | {ip_info} | {l4} | Payload: {payload}")
    except Exception as e:
        print("Error:", e)
if __name__ == "__main__":
    try:
        sniff(prn=show, store=False, timeout=TIMEOUT)
    except KeyboardInterrupt:
        print("Stopped by user.")