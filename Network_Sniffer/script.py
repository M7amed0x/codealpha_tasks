from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP
import textwrap

TIMEOUT = 10

def fmt(prefix, data, size=80):
    if isinstance(data, bytes):
        data = ''.join(f'\\x{b:02x}' for b in data)
    return '\n'.join(prefix + line for line in textwrap.wrap(str(data), size - len(prefix)))

def handle(pkt):
    if pkt.haslayer(Ether):
        eth = pkt[Ether]
        print(f"\nEthernet: dst={eth.dst}, src={eth.src}, type={eth.type}")
    if pkt.haslayer(IP):
        ip = pkt[IP]
        print(f" IPv4: {ip.src} -> {ip.dst}, proto={ip.proto}, ttl={ip.ttl}")
        if ip.proto == 1 and pkt.haslayer(ICMP):
            icmp = pkt[ICMP]
            print(f" ICMP: type={icmp.type}, code={icmp.code}")
            if hasattr(icmp, "load"):
                print(fmt("   ", bytes(icmp.load)))
        elif ip.proto == 6 and pkt.haslayer(TCP):
            tcp = pkt[TCP]
            print(f" TCP: {tcp.sport} -> {tcp.dport}, seq={tcp.seq}, ack={tcp.ack}, flags={tcp.flags}")
            print(fmt("   ", bytes(tcp.payload)))
        elif ip.proto == 17 and pkt.haslayer(UDP):
            udp = pkt[UDP]
            print(f" UDP: {udp.sport} -> {udp.dport}, len={udp.len}")
            print(fmt("   ", bytes(udp.payload)))

def main():
    sniff(prn=handle, store=False, timeout=TIMEOUT)

if __name__ == "__main__":
    main()
