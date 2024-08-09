# Importing necessary libraries..
# 1. scapy = used for network packet manipulation.
# 2. datetime = for date and time..
from scapy.all import sniff, IP, TCP, UDP, ARP, ICMP, wrpcap 
from datetime import datetime

# 1. time stamp
# 2. packet summary
# 3. detailed analysis of IP, TCP, UDP, ARP, ICMP layers..
def process_packet(packet):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    #Print a brief summary of the packet
    print(f"\n[+] Captured Packet at {timestamp}")
    print(packet.summary())

    #Detailed packet analysis
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print(f"IP Packet: {ip_layer.src} -> {ip_layer.dst}")

        #Check if it is a TCP packet and print details
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            print(f"TCP Packet: Source Port {tcp_layer.sport} -> Destination Port {tcp_layer.dport}")

        #Check if this is a UDP packet and print details
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            print(f"UDP Packet: Source Port {udp_layer.sport} -> Destination Port {udp_layer.dport}")

    #If the packet is an ARP packet, print ARP-related details
    elif packet.haslayer(ARP):
        arp_layer = packet[ARP]
        print(f"ARP Packet: {arp_layer.psrc} -> {arp_layer.pdst}")

    #If the packet is an ICMP packet, print ICMP-related details
    elif packet.haslayer(ICMP):
        icmp_layer = packet[ICMP]
        print(f"ICMP Packet: Type {icmp_layer.type}, Code {icmp_layer.code}")

# Filter the packets we are intersted in, 
def packet_filter(packet):
    return packet.haslayer(IP) or packet.haslayer(ARP) or packet.haslayer(ICMP)

# start the packet sniffer..
# count = 26, That means this will capture packets for 26 times..
def start_sniffing():
    print("Starting advanced network sniffer...")
    packets = sniff(prn=process_packet, filter="ip or arp or icmp", lfilter=packet_filter, count=26)
    save_packets(packets)

# saving captured packet in .pcap format, which can be opened and analyzed through wireshark..
def save_packets(packets):
    pcap_file = f"captured_packets_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
    wrpcap(pcap_file, packets)
    print(f"\n[+] Packets saved to {pcap_file}")

# Main function to run the sniffer..
if __name__ == "__main__":
    start_sniffing()

     

    
