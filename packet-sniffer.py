from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

packet_count = 0
MAX_PACKETS = 10


def process_packet(packet):
    global packet_count

    if IP in packet:
        packet_count += 1

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        elif ICMP in packet:
            protocol = "ICMP"
        else:
            protocol = "IP"

        print("\n" + "=" * 60)
        print(f"PACKET {packet_count}/{MAX_PACKETS}")
        print("=" * 60)

        print(f"Source IP       : {source_ip}")
        print(f"Destination IP  : {destination_ip}")
        print(f"Protocol        : {protocol}")

        if TCP in packet:
            print(f"Source Port     : {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")

        elif UDP in packet:
            print(f"Source Port     : {packet[UDP].sport}")
            print(f"Destination Port: {packet[UDP].dport}")

        if Raw in packet:
            data = packet[Raw].load
            print(f"Packet Data     : {data[:100]}")

        print("=" * 60)


print("=" * 60)
print("       PYTHON NETWORK PACKET SNIFFER")
print("=" * 60)
print(f"Capturing {MAX_PACKETS} packets...")
print("The program will stop automatically.\n")


sniff(
    prn=process_packet,
    store=False,
    count=MAX_PACKETS,
    lfilter=lambda packet: IP in packet
)


print("\n" + "=" * 60)
print("CAPTURE COMPLETE")
print(f"Total packets captured: {packet_count}")
print("=" * 60)