from scapy.all import sniff, Raw

def show(packet):
    if packet.haslayer(Raw):
        print(packet[Raw].load)

sniff(filter="tcp port 80", prn=show)
