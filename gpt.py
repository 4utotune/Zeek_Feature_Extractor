from scapy.all import *

# Funzione per creare un pacchetto ICMP
def create_icmp_packet(src_ip, dst_ip):
    icmp_packet = IP(src=src_ip, dst=dst_ip)/ICMP()
    return icmp_packet

# Impostare gli indirizzi IP sorgente e destinazione
src_ip1 = "192.168.1.1"
dst_ip1 = "192.168.1.2"

src_ip2 = "192.168.1.3"
dst_ip2 = "192.168.1.4"

# Creare i pacchetti ICMP
icmp_packet1 = create_icmp_packet(src_ip1, dst_ip1)
icmp_packet2 = create_icmp_packet(src_ip2, dst_ip2)

# Unire i pacchetti in una lista
packets = [icmp_packet1, icmp_packet2]

# Salvare i pacchetti in un file pcap
wrpcap("output.pcap", packets)

print("Pacchetti creati e salvati in output.pcap")
