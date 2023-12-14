#!/bin/bash

# Directory paths
pcap_base_dir="/Users/gabrieletassinari/Desktop/Zeek_Feature_Extractor/attack"

# Creare una variabile per i totali
touch finale2.txt

for pcap_file in "$pcap_base_dir"/*.pcap; do
    if [ -f "$pcap_file" ]; then
        # Eseguire lo script Zeek e salvare l'output
        zeek -C -r "$pcap_file" complessivo.zeek >> finale2.txt
        
        echo "Analysis completed for $pcap_file"
    fi
done

#Total results:
#flows=9055995, src_bytes=3179361798, dst_bytes=2368174501, src_pkt=49821269, dst_pkt=38436078, tcp=9042823, udp=11964, icmp=1208, other=80