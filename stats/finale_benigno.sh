#!/bin/bash

# Directory paths
pcap_base_dir="benign"

# Creare una variabile per i totali
touch finale.txt
# Iterate over pcap directories
for pcap_dir in "$pcap_base_dir"/*; do
    if [ -d "$pcap_dir" ]; then
        # Estrarre il nome della cartella di cattura di rete
        capture_folder=$(basename "$pcap_dir")"-network-capture"

        # Iterare sui file pcap
        for pcap_file in "$pcap_dir/$capture_folder"/*.pcap; do
            if [ -f "$pcap_file" ]; then
                # Eseguire lo script Zeek e salvare l'output
                zeek -C -r "$pcap_file" complessivo.zeek >> finale.txt
                
                echo "Analysis completed for $pcap_file"
            fi
        done
    fi
done

#Total results:
#flows=4559770, src_bytes=1478356764, dst_bytes=1128175330, src_pkt=26006278, dst_pkt=20094581, tcp=4550004, udp=8589, icmp=1177, other=60