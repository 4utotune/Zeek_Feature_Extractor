#!/bin/bash

# Directory paths
pcap_base_dir="benign"
output_dir="results"

# Creare una variabile per i totali
total_stats="flows=0, src_bytes=0, dst_bytes=0, src_pkt=0, dst_pkt=0, tcp=0, udp=0, icmp=0, other=0"

# Iterate over pcap directories
for pcap_dir in "$pcap_base_dir"/*; do
    if [ -d "$pcap_dir" ]; then
        # Estrarre il nome della cartella di cattura di rete
        capture_folder=$(basename "$pcap_dir")"-network-capture"

        # Creare una sottodirectory di output
        output_subdir="$output_dir/$capture_folder"
        mkdir -p "$output_subdir"

        # Iterare sui file pcap
        for pcap_file in "$pcap_dir/$capture_folder"/*.pcap; do
            if [ -f "$pcap_file" ]; then
                # Eseguire lo script Zeek per ciascun file pcap
                output_file="$output_subdir/$(basename "$pcap_file" .pcap)_output.txt"
                
                # Eseguire lo script Zeek e salvare l'output
                zeek -C -r "$pcap_file" complessivo.zeek > "$output_file"
                
                # Aggiornare i totali con i risultati di ogni file
                current_stats=$(tail -n 1 "$output_file")
                total_stats=$(echo "$total_stats" | awk -v current="$current_stats" '{split($0, a, ", "); split(current, b, ", "); for(i=1; i<=NF; i++) {split(a[i], c, "="); split(b[i], d, "="); c[2]+=d[2]; a[i]=c[1]"="c[2]} print a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9]}')

                echo "Analysis completed for $pcap_file. Results saved to $output_file"
            fi
        done
    fi
done

# Stampare i totali alla fine
echo "Total results: [$total_stats]"
