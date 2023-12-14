#!/bin/bash

# File contenente i risultati Zeek
results_file="finale2.txt"

# Inizializza variabili per totali
total_flows=0
total_src_bytes=0
total_dst_bytes=0
total_src_pkt=0
total_dst_pkt=0
total_tcp=0
total_udp=0
total_icmp=0
total_other=0

# Leggi ogni riga del file di risultati
while IFS= read -r line; do
    # Estrai i valori da ogni campo
    flows=$(echo "$line" | awk -F ', ' '{print $1}' | cut -d= -f2)
    src_bytes=$(echo "$line" | awk -F ', ' '{print $2}' | cut -d= -f2)
    dst_bytes=$(echo "$line" | awk -F ', ' '{print $3}' | cut -d= -f2)
    src_pkt=$(echo "$line" | awk -F ', ' '{print $4}' | cut -d= -f2)
    dst_pkt=$(echo "$line" | awk -F ', ' '{print $5}' | cut -d= -f2)
    tcp=$(echo "$line" | awk -F ', ' '{print $6}' | cut -d= -f2)
    udp=$(echo "$line" | awk -F ', ' '{print $7}' | cut -d= -f2)
    icmp=$(echo "$line" | awk -F ', ' '{print $8}' | cut -d= -f2)
    #other=$(echo "$line" | awk -F ', ' '{print $9}' | cut -d= -f2)
    other=$(echo "$line" | awk -F ', ' '{print $9}' | cut -d= -f2 | cut -d']' -f1)

    # Somma i valori ai totali
    total_flows=$((total_flows + flows))
    total_src_bytes=$((total_src_bytes + src_bytes))
    total_dst_bytes=$((total_dst_bytes + dst_bytes))
    total_src_pkt=$((total_src_pkt + src_pkt))
    total_dst_pkt=$((total_dst_pkt + dst_pkt))
    total_tcp=$((total_tcp + tcp))
    total_udp=$((total_udp + udp))
    total_icmp=$((total_icmp + icmp))
    total_other=$((total_other + other))
done < "$results_file"

# Stampare i totali
echo "Total results:"
echo "flows=$total_flows, src_bytes=$total_src_bytes, dst_bytes=$total_dst_bytes, src_pkt=$total_src_pkt, dst_pkt=$total_dst_pkt, tcp=$total_tcp, udp=$total_udp, icmp=$total_icmp, other=$total_other"
