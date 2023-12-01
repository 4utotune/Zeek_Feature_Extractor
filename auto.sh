#!/bin/bash

# Directory paths
script_dir="script"
pcap_base_dir="benign"
output_dir="results"

# Create output directory if not exists
mkdir -p "$output_dir"

# Iterate over pcap directories
for pcap_dir in "$pcap_base_dir"/*; do
    if [ -d "$pcap_dir" ]; then
        # Extract network capture folder name
        capture_folder=$(basename "$pcap_dir")"-network-capture"

        # Create output subdirectory
        output_subdir="$output_dir/$capture_folder"
        mkdir -p "$output_subdir"

        # Iterate over pcap files
        for pcap_file in "$pcap_dir/$capture_folder"/*.pcap; do
            if [ -f "$pcap_file" ]; then
                # Run Zeek script for each pcap file
                script_name=$(basename "$script_dir")
                output_file="$output_subdir/$(basename "$pcap_file" .pcap)_output.txt"
                zeek -C -r "$pcap_file" "$script_dir" > "$output_file"
                echo "Analysis completed for $pcap_file. Results saved to $output_file"
            fi
        done
    fi
done
