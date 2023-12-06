import os
import numpy as np
from tqdm import tqdm
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout, LSTM
from tensorflow.keras.utils import to_categorical
import dpkt
import socket

# Directory dei dataset
dataset_path_legittimo = "/Users/gabrieletassinari/Desktop/Zeek_Feature_Extractor/dataset_leg/"
#dataset_path_malevolo = "/Users/gabrieletassinari/Desktop/Zeek_Feature_Extractor/dataset_malevolo/"

# Lista per le etichette e le features
labels = []
features = []
max_packets = 0

def extract_features(file_path):
    global max_packets
    file_features = []

    with open(file_path, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        packets = list(pcap)

        if len(packets) > max_packets:
            max_packets = len(packets)

        for _, buf in packets:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            tcp = ip.data

            try:
                if isinstance(ip, dpkt.ip.IP):
                    # Estrai informazioni di interesse solo se il pacchetto è di tipo IP
                    src_ip = socket.inet_ntoa(ip.src)
                    dst_ip = socket.inet_ntoa(ip.dst)
                else:
                    # Ignora i pacchetti che non sono di tipo IP (ad esempio ARP)
                    continue
            except OSError as e:
                print(f"Error decoding IP addresses in file {file_path}: {e}")
                print(f"Packet data: {buf}")
                continue

            protocol = ip.p
            length = len(buf)

            # Informazioni protocollo di trasporto (TCP/UDP)
            if isinstance(tcp, dpkt.tcp.TCP):
                src_port = tcp.sport
                dst_port = tcp.dport
                flags = tcp.flags
                seq_number = tcp.seq
                ack_number = tcp.ack
            elif isinstance(ip.data, dpkt.udp.UDP):
                src_port = ip.data.sport
                dst_port = ip.data.dport
                flags = None
                seq_number = ack_number = None
            else:
                src_port = dst_port = flags = seq_number = ack_number = None

            # Informazioni IP
            ip_version = ip.v
            ttl = ip.ttl
            identification = ip.id
            fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

            # Aggiungi le feature alla lista
            file_features.append([
                src_ip, dst_ip, protocol, length,
                src_port, dst_port, flags,
                ip_version, ttl, identification, fragment_offset,
                seq_number, ack_number
            ])

    features.append(file_features)

# Funzione per caricare i dati da una directory
def load_data_from_directory(directory, label):
    data = []
    for file_name in tqdm(os.listdir(directory), desc="Caricamento dati"):
        file_path = os.path.join(directory, file_name)
        if file_name.endswith(".pcap"):
            labels.append(label)
            extract_features(file_path)
    return data

if __name__ == "__main__":
    # Caricamento dei dati legittimi
    load_data_from_directory(dataset_path_legittimo, label=0)

    # Converte le liste in array numpy
    labels = np.array(labels)

    # Padding dei pacchetti per uniformare le dimensioni
    max_seq_length = max_packets  # Usa la lunghezza massima dei pacchetti
    features_padded = []

    for file_features in features:
        # Padding delle sequenze per uniformare le dimensioni
        padding_size = max_seq_length - len(file_features)
        padded_sequence = file_features + [[None] * 13] * padding_size
        features_padded.append(padded_sequence)

    # Converte le feature in un array NumPy
    features = np.array(features_padded, dtype=object)

    # Salva gli array NumPy su disco
    np.save("labels0.npy", labels)
    np.save("features_padded0.npy", features)