import os
import numpy as np
from tqdm import tqdm
from concurrent.futures import ProcessPoolExecutor
import dpkt
import socket

# Funzione di estrazione delle feature con lunghezza fissa
def extract_features(file_path, max_packets=235092):  # Impostiamo un limite massimo di pacchetti per file
    file_features = []

    with open(file_path, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        packets = list(pcap)[:max_packets]  # Limitiamo il numero di pacchetti

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
                flags = 0
                seq_number = ack_number = 0
            else:
                src_port = dst_port = flags = seq_number = ack_number = 0

            # Informazioni IP
            ip_version = ip.v
            ttl = ip.ttl
            identification = ip.id
            fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

            # Aggiungi le feature alla lista
            file_features.append([
                protocol, length,
                src_port, dst_port, flags,
                ip_version, ttl, identification, fragment_offset,
                seq_number, ack_number
            ])

    # Ridimensiona la lista di feature per ottenere lunghezza fissa
    pad_length = max_packets - len(file_features)
    file_features.extend([[0] * len(file_features[0])] * pad_length)

    return np.array(file_features)

# Definizione della funzione per il caricamento parallelo dei dati
def load_data_from_directory_parallel(directory, label, max_packets=235092):
    data = []
    with ProcessPoolExecutor() as executor:
        futures = [executor.submit(extract_features, os.path.join(directory, file_name), max_packets) for file_name in os.listdir(directory) if file_name.endswith(".pcap")]
        for future in tqdm(futures, desc="Caricamento dati"):
            result = future.result()
            if len(result) > 0:
                labels.append(label)
                features.append(result)
    return data

if __name__ == "__main__":
    # Directory dei dataset
    dataset_path_legittimo = "/Users/gabrieletassinari/Desktop/Zeek_Feature_Extractor/dataset_malevolo2/"

    # Lista per le etichette e le features
    labels = []
    features = []

    # Caricamento dei dati in modo parallelo
    load_data_from_directory_parallel(dataset_path_legittimo, label=1, max_packets=235092)

    print("sono qui")
    # Converte le liste in array numpy
    labels = np.array(labels)

    print("ora qui")
    # Converte le feature in un array NumPy con dtype=object
    features = np.array(features, dtype=object)

    print("e qui")
    # Salva gli array NumPy su disco
    np.save("labsi1.npy", labels)
    np.save("featsi1.npy", features)
