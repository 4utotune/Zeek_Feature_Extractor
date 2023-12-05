import os
import numpy as np
from tqdm import tqdm
from sklearn.preprocessing import LabelEncoder
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout, LSTM
from tensorflow.keras.utils import to_categorical
import dpkt
import socket

# Directory dei dataset
dataset_path_legittimo = "/Users/gabrieletassinari/Desktop/Zeek_Feature_Extractor/dataset_leg/"
dataset_path_malevolo = "/Users/gabrieletassinari/Desktop/Zeek_Feature_Extractor/dataset_malevolo/"

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

# Caricamento dei dati legittimi
load_data_from_directory(dataset_path_legittimo, label=0)

# Caricamento dei dati malevoli
load_data_from_directory(dataset_path_malevolo, label=1)

# Converte le liste in array numpy
labels = np.array(labels)

# Padding dei pacchetti per uniformare le dimensioni
features_padded = [file_features + [[None] * 13] * (max_packets - len(file_features)) for file_features in features]

# Converte le feature in un array NumPy
features_padded = np.array(features_padded)

# Salva gli array NumPy su disco
np.save("labels0.npy", labels)
np.save("features_padded0.npy", features_padded)

# Suddividi il dataset in training e test set
train_size = int(0.9 * len(features_padded))

# Suddividi i dati in un training set e un testing set
x_train, x_test = features_padded[:train_size], features_padded[train_size:]
y_train, y_test = labels[:train_size], labels[train_size:]

# Codifica le etichette
le = LabelEncoder()
y_train_encoded = to_categorical(le.fit_transform(y_train))
y_test_encoded = to_categorical(le.transform(y_test))

print("Inizio training...")
# Costruisci il modello della rete neurale
model = Sequential()
model.add(LSTM(64, input_shape=(max_packets, 13), activation='relu'))
model.add(Dropout(0.5))
model.add(Dense(32, activation='relu'))
model.add(Dense(2, activation='softmax'))  # Output layer con 2 neuroni per la classificazione binaria
model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])

# Addestra il modello
model.fit(x_train, y_train_encoded, epochs=10, batch_size=32, validation_data=(x_test, y_test_encoded))

# Valuta il modello
loss, accuracy = model.evaluate(x_test, y_test_encoded)
print(f"Test Loss: {loss}, Test Accuracy: {accuracy}")

# Salva il modello su disco
model.save("modello_di_classificazione.h5")
