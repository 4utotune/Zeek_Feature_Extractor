import os
import scapy.all as scapy
import numpy as np
from tqdm import tqdm

dataset_path_malevolo = "/Users/gabrieletassinari/Desktop/Zeek_Feature_Extractor/dataset_malevolo/"
labels = []
features = []

def extract_features(file_path):
    # Analizza il file pcap utilizzando scapy
    packets = scapy.rdpcap(file_path)
    return packets

for file_name in tqdm(os.listdir(dataset_path_malevolo), desc="Legittimo"):
    file_path = os.path.join(dataset_path_malevolo, file_name)
    if file_name.endswith(".pcap"):
        label = 1
        labels.append(label)
        features.append(extract_features(file_path))

labels = np.array(labels)
features = np.array(features)

np.save("labels2.npy", labels)
np.save("features2.npy", features)