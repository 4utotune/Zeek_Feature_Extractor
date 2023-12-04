import os
import scapy.all as scapy
import numpy as np
from tqdm import tqdm

dataset_path_legittimo = "/Users/gabrieletassinari/Desktop/Zeek_Feature_Extractor/dataset_legittimo/1/"
labels = []
features = []

def extract_features(file_path):
    # Analizza il file pcap utilizzando scapy
    packets = scapy.rdpcap(file_path)
    return packets

for file_name in tqdm(os.listdir(dataset_path_legittimo), desc="Legittimo1"):
    file_path = os.path.join(dataset_path_legittimo, file_name)
    if file_name.endswith(".pcap"):
        label = 0
        labels.append(label)
        features.append(extract_features(file_path))

labels = np.array(labels)
features = np.array(features)

np.save("labels.npy", labels)
np.save("features.npy", features)
print("Dataset caricato correttamente.")