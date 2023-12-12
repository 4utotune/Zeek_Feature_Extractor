import os
import numpy as np
from sklearn.preprocessing import LabelEncoder
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout, LSTM
from tensorflow.keras.utils import to_categorical
import scapy.all as scapy
import multiprocessing
from tqdm import tqdm  # Importa tqdm

# Carica il dataset
dataset_path_legittimo = "/Users/gabrieletassinari/Desktop/Zeek_Feature_Extractor/dataset_legittimo/"
dataset_path_malevolo = "/Users/gabrieletassinari/Desktop/Zeek_Feature_Extractor/dataset_malevolo/"
labels = []
features = []

def extract_features(file_path):
    # Analizza il file pcap utilizzando scapy
    packets = scapy.rdpcap(file_path)
    return packets

# Loop per il dataset legittimo
for file_name in tqdm(os.listdir(dataset_path_legittimo), desc="Legittimo"):
    file_path = os.path.join(dataset_path_legittimo, file_name)
    if file_name.endswith(".pcap"):
        label = 0
        labels.append(label)
        features.append(extract_features(file_path))

# Loop per il dataset malevolo
for file_name in tqdm(os.listdir(dataset_path_malevolo), desc="Malevolo"):
    file_path = os.path.join(dataset_path_malevolo, file_name)
    if file_name.endswith(".pcap"):
        label = 1
        labels.append(label)
        features.append(extract_features(file_path))

print("----------------------------------------")
print("Dataset caricato correttamente.")
# Trova il numero massimo di pacchetti tra tutti i file
max_packets = max(len(packets) for packets in features)

# Padding dei pacchetti per uniformare le dimensioni
features_padded = [packets + [None] * (max_packets - len(packets)) for packets in features]

# Converte le liste in array numpy
labels = np.array(labels)
features_padded = np.array(features_padded)

# Salva gli array NumPy su disco
np.save("labels.npy", labels)
np.save("features_padded.npy", features_padded)

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
model.add(LSTM(64, input_shape=(max_packets, 1), activation='relu'))
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

multiprocessing.set_start_method('forkserver')
multiprocessing.get_start_method().run_exit_callbacks()
