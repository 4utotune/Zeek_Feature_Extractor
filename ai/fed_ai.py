import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense
from tensorflow.keras.layers import Dropout
from tensorflow.keras.layers import LSTM
from tensorflow.keras.callbacks import Callback
import random
from tensorflow.keras.preprocessing.sequence import pad_sequences

# Carica i dati dai file con allow_pickle=True
labels_0 = np.load("labs0.npy", allow_pickle=True)
features_0 = np.load("feats0.npy", allow_pickle=True)
labels_1 = np.load("labs1.npy", allow_pickle=True)
features_1 = np.load("feats1.npy", allow_pickle=True)

class RandomTestPredictionCallback(Callback):
    def on_epoch_end(self, epoch, logs=None):
        # Scegli casualmente un campione dal set di test
        random_index = random.randint(0, len(X_test) - 1)
        sample_X = X_test[random_index]
        sample_y = y_test[random_index]

        # Effettua la predizione
        prediction = self.model.predict(np.expand_dims(sample_X, axis=0))[0][0]

        # Stampa i risultati
        print(f"\nEpoch {epoch + 1} - Random Test Sample:")
        #print(f"Input: {sample_X}")
        if prediction >= 0.5:
            print(f"True Label: {sample_y} - Predicted Label: [1]")
        else:
            print(f"True Label: {sample_y} - Predicted Label: [0]")
        print(f"Predicted Probability: {prediction}")

# Unisci i dataset
labels = np.concatenate((labels_0, labels_1), axis=0)
features = np.concatenate((features_0, features_1), axis=0)

# Mescola i dati
indices = np.arange(len(labels))
np.random.shuffle(indices)

labels = labels[indices]
features = features[indices]

# Appiattisci completamente le features
X_flat = [item for sublist in features for item in sublist]

# Converte le liste appiattite in array NumPy
X_flat = np.array(X_flat)

# Standardizza le features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X_flat)

# Reshape delle features appiattite in forma originale
X_scaled = X_scaled.reshape(features.shape)

# Definisci la lunghezza massima della sequenza desiderata
max_sequence_length = 1000

# Pad delle sequenze per uniformarle a lunghezza fissa
X_padded = pad_sequences(X_scaled, maxlen=max_sequence_length, padding='post', truncating='post')

# Converti labels in array bidimensionale
labels = labels.reshape(-1, 1)

# Dividi i dati in set di allenamento e set di test
X_train, X_test, y_train, y_test = train_test_split(X_padded, labels, test_size=0.2, random_state=42)

# Creazione del modello
model = Sequential()
model.add(LSTM(128, input_shape=(max_sequence_length, features.shape[2])))
model.add(Dense(64, activation='relu'))
model.add(Dropout(0.5))
model.add(Dense(1, activation='sigmoid'))

# Compilazione del modello
model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])

# Allenamento del modello
model.fit(X_train, y_train, epochs=10, batch_size=32, validation_split=0.1, callbacks=[RandomTestPredictionCallback()])
# Valutazione del modello
loss, accuracy = model.evaluate(X_test, y_test)
print(f"Test Loss: {loss}, Test Accuracy: {accuracy}")

# Salvataggio del modello
model.save("binary_classifier_model.h5")
