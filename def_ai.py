import numpy as np
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout
from tensorflow.keras.utils import to_categorical
from tensorflow.keras.callbacks import Callback
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split

print("Caricamento del dataset...")
# Carica i dati dal disco con allow_pickle=True
x_train = np.load("x_train0.npy")
y_train = np.load("y_train0.npy")
x_test = np.load("x_test0.npy")
y_test = np.load("y_test0.npy")

print("Dataset caricato correttamente.")
# Codifica le etichette
le = LabelEncoder()
y_train_encoded = to_categorical(le.fit_transform(y_train))
y_test_encoded = to_categorical(le.transform(y_test))

# Aggiungi una dimensione alle features
x_train = np.expand_dims(x_train, axis=-1)
x_test = np.expand_dims(x_test, axis=-1)

print("Dimensioni x_train:", x_train.shape)
print("Dimensioni y_train_encoded:", y_train_encoded.shape)
print("Dimensioni x_test:", x_test.shape)
print("Dimensioni y_test_encoded:", y_test_encoded.shape)
print("Tipo di dato x_train:", type(x_train))
print("Tipo di dato y_train_encoded:", type(y_train_encoded))
print("Tipo di dato x_test:", type(x_test))
print("Tipo di dato y_test_encoded:", type(y_test_encoded))
print("Inizio training...")

# Definisci il modello della rete neurale (feedforward)
model = Sequential()
model.add(Dense(64, input_shape=(x_train.shape[1],), activation='relu'))
model.add(Dropout(0.5))
model.add(Dense(32, activation='relu'))
model.add(Dense(2, activation='softmax'))  # Output layer con 2 neuroni per la classificazione binaria
model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])

# Aggiungi la callback personalizzata al modello
class PredictionCallback(Callback):
    def on_epoch_end(self, epoch, logs=None):
        # Prendi a caso un esempio da x_test
        random_index = np.random.randint(0, len(x_test))
        x_example = np.expand_dims(x_test[random_index], axis=0)
        y_true = y_test[random_index]

        # Fai la previsione con il modello
        y_pred = self.model.predict(x_example)[0]

        # Decodifica le etichette
        decoded_true = le.inverse_transform([np.argmax(y_true)])[0]
        decoded_pred = le.inverse_transform([np.argmax(y_pred)])[0]

        # Stampa le informazioni
        print(f"\nEpoch {epoch + 1} - Random Example Prediction:")
        print(f"True Label: {decoded_true}")
        print(f"Predicted Label: {decoded_pred}")

# Addestra il modello con la callback
model.fit(x_train, y_train_encoded, epochs=10, batch_size=32, validation_data=(x_test, y_test_encoded), callbacks=[PredictionCallback()])

# Valuta il modello
loss, accuracy = model.evaluate(x_test, y_test_encoded)
print(f"\nTest Loss: {loss}, Test Accuracy: {accuracy}")

# Salva il modello su disco
model.save("modello_di_classificazione.h5")
