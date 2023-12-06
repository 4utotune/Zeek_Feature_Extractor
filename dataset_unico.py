import numpy as np
from sklearn.model_selection import train_test_split

# Carica i dati dai file numpy
labels0 = np.load("labels0.npy")
features_padded0 = np.load("features_padded0.npy", allow_pickle=True)
labels2 = np.load("labels2.npy")
features_padded2 = np.load("features_padded2.npy", allow_pickle=True)

# Unisci i dati relativi a label 0 e label 2
all_labels = np.concatenate((labels0, labels2))
all_features_padded = np.concatenate((features_padded0, features_padded2))

# Mescola i dati
indices = np.arange(len(all_labels))
np.random.shuffle(indices)

shuffled_labels = all_labels[indices]
shuffled_features_padded = all_features_padded[indices]

# Suddividi il dataset in training set e test set (90% training, 10% test)
train_size = int(0.9 * len(shuffled_labels))
x_train, x_test, y_train, y_test = train_test_split(shuffled_features_padded, shuffled_labels, test_size=0.1, random_state=42)

# Salva gli array NumPy su disco
np.save("x_train0.npy", x_train)
np.save("x_test0.npy", x_test)
np.save("y_train0.npy", y_train)
np.save("y_test0.npy", y_test)
