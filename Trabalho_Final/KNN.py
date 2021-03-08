## KNN Code
import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
#Read dataset CSV file
list_columns = ["access_authentication","access_complexity","access_vector","impact_availability",
        "impact_confidentiality","impact_integrity","cvss"]
file_csv_OrdinalEncoder = "" 
dataset = pd.read_csv("/content/drive/My Drive/06_Mestrado/Aula-Ciencia_Dados/Trabalho_Final/data-list-80_OrdinalEncoder.csv", nrows=60000, usecols= list_columns)


X = dataset.iloc[:, :-1].values
y = dataset.iloc[:, 6].values

from sklearn.model_selection import train_test_split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20)

from sklearn.preprocessing import StandardScaler
scaler = StandardScaler()
scaler.fit(X_train)

X_train = scaler.transform(X_train)
X_test = scaler.transform(X_test)

from sklearn.neighbors import KNeighborsClassifier
classifier = KNeighborsClassifier(n_neighbors=5)
classifier.fit(X_train, y_train)

y_pred = classifier.predict(X_test)

from sklearn.metrics import classification_report, confusion_matrix
print(confusion_matrix(y_test, y_pred))
print(classification_report(y_test, y_pred))


error = []

# Calculating error for K values between 1 and 40
for i in range(1, 40):
    knn = KNeighborsClassifier(n_neighbors=i)
    knn.fit(X_train, y_train)
    pred_i = knn.predict(X_test)
    error.append(np.mean(pred_i != y_test))


plt.figure(figsize=(12, 6))
plt.plot(range(1, 40), error, color='red', linestyle='dashed', marker='o',
         markerfacecolor='blue', markersize=10)
plt.title('Error Rate K Value')
plt.xlabel('K Value')
plt.ylabel('Mean Error')
