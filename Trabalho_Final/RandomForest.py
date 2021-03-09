"""
Trabalho final - Ciência de Dados para Segurança (CI1030) - Trabalho Final
Alunos:
    Michael A Hempkemeyer (PPGINF-202000131795)
    Roger R R Duarte (PPGINF-202000131793)

Antes de executar esse script, execute o pré-processamento através do py "PreProcessamento.py"
Esse script faz o processamento do dataset com o RandonForest
"""
import sys

import pandas as pd
import os
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import MinMaxScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix
import numpy as np
from sklearn.metrics import accuracy_score

# Caminho dos DataSets
data_path_80 = os.path.join("dataset", "data-list-80.csv")
data_path_20 = os.path.join("dataset", "data-list-20.csv")

# Verifica se os arquivos de dataset pré-processados existem
if os.path.isfile(data_path_80) is False or os.path.isfile(data_path_20) is False:
    print(f"Arquivos \"{data_path_80}\" e \"{data_path_20}\" não encontrados")
    print("Execute primeiramente o pré-processamento com o script \"PreProcessamento.py\"")
    sys.exit(-1)

# Atribuição das colunas conforme o tipo das colunas
all_attributes = ["cvss", "cwe", "access", "impact", "summary", "vulnerable_configuration_cpe_2_2"]
textual_attributes = ["cwe", "summary", "vulnerable_configuration_cpe_2_2"]
numerical_attributes = ["cvss", "access"]
label_attribute = "impact"

# Criação dos DataFrames conforme as porções de dados
df_data = pd.read_csv(data_path_80)

# Valor do label, que será utilizado para classificação
label = df_data[label_attribute].values


def split_data(param_data):
    # Função utilizada para realizar o split dos dados
    # Parte serão utilizadas para treinamento, e demiais para dados
    middle = int((len(param_data) + 1) / 2)
    train_data_f = param_data[:middle]
    test_data_f = param_data[middle:]
    return train_data_f, test_data_f


def textual_feature_extraction(train_data_param, test_data_param, extractor=TfidfVectorizer(max_features=200)):
    extractor.fit(train_data_param)
    train_features_o = extractor.transform(train_data_param)
    test_features_o = extractor.transform(test_data_param)

    return train_features_o, test_features_o


# Split dos dados
train_data, test_data = split_data(df_data)
train_label, test_label = split_data(label)

# Obtem atributos numéricos
train_features = train_data[numerical_attributes].values
test_features = test_data[numerical_attributes].values

# Faz o tratamento de características textuais e já faz a junção com os numéricos
for a in textual_attributes:
    train_texts, test_texts = textual_feature_extraction(train_data[a], test_data[a])
    train_features = np.concatenate((train_features, train_texts.toarray()), axis=1)
    test_features = np.concatenate((test_features, test_texts.toarray()), axis=1)

# Faz a normalização
scaler_param = MinMaxScaler()
scaler_param.fit(train_features)
train_features_norm = scaler_param.transform(train_features)
test_features_norm = scaler_param.transform(test_features)


# Inicializa
clf = RandomForestClassifier(n_estimators=10, random_state=0)
# Treina o classificador
clf.fit(train_features_norm, train_label)
# Classe de predição
test_pred = clf.predict(test_features_norm)
# print(test_pred.shape, test_label.shape)


print("Acurácia: ")
print(accuracy_score(test_label, test_pred))
print("Matriz de confusão: ")
print(confusion_matrix(test_label, test_pred))

print("Finalizado")
sys.exit(0)
