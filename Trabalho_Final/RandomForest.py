"""
Trabalho final - Ciência de Dados para Segurança (CI1030) - Trabalho Final
Alunos:
    Michael A Hempkemeyer (PPGINF-202000131795)
    Roger R R Duarte (PPGINF-202000131793)

Antes de executar esse script, execute o pré-processamento através do py "PreProcessamento.py"
Esse script faz o processamento do dataset com o RandonForest

Referência:
https://github.com/fabriciojoc/ml-cybersecuritiy-course/
"""
import sys

import pandas as pd
import os

from gensim.models import Word2Vec
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import MinMaxScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix
import numpy as np
from sklearn.metrics import accuracy_score
import numpy as np

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
    """
    Função utilizada para realizar o split dos dados
    :param param_data: dataset
    :return: duas porções do dataset, uma com 80% dos dados e outra com 20%
    """
    middle = int((len(param_data) + 1) / 2)
    train_data_f = param_data[:middle]
    test_data_f = param_data[middle:]
    return train_data_f, test_data_f


def textual_feature_tfid(train_data_param, test_data_param):
    """
    Função utilizada para o processamento do Tf-idf
    :param train_data_param: dataset de treino
    :param test_data_param: dataset de test
    :return: dois dataset processados pelo tf-idf
    """
    extractor = TfidfVectorizer(max_features=100)
    extractor.fit(train_data_param)
    train_features_o = extractor.transform(train_data_param)
    test_features_o = extractor.transform(test_data_param)
    return train_features_o, test_features_o


class MeanEmbeddingVectorizer(object):
    """
    Classe utilizada para o processamento do Word2Vec
    Referência: https://github.com/fabriciojoc/ml-cybersecuritiy-course/blob/master/04_features.ipynb
    """
    def __init__(self, size, min_count=1):
        self.size = size
        self.min_count = 1

    def fit(self, X):
        w2v = Word2Vec(X, size=self.size, min_count=self.min_count)
        self.word2vec = dict(zip(w2v.wv.index2word, w2v.wv.vectors))
        # if a text is empty we should return a vector of zeros
        # with the same dimensionality as all the other vectors
        self.dim = len(list(self.word2vec.values())[0])
        return self

    def transform(self, X):
        return np.array([
            np.mean([self.word2vec[w] for w in words if w in self.word2vec]
                    or [np.zeros(self.dim)], axis=0)
            for words in X
        ])


def textual_feature_word2vec(train_data_param, test_data_param):
    """
    Função utilizada para o processamento do Word2Vec
    :param train_data_param: dataset de treino
    :param test_data_param: dataset de test
    :return: dois dataset processados pelo Word2Vec
    """
    word2vec = MeanEmbeddingVectorizer(size=200)
    word2vec.fit(train_data_param)
    train_features_o = word2vec.transform(train_data_param)
    test_features_o = word2vec.transform(test_data_param)
    return train_features_o, test_features_o


def generate_randon_forest(text_type="tfid"):
    # Split dos dados
    train_data, test_data = split_data(df_data)
    train_label, test_label = split_data(label)

    # Obtem atributos numéricos
    train_features = train_data[numerical_attributes].values
    test_features = test_data[numerical_attributes].values

    # Faz o tratamento das características textuais e já faz a junção com os numéricos
    for a in textual_attributes:
        if text_type == "tfid":
            train_texts, test_texts = textual_feature_tfid(train_data[a].values, test_data[a].values)
            train_features = np.concatenate((train_features, train_texts.toarray()), axis=1)
            test_features = np.concatenate((test_features, test_texts.toarray()), axis=1)
        elif text_type == "word2vec":
            train_texts, test_texts = textual_feature_word2vec(train_data[a].values, test_data[a].values)
            train_features = np.concatenate((train_features, train_texts), axis=1)
            test_features = np.concatenate((test_features, test_texts), axis=1)

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

    print(f"Acurácia ({text_type}): ", end="")
    print(accuracy_score(test_label, test_pred))
    print(f"Matriz de confusão ({text_type}): ")
    print(confusion_matrix(test_label, test_pred))


generate_randon_forest("tfid")
generate_randon_forest("word2vec")

sys.exit(0)
