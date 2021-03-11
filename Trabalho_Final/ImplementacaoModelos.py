"""
Trabalho final - Ciência de Dados para Segurança (CI1030) - Trabalho Final
Alunos:
    Michael A Hempkemeyer (PPGINF-202000131795)
    Roger R R Duarte (PPGINF-202000131793)

Antes de executar esse script, execute o pré-processamento através do py "PreProcessamento.py"
Esse script faz a criação e execução de modelos
"""
import math
import sys
import time

import pandas as pd
import os

from gensim.models import Word2Vec
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import MinMaxScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, precision_score, mean_absolute_error
import numpy as np
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC
import matplotlib.pyplot as plt
from sklearn.metrics import plot_roc_curve

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

# Apaga o label do dataset
del df_data[label_attribute]

# Variável para controle da geração das janelas de gráficos das curvas ROC
# Documentação base: https://scikit-learn.org/stable/auto_examples/miscellaneous/plot_roc_curve_visualization_api.html
generate_roc_curve = True


def split_data(param_data):
    """
    Função utilizada para realizar o split dos dados
    :param param_data: dataset
    :return: duas porções do dataset (80 e 20 % dos dados)
    """
    size_80 = math.floor((len(param_data) * 80) / 100)

    train_data_f = param_data[:size_80]
    test_data_f = param_data[size_80:]

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


def execute_kfold(model, X, Y, cv, model_name=""):
    """
    Execução k-fold cross validation, k=cv
    """
    global generate_roc_curve

    """
    https://scikit-learn.org/stable/modules/generated/sklearn.model_selection.StratifiedKFold.html
    https://scikit-learn.org/stable/glossary.html#term-random_state
    """
    kf = StratifiedKFold(n_splits=cv, random_state=None)

    count = 1
    ax = plt.gca()

    print(f"---------*--------- Kfold ({model_name}) ---------*---------")
    for train_index, test_index in kf.split(X, Y):
        X_train, X_test = X[train_index], X[test_index]
        Y_train, Y_test = Y[train_index], Y[test_index]
        clf = model
        clf.fit(X_train, Y_train)
        pred_t = clf.predict(X_test)
        print(f"Precisão: ", end="")
        print(precision_score(Y_test, pred_t))
        print(f"Erro (mean_absolute_error): ", end="")
        print(mean_absolute_error(Y_test, pred_t))
        print(f"Matriz de confusão: ")
        print(confusion_matrix(Y_test, pred_t))

        if generate_roc_curve is True:
            plot_roc_curve(clf, X_test, Y_test, ax=ax, label=f"{model_name}-{count}")
            count += 1

    if generate_roc_curve is True:
        plt.show()


def execute_model(model, train_features_norm, train_label, test_features_norm, test_label, model_name=""):
    global generate_roc_curve
    """
    Executa um modelo conforme parâmetros
    """
    if model_name == "RandomForestClassifier" or model_name == "KNeighborsClassifier" or model_name == "SVM":
        clf = model
        clf.fit(train_features_norm, train_label)
        test_pred = clf.predict(test_features_norm)
        print(f"---------*--------- Split percentage ({model_name}) ---------*---------")
        print(f"Precisão: ", end="")
        print(precision_score(test_label, test_pred))
        print(f"Erro (mean_absolute_error): ", end="")
        print(mean_absolute_error(test_label, test_pred))
        print(f"Matriz de confusão: ")
        print(confusion_matrix(test_label, test_pred))

        if generate_roc_curve is True:
            plot_roc_curve(clf, test_features_norm, test_label)
            plt.show()


def generate_models():
    """
    Função principal para gerar os modelos e executá-los

    Referência:
    https://github.com/fabriciojoc/ml-cybersecuritiy-course/
    https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.RandomForestClassifier.html#sklearn.ensemble.RandomForestClassifier
    https://scikit-learn.org/stable/modules/generated/sklearn.neighbors.KNeighborsClassifier.html#sklearn.neighbors.KNeighborsClassifier
    https://scikit-learn.org/stable/modules/generated/sklearn.svm.SVC.html#sklearn.svm.SVC
    """
    global df_data, label
    # Split dos dados
    train_data, test_data = split_data(df_data)
    train_label, test_label = split_data(label)

    # Obtem atributos numéricos
    train_features = train_data[numerical_attributes].values
    test_features = test_data[numerical_attributes].values

    # Faz o tratamento das características textuais e já faz a junção com os numéricos
    for a in textual_attributes:
        # TDF-IDF
        train_texts, test_texts = textual_feature_tfid(train_data[a].values, test_data[a].values)
        train_features = np.concatenate((train_features, train_texts.toarray()), axis=1)
        test_features = np.concatenate((test_features, test_texts.toarray()), axis=1)
        # Word2Vec
        train_texts, test_texts = textual_feature_word2vec(train_data[a].values, test_data[a].values)
        train_features = np.concatenate((train_features, train_texts), axis=1)
        test_features = np.concatenate((test_features, test_texts), axis=1)

    # Faz a normalização
    scaler_param = MinMaxScaler()
    scaler_param.fit(train_features)
    train_features_norm = scaler_param.transform(train_features)
    test_features_norm = scaler_param.transform(test_features)
    cv = 5

    # ****************************** RandomForestClassifier
    execute_model(RandomForestClassifier(n_estimators=100), train_features_norm, train_label,
                  test_features_norm, test_label, model_name="RandomForestClassifier")
    execute_kfold(RandomForestClassifier(n_estimators=100), train_features_norm, train_label, cv,
                  model_name="RandomForestClassifier-KFold")

    # ****************************** "KNeighborsClassifier
    execute_model(KNeighborsClassifier(n_neighbors=5), train_features_norm, train_label, test_features_norm, test_label,
                  model_name="KNeighborsClassifier")
    execute_kfold(KNeighborsClassifier(n_neighbors=5), train_features_norm, train_label, cv,
                  model_name="KNeighborsClassifier-KFold")

    # ****************************** SVM
    execute_model(SVC(kernel="linear"), train_features_norm, train_label, test_features_norm, test_label,
                  model_name="SVM")
    execute_kfold(SVC(kernel="linear"), train_features_norm, train_label, cv,
                  model_name="SVM-KFold")


if __name__ == "__main__":
    start = time.time()

    if len(sys.argv) >= 2:
        if "-roc=false" in sys.argv:
            generate_roc_curve = False
            print("Geração dos gráficos de curva ROC desabilitado")

    generate_models()
    end = time.time()
    print(f"\nRuntime of the program is {end - start}s")
    sys.exit(0)
