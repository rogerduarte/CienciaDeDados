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
from joblib import dump, load
import shutil

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
df_data_20 = pd.read_csv(data_path_20)

# Valor do label, que será utilizado para classificação
label = df_data[label_attribute].values
label_20 = df_data_20[label_attribute].values

# Apaga o label do dataset
del df_data[label_attribute]
del df_data_20[label_attribute]

# Variável para controle da geração das janelas de gráficos das curvas ROC
# Documentação base: https://scikit-learn.org/stable/auto_examples/miscellaneous/plot_roc_curve_visualization_api.html
generate_roc_curve = True

# Variáveis utilizadas para indicar o caminho onde os modelos treinados serão salvos
# (para serem utilizados posteriormente sem treinar)

output_model_folder = "ModelosSalvos"
output_model_recreate_folder = False
if os.path.isdir(output_model_folder) is False:
    print(f"Criando pasta \"{output_model_folder}\" ...")
    os.mkdir(output_model_folder)
else:
    if output_model_recreate_folder is True:
        print(f"Recriando pasta \"{output_model_folder}\" ...")
        shutil.rmtree(output_model_folder)
        os.mkdir(output_model_folder)
output_model_word2vec = os.path.join(output_model_folder, "vectorizer-tfidf.model")
output_model_tdidf = os.path.join(output_model_folder, "vectorizer-w2vec.model")
output_model_split = {"RandomForestClassifier": os.path.join(output_model_folder, "RandomForestClassifier_model_split.model"),
                      "KNeighborsClassifier": os.path.join(output_model_folder, "KNeighborsClassifier_model_split.model"),
                      "SVM": os.path.join(output_model_folder, "SVM_model_model_split.model")}
output_model_kfold = {"RandomForestClassifier-KFold":
                          [os.path.join(output_model_folder, "RandomForestClassifier_model_kfold1.model"),
                           os.path.join(output_model_folder, "RandomForestClassifier_model_kfold2.model"),
                           os.path.join(output_model_folder, "RandomForestClassifier_model_kfold3.model"),
                           os.path.join(output_model_folder, "RandomForestClassifier_model_kfold4.model"),
                           os.path.join(output_model_folder, "RandomForestClassifier_model_kfold5.model")],
                      "KNeighborsClassifier-KFold": [os.path.join("ModelosSalvos", "KNeighborsClassifier_model_kfold1.model"),
                                               os.path.join("ModelosSalvos", "KNeighborsClassifier_model_kfold2.model"),
                                               os.path.join("ModelosSalvos", "KNeighborsClassifier_model_kfold3.model"),
                                               os.path.join("ModelosSalvos", "KNeighborsClassifier_model_kfold4.model"),
                                               os.path.join("ModelosSalvos", "KNeighborsClassifier_model_kfold5.model")],
                      "SVM-KFold": [os.path.join(output_model_folder, "SVM_model_kfold1.model"),
                              os.path.join(output_model_folder, "SVM_model_kfold2.model"),
                              os.path.join(output_model_folder, "SVM_model_kfold3.model"),
                              os.path.join(output_model_folder, "SVM_model_kfold4.model"),
                              os.path.join(output_model_folder, "SVM_model_kfold5.model")]}


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


def textual_feature_tfid(train_data_param, test_data_param=None):
    """
    Função utilizada para o processamento do Tf-idf
    :param train_data_param: dataset de treino
    :param test_data_param: dataset de test
    :return: dois dataset processados pelo tf-idf
    """
    extractor = None
    if os.path.exists(output_model_tdidf) is True:
        extractor = load(output_model_tdidf)
    else:
        extractor = TfidfVectorizer(max_features=100)
        extractor.fit(train_data_param)
        dump(extractor, output_model_tdidf)

    train_features_o = extractor.transform(train_data_param)
    if test_data_param is not None:
        test_features_o = extractor.transform(test_data_param)
    else:
        test_features_o = None
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


def textual_feature_word2vec(train_data_param, test_data_param=None):
    """
    Função utilizada para o processamento do Word2Vec
    :param train_data_param: dataset de treino
    :param test_data_param: dataset de test
    :return: dois dataset processados pelo Word2Vec
    """
    word2vec = None
    if os.path.exists(output_model_word2vec):
        word2vec = load(output_model_word2vec)
    else:
        word2vec = MeanEmbeddingVectorizer(size=200)
        word2vec.fit(train_data_param)
        dump(word2vec, output_model_word2vec)

    train_features_o = word2vec.transform(train_data_param)
    if test_data_param is not None:
        test_features_o = word2vec.transform(test_data_param)
    else:
        test_features_o = None
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
    idx = 0

    print(f"---------*--------- Kfold ({model_name}) ---------*---------")
    for train_index, test_index in kf.split(X, Y):
        X_train, X_test = X[train_index], X[test_index]
        Y_train, Y_test = Y[train_index], Y[test_index]
        clf = model
        clf.fit(X_train, Y_train)
        dump(clf, output_model_kfold[model_name][idx])
        idx += 1
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


def execute_kfold_production(test_features_norm, test_label, cv, model_name=""):
    """
    Execução k-fold cross validation de um modelo já treinado
    """
    global generate_roc_curve

    count = 1
    ax = plt.gca()

    print(f"---------*--------- Kfold ({model_name})-Production ---------*---------")
    for i in range(cv):
        # Carrega o modelo treinado
        clf = load(output_model_kfold[model_name][i])
        pred_t = clf.predict(test_features_norm)

        print(f"Precisão: ", end="")
        print(precision_score(test_label, pred_t))
        print(f"Erro (mean_absolute_error): ", end="")
        print(mean_absolute_error(test_label, pred_t))
        print(f"Matriz de confusão: ")
        print(confusion_matrix(test_label, pred_t))

        if generate_roc_curve is True:
            plot_roc_curve(clf, test_features_norm, test_label, ax=ax, label=f"{model_name}-{count}")
            count += 1

    if generate_roc_curve is True:
        plt.show()


def execute_model(model, train_features_norm, train_label, test_features_norm, test_label, model_name=""):
    global generate_roc_curve
    """
    Executa um modelo conforme parâmetros
    """
    if model_name == "RandomForestClassifier" or model_name == "KNeighborsClassifier" or model_name == "SVM":
        print(f"---------*--------- Split percentage ({model_name}) ---------*---------")
        clf = model
        clf.fit(train_features_norm, train_label)
        # Salvo o modelo treinado
        dump(clf, output_model_split[model_name])
        # Predição
        test_pred = clf.predict(test_features_norm)
        print(f"Precisão: ", end="")
        print(precision_score(test_label, test_pred))
        print(f"Erro (mean_absolute_error): ", end="")
        print(mean_absolute_error(test_label, test_pred))
        print(f"Matriz de confusão: ")
        print(confusion_matrix(test_label, test_pred))

        if generate_roc_curve is True:
            plot_roc_curve(clf, test_features_norm, test_label)
            plt.show()


def execute_model_production(test_features_norm, test_label, model_name=""):
    global generate_roc_curve
    """
    Executa um modelo conforme parâmetros
    """
    if model_name == "RandomForestClassifier" or model_name == "KNeighborsClassifier" or model_name == "SVM":
        print(f"---------*--------- Split percentage ({model_name})-Production---------*---------")
        # Carrega o modelo salvo em disco
        clf = load(output_model_split[model_name])
        # Predição
        test_pred = clf.predict(test_features_norm)
        print(f"Precisão: ", end="")
        print(precision_score(test_label, test_pred))
        print(f"Erro (mean_absolute_error): ", end="")
        print(mean_absolute_error(test_label, test_pred))
        print(f"Matriz de confusão: ")
        print(confusion_matrix(test_label, test_pred))

        if generate_roc_curve is True:
            plot_roc_curve(clf, test_features_norm, test_label)
            plt.show()


def generate_models(random_florest=False, k_neighbors=False, svm=False):
    """
    Função principal para gerar os modelos e executá-los

    Referência:
    https://github.com/fabriciojoc/ml-cybersecuritiy-course/
    https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.RandomForestClassifier.html#sklearn.ensemble.RandomForestClassifier
    https://scikit-learn.org/stable/modules/generated/sklearn.neighbors.KNeighborsClassifier.html#sklearn.neighbors.KNeighborsClassifier
    https://scikit-learn.org/stable/modules/generated/sklearn.svm.SVC.html#sklearn.svm.SVC
    """
    global df_data, label

    # Finaliza a função se nenhum algortimo foi selecionado
    if random_florest is False and k_neighbors is False and svm is False:
        return

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
    if random_florest is True:
        execute_model(RandomForestClassifier(n_estimators=100), train_features_norm, train_label,
                      test_features_norm, test_label, model_name="RandomForestClassifier")
        execute_kfold(RandomForestClassifier(n_estimators=100), train_features_norm, train_label, cv,
                      model_name="RandomForestClassifier-KFold")

    # ****************************** "KNeighborsClassifier
    if k_neighbors is True:
        execute_model(KNeighborsClassifier(n_neighbors=5), train_features_norm, train_label, test_features_norm, test_label,
                      model_name="KNeighborsClassifier")
        execute_kfold(KNeighborsClassifier(n_neighbors=5), train_features_norm, train_label, cv,
                      model_name="KNeighborsClassifier-KFold")

    # ****************************** SVM
    if svm is True:
        execute_model(SVC(kernel="linear"), train_features_norm, train_label, test_features_norm, test_label,
                      model_name="SVM")
        execute_kfold(SVC(kernel="linear"), train_features_norm, train_label, cv,
                      model_name="SVM-KFold")


def execute_models_production(random_florest=False, k_neighbors=False, svm=False):
    """
    Função principal para executar os modelos já salvos
    """
    global df_data_20, label_20

    # Finaliza a função se nenhum algortimo foi selecionado
    if random_florest is False and k_neighbors is False and svm is False:
        return

    # Split dos dados
    test_data = df_data_20
    test_label = label_20

    # Obtem atributos numéricos
    test_features = test_data[numerical_attributes].values

    # Faz o tratamento das características textuais e já faz a junção com os numéricos
    for a in textual_attributes:
        # TDF-IDF
        test_texts, _ = textual_feature_tfid(test_data[a].values, None)
        test_features = np.concatenate((test_features, test_texts.toarray()), axis=1)
        # Word2Vec
        test_texts, _ = textual_feature_word2vec(test_data[a].values, None)
        test_features = np.concatenate((test_features, test_texts), axis=1)

    # Faz a normalização
    scaler_param = MinMaxScaler()
    scaler_param.fit(test_features)
    test_features_norm = scaler_param.transform(test_features)
    cv = 5

    # ****************************** RandomForestClassifier
    if random_florest is True:
        execute_model_production(test_features_norm, test_label, model_name="RandomForestClassifier")
        execute_kfold_production(test_features_norm, test_label, 5, model_name="RandomForestClassifier-KFold")

    # ****************************** "KNeighborsClassifier
    if k_neighbors is True:
        execute_model_production(test_features_norm, test_label, model_name="KNeighborsClassifier")
        execute_kfold_production(test_features_norm, test_label, 5, model_name="KNeighborsClassifier-KFold")

    # ****************************** "SVM
    if svm is True:
        execute_model_production(test_features_norm, test_label, model_name="SVM")
        execute_kfold_production(test_features_norm, test_label, 5, model_name="SVM-KFold")


if __name__ == "__main__":
    start = time.time()

    if len(sys.argv) >= 2:
        if "-roc=false" in sys.argv:
            generate_roc_curve = False
            print("Geração dos gráficos de curva ROC desabilitado")

    # Treina os modelos
    generate_models(True, True, True)
    # Executa os modelos com base em treinos já realizados (salvos em disco).
    # Utiliza a porção dos 20%
    execute_models_production(True, True, True)

    end = time.time()
    print(f"\nRuntime of the program is {end - start}s")
    sys.exit(0)
