import os
import sys

import pandas as pd
import json
from dateutil import parser

# Lista de colunas selecionadas na pré-análise do dataset
list_columns = ["cvss", "cwe", "access", "impact", "summary", "vulnerable_configuration_cpe_2_2"]

# Caminho dos DataSets
data_path = os.path.join("dataset", "data-list-complete.csv")

# Verifica se os arquivos de dataset pré-processados existem
if os.path.isfile(data_path) is False:
    print(f"Arquivo \"{data_path}\" não encontrado")
    print("Execute primeiramente o pré-processamento com o script \"PreProcessamento.py\"")
    sys.exit(-1)

# Leitura do dataset. Os dados serão salvos na variável global data_list
df_cve = pd.read_csv(data_path)

# Número de registros para um dos parâmetros
print(df_cve.count(), end="\n\n")

# Distribuição CVSS (score)
print(df_cve.fillna('Vazio').groupby('cvss').size().sort_values(ascending=False).head(), end="\n\n")

# Distribuição pelo impact
print(df_cve.fillna('Vazio').groupby('impact').size().sort_values(ascending=False).head(), end="\n")
