# Teste em funções do pandas no dataset escolhido
# dataset: https://www.kaggle.com/vsathiamoo/cve-common-vulnerabilities-and-exposures/version/1
import sys

import pandas as pd
import json

# Lista de colunas selecionadas na pré-análise do dataset
list_columns = ["Modified", "Published", "access", "cvss", "cvss-time", "impact", "references",
                "summary", "vulnerable_configuration_cpe_2_2", "id"]
# Váriavel contendo a lista de JSON
data_list = []
# Número máximo de linhas que serão lidas. Geralmente utilizado para debug
max_lines_debug = 60500
# Caminho do arquivo dataset
file_name_dataset = "circl-cve-search-expanded.json"


def read_json_file(debug=False):
    global data_list, file_name_dataset

    # Leitura do dataset
    with open(file_name_dataset, encoding="UTF-8") as json_file:
        line = json_file.readline()
        control = 0
        while line:
            # Faz a leitura do JSON
            tmp = json.loads(line)
            # Cria um novo dicionário contendo apenas as colunas da lista list_columns
            tmp_dict = dict()
            for d in list_columns:
                tmp_dict[d] = tmp[d] if d in tmp.keys() else None

            data_list.append(tmp_dict)
            # Utilizado para debug. Cancela o loop conforme condição abaixo
            if debug is True and control > max_lines_debug:
                break
            control += 1
            line = json_file.readline()


# Leitura do dataset. Os dados serão salvos na variável global file_name_dataset
read_json_file(True)
# Criação do dataframe utilizando a informação lida do dataset
df_cve = pd.DataFrame(data_list)

# Group by CVSS (score)
print(df_cve.groupby('cvss').size().sort_values(ascending=False).head())
# Lista os CVEs com score "10.0"
df_sub = df_cve.loc[df_cve["cvss"] == 10.0]
print(df_sub[['id', 'access']].to_numpy())



# print("\n======> Group by pelo produto")
# print(df_j.groupby('vulnerable_product').size().sort_values(ascending=False).head())

# print("\n======> Lista apenas algunas colunas")
# print(df_j.loc[:, ['vendor', 'vulnerable_product', 'access_complexity']])
# oOu ..
# print(df_j.reindex(columns=['vendor', 'vulnerable_product', 'access_complexity']))


# group by Vendor em que access_complexity == "HIGH"
# print(df_j.loc[df_j['access_complexity'] == 'HIGH'])
# Group by por vulnerable_product cujo access_complexity é 'HIGH'
# print(df_j.loc[df_j['access_complexity'] == 'HIGH'].groupby('vulnerable_product').size().sort_values(ascending=False).head())
