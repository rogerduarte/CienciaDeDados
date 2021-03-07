import pandas as pd
import json
from dateutil import parser

# Lista de colunas selecionadas na pré-análise do dataset
list_columns = [ "id", "Modified", "Published", "access", "cvss", "cvss-time", "impact"]
# Váriavel contendo a lista de JSON
data_list = []
# Número máximo de linhas que serão lidas. Geralmente utilizado para debug
max_lines_debug = 60500
# Caminho do arquivo dataset
file_name_dataset = "circl-cve-search-expanded.json"


def read_dataset_to_list(debug=False, max_line=max_lines_debug):
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
            # Variável de controle
            use_line = True
            for d in list_columns:
                # impact, access são tratados de forma diferente, pois são dict()
                if d != "impact" and d != "access":
                    if d in tmp.keys():
                        # Realiza um ajuste na data, com parser, em campos com datas
                        if d == "Published" or d == "Modified" or d == "cvss-time":
                            tmp_dict[d] = parser.parse(tmp[d])
                        else:
                            tmp_dict[d] = tmp[d]
                    else:
                        tmp_dict[d] = None
                # Faz o tratamento do dicionário impact
                elif d == "impact":
                    if d in tmp.keys():
                        tmp_dict["impact_availability"] = tmp[d]["availability"] if "availability" in tmp[d] else None
                        tmp_dict["impact_confidentiality"] = tmp[d]["confidentiality"] if "confidentiality" in tmp[d] else None
                        tmp_dict["impact_integrity"] = tmp[d]["integrity"] if "integrity" in tmp[d] else None
                    else:
                        tmp_dict["impact_availability"] = None
                        tmp_dict["impact_confidentiality"] = None
                        tmp_dict["impact_integrity"] = None
                # Faz o tratamento do dicionário acccess
                elif d == "access":
                    if d in tmp.keys():
                        tmp_dict["access_authentication"] = tmp[d]["authentication"] if "authentication" in tmp[d] else None
                        tmp_dict["access_complexity"] = tmp[d]["complexity"] if "complexity" in tmp[d] else None
                        tmp_dict["access_vector"] = tmp[d]["vector"] if "vector" in tmp[d] else None
                    else:
                        tmp_dict["access_authentication"] = None
                        tmp_dict["access_complexity"] = None
                        tmp_dict["access_vector"] = None

            # Adiciona a linha lida na lista
            if use_line is True:
                data_list.append(tmp_dict)
            # Utilizado para debug. Cancela o loop conforme condição abaixo
            # Evita que em todo debug seja necessário ler todo o dataset
            if debug is True and control == max_line-1:
                break
            if use_line is True:
                control += 1
            line = json_file.readline()


# Leitura do dataset. Os dados serão salvos na variável global data_list
read_dataset_to_list()
# Criação do dataframe utilizando a informação lida do dataset
df_cve = pd.DataFrame(data_list)

# Número de registros para um dos parâmetros
print(df_cve.count(), end="\n\n")

# Distribuição CVSS (score)
print(df_cve.fillna('Vazio').groupby('cvss').size().sort_values(ascending=False).head(), end="\n\n")

# Distribuição pelo impact
print(df_cve.fillna('Vazio').groupby('impact_availability').size().sort_values(ascending=False).head(), end="\n")
print(df_cve.fillna('Vazio').groupby('impact_confidentiality').size().sort_values(ascending=False).head(), end="\n")
print(df_cve.fillna('Vazio').groupby('impact_integrity').size().sort_values(ascending=False).head(), end="\n\n")

# Distribuição pelo access
print(df_cve.fillna('Vazio').groupby('access_authentication').size().sort_values(ascending=False).head(), end="\n")
print(df_cve.fillna('Vazio').groupby('access_complexity').size().sort_values(ascending=False).head(), end="\n")
print(df_cve.fillna('Vazio').groupby('access_vector').size().sort_values(ascending=False).head(), end="\n\n")

# Distribuição por data
print(df_cve.fillna('Vazio').groupby(df_cve['Published'].dt.year).size().sort_values(ascending=False).head(),
      end="\n\n")
