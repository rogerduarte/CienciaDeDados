import pandas as pd
import json
from dateutil import parser
import math
import csv

## Pré-processamento

# Lista de colunas selecionadas na pré-análise do dataset
list_columns = ["id", "Modified", "Published", "access", "cvss", "cvss-time", "impact",
                "summary", "references", "vulnerable_configuration_cpe_2_2"]
# Váriavel contendo as listas JSON
data_list = []
data_list_80 = []
data_list_20 = []
# Número máximo de linhas que serão lidas. Geralmente utilizado para debug
max_lines_debug = 60500
# Caminho do arquivo dataset
file_name_dataset = "../Exploração de Dados/circl-cve-search-expanded.json"
# Arquivo de saida do pré-processamento
output_file_name_80 = "data-list-80.csv"
output_file_name_20 = "data-list-20.csv"


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
                        elif d == "summary":
                            # Em determinados casos, existe a marcação de "REJECT" no summary.
                            # Tais CVEs que contêm o REJECT no summary serão eliminados
                            # Ex.: ** REJECT **  DO NOT USE THIS CANDIDATE NUMBER.  ConsultIDs: none.  Reason: This ...
                            if "** REJECT **  DO NOT USE THIS CANDIDATE NUMBER" in tmp[d].upper():
                                use_line = False
                                break
                            # Faz a substituição de uma aspas duplas por simples
                            # Evita problemas na leitura do CSV pelo Weka
                            tmp_dict[d] = tmp[d].replace("\"", "'")
                        elif d == "references":
                            # Inclui aspas caso necessário
                            # Verifica se é uma lista e o tamanho da lista
                            # Se for uma lista vazia, deixa como None
                            if type(tmp[d]) is list and len(tmp[d]) > 0:
                                tmp_dict[d] = tmp[d]
                            else:
                                tmp_dict[d] = None
                        elif d == "vulnerable_configuration_cpe_2_2":
                            # vulnerable_configuration_cpe_2_2 também é uma lista
                            # Deixa None se vazia
                            if type(tmp[d]) is list and len(tmp[d]) > 0:
                                tmp_dict[d] = tmp[d]
                            else:
                                tmp_dict[d] = None
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


# Particiona a variável data_list em 80x20
def partition_80_20():
    global data_list, data_list_80, data_list_20

    size_80 = math.floor((len(data_list) * 80) / 100)
    max_loop = len(data_list)

    for i in range(len(data_list)):
        if i < size_80:
            data_list_80.append(data_list[i])
        else:
            data_list_20.append(data_list[i])


# Leitura do dataset. Os dados serão salvos na variável global data_list
# read_dataset_to_list(True, 10) # modo debug
read_dataset_to_list()
# Particiona os dados em dois vetores, 80x20
partition_80_20()

# Cria os dataframes
df_80 = pd.DataFrame(data_list_80)
df_20 = pd.DataFrame(data_list_20)

# Grava em formato .csv
# Dois arquivos serão gerados: data-list-20.csv | data-list-80.csv
# Obs.: quoting=csv.QUOTE_ALL - evita problemas na leitura do CSV no Weka
df_80.fillna("").to_csv(output_file_name_80, index=False, header=True, quoting=csv.QUOTE_ALL)
df_20.fillna("").to_csv(output_file_name_20, index=False, header=True, quoting=csv.QUOTE_ALL)


# Exemplo de resultado:
# De 2,25GB do arquivo JSON, foram gerados dois .CSV, um com 15MB e outro com 160MB
# 06/03/2021  23:21        15.551.907 data-list-20.csv
# 06/03/2021  23:20       160.093.295 data-list-80.csv


# O CSV gerado foi lido corretamente pelo Weka
