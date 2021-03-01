import pandas as pd
import json
from dateutil import parser

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
                # Realiza um ajuste na data. Gasto de CPU alto neste ponto
                if (d == "Published" or d == "Modified") and tmp_dict[d] is not None:
                    tmp_dict[d] = parser.parse(tmp_dict[d])

            data_list.append(tmp_dict)
            # Utilizado para debug. Cancela o loop conforme condição abaixo
            if debug is True and control > max_lines_debug:
                break
            control += 1
            line = json_file.readline()


# Leitura do dataset. Os dados serão salvos na variável global file_name_dataset
read_json_file(False)
# Criação do dataframe utilizando a informação lida do dataset
df_cve = pd.DataFrame(data_list)

# Número de registros para um dos parâmetros
print(df_cve.count())
print()

# Distribuição CVSS (score)
print(df_cve.fillna('Vazio').groupby('cvss').size().sort_values(ascending=False).head())
print()

# Distribuição por data de publicação
print(df_cve.groupby(pd.Grouper(key='Published', freq='Y')).size().sort_values(ascending=False))
print()
