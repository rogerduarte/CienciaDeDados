import pandas as pd
import json
from dateutil import parser
import math
import csv


class PreProcessDataSet:
    """
    Classe utilizada para o pré-processamento da datalist
    Atividades:
        - Seleciona as colunas corretas
        - Gera DataFrame (pandas)
        - Exporta os dados para CSV
    """

    def __init__(self):
        # Lista de colunas selecionadas na pré-análise do dataset
        self.list_columns = ["id", "Modified", "Published", "access", "cvss", "cvss-time", "impact",
                        "summary", "references", "vulnerable_configuration_cpe_2_2"]
        # Váriavel contendo as listas JSON
        self.data_list = []
        self.data_list_80 = []
        self.data_list_20 = []
        # Número máximo de linhas que serão lidas. Utilizado para debug
        self.max_lines_debug = 60500
        # Caminho do arquivo dataset
        self.file_name_dataset = "dataset/circl-cve-search-expanded.json"
        # Arquivo de saida do pré-processamento
        self.output_file_name_80 = "dataset/data-list-80.csv"
        self.output_file_name_20 = "dataset/data-list-20.csv"
        # DataFrames (pandas)
        self.df_20 = None
        self.df_80 = None

    def read_dataset_to_list(self, debug=False, max_line=None):
        """
        Faz a leitura do dataset JSON e o pré-processamento das variáveis
        :param debug:
        :param max_line:
        :return:
        """
        if max_line is None:
            max_line = self.max_lines_debug

        # Leitura do dataset
        with open(self.file_name_dataset, encoding="UTF-8") as json_file:
            line = json_file.readline()
            control = 0
            while line:
                # Faz a leitura do JSON
                tmp = json.loads(line)
                # Cria um novo dicionário contendo apenas as colunas da lista list_columns
                tmp_dict = dict()
                # Variável de controle
                use_line = True
                for d in self.list_columns:
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
                    self.data_list.append(tmp_dict)
                # Utilizado para debug. Cancela o loop conforme condição abaixo
                # Evita que em todo debug seja necessário ler todo o dataset
                if debug is True and control == max_line-1:
                    break
                if use_line is True:
                    control += 1
                line = json_file.readline()

    def partition_80_20(self):
        """
        Particiona o dataset em dois grupos, o primeiro com 80% dos dados e o segundo com 20%
        Com o resultado gera dois dataframes com os dados correspondentes
        """
        size_80 = math.floor((len(self.data_list) * 80) / 100)

        for i in range(len(self.data_list)):
            if i < size_80:
                self.data_list_80.append(self.data_list[i])
            else:
                self.data_list_20.append(self.data_list[i])

        self.df_80 = pd.DataFrame(self.data_list_80)
        self.df_20 = pd.DataFrame(self.data_list_20)

    def generate_csv_80_20(self, f_name_80=None, f_name_20=None):
        """
        Gera arquivos CSV com dataframes previamentes gerados
        :param f_name_80: opcional, nome do csv
        :param f_name_20: opcional, nome do csv
        :return: bool
        """
        if self.df_80 is None or self.df_20 is None:
            return False

        if f_name_80 is None:
            self.df_80.fillna("").to_csv(self.output_file_name_80, index=False, header=True, quoting=csv.QUOTE_ALL)
        else:
            self.df_80.fillna("").to_csv(f_name_80, index=False, header=True, quoting=csv.QUOTE_ALL)

        if f_name_20 is None:
            self.df_20.fillna("").to_csv(self.output_file_name_20, index=False, header=True, quoting=csv.QUOTE_ALL)
        else:
            self.df_20.fillna("").to_csv(f_name_20, index=False, header=True, quoting=csv.QUOTE_ALL)

        return True


# Utilizado para testar a classe
if __name__ == "__main__":
    pre_process = PreProcessDataSet()

    pre_process.read_dataset_to_list()
    pre_process.partition_80_20()
    pre_process.generate_csv_80_20()

    # Exemplo de resultado:
    # De 2,25GB do arquivo JSON, foram gerados dois .CSV, um com 15MB e outro com 160MB
    # 06/03/2021  23:21        15.551.907 data-list-20.csv
    # 06/03/2021  23:20       160.093.295 data-list-80.csv

