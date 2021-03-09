"""
Trabalho final - Ciência de Dados para Segurança (CI1030) - Trabalho Final
Alunos:
    Michael A Hempkemeyer (PPGINF-202000131795)
    Roger R R Duarte (PPGINF-202000131793)

Esse script faz o pré-processamento do dataset de CVEs (arquivo JSON).
Como resultado, gera dois CSVs, um com 80% dos dados e outro com 20% dos dados.
"""
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
        # self.list_columns = ["id", "Modified", "Published", "access", "cvss", "cvss-time", "impact",
        #                "summary", "references", "vulnerable_configuration_cpe_2_2"]
        # self.list_columns = ["id", "summary", "Published", "access", "impact", "cvss"]
        self.list_columns = ["cvss", "cwe", "access", "impact", "summary", "vulnerable_configuration_cpe_2_2"]
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
        # Variável para controle do campo access
        self.control_access = {
            "vector": {
                "ADJACENT_NETWORK": 1,
                "LOCAL": 2,
                "NETWORK": 3
            },
            "complexity": {
                "HIGH": 5,
                "LOW": 6,
                "MEDIUM": 7
            },
            "authentication": {
                "MULTIPLE_INSTANCES": 9,
                "NONE": 10,
                "SINGLE_INSTANCE": 11
            },
            "NotAvailable": 12
        }

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
                            if d == "Published":
                                tmp_dict[d] = parser.parse(tmp[d])
                            elif d == "cvss":
                                # Não inclui no dataset pre-processado itens com cvss zerados
                                if tmp[d] is None:
                                    use_line = False
                                    break
                                else:
                                    tmp_dict[d] = tmp[d]
                            elif d == "summary":
                                # Em determinados casos, existe a marcação de "REJECT" no summary.
                                # Tais CVEs que contêm o REJECT no summary serão eliminados
                                # Ex.: ** REJECT **  DO NOT USE THIS CANDIDATE NUMBER.  ConsultIDs: none.  Reason: This ...
                                if ("** REJECT **" in tmp[d].upper() or
                                        "DO NOT USE THIS CANDIDATE NUMBER" in tmp[d].upper()):
                                    use_line = False
                                    break
                                # Para teste, será incluído
                                tmp_dict[d] = tmp[d].replace("\"", "'")
                            elif d == "vulnerable_configuration_cpe_2_2":
                                if type(tmp[d]) is list and len(tmp[d]) > 0:
                                    tmp_vc = ""
                                    for i in tmp[d]:
                                        tmp_vc = tmp_vc+";"+i
                                    tmp_dict[d] = tmp_vc
                                else:
                                    tmp_dict[d] = "NotAvailable"
                            elif tmp[d] is None:
                                tmp_dict[d] = "NotAvailable"
                            else:
                                tmp_dict[d] = tmp[d]
                        else:
                            tmp_dict[d] = "NotAvailable"
                    # Faz o tratamento do dicionário impact
                    elif d == "impact":
                        if ((d in tmp.keys()) and
                                (tmp[d]["availability"] == "PARTIAL" or tmp[d]["availability"] == "COMPLETE") and
                                (tmp[d]["confidentiality"] == "PARTIAL" or tmp[d]["confidentiality"] == "COMPLETE") and
                                (tmp[d]["integrity"] == "PARTIAL" or tmp[d]["integrity"] == "COMPLETE")):
                            tmp_dict["impact"] = 1
                        else:
                            tmp_dict["impact"] = 0
                        ''' 
                        if d in tmp.keys():
                            tmp_dict["impact_availability"] = tmp[d]["availability"] if "availability" in tmp[d] else "NotAvailable"
                            tmp_dict["impact_confidentiality"] = tmp[d]["confidentiality"] if "confidentiality" in tmp[d] else "NotAvailable"
                            tmp_dict["impact_integrity"] = tmp[d]["integrity"] if "integrity" in tmp[d] else "NotAvailable"
                        else:
                            tmp_dict["impact_availability"] = "NotAvailable"
                            tmp_dict["impact_confidentiality"] = "NotAvailable"
                            tmp_dict["impact_integrity"] = "NotAvailable"
                        '''
                    # Faz o tratamento do dicionário acccess
                    elif d == "access":
                        if d in tmp.keys():
                            # Faz a categorização do access conforme variável self.access_control
                            tmp_dict["access"] = self.control_access["vector"][tmp[d]["vector"]]
                            tmp_dict["access"] += self.control_access["authentication"][tmp[d]["authentication"]]
                            tmp_dict["access"] += self.control_access["complexity"][tmp[d]["complexity"]]

                            '''
                            tmp_dict["access_authentication"] = tmp[d]["authentication"] if "authentication" in tmp[d] else "NotAvailable"
                            tmp_dict["access_complexity"] = tmp[d]["complexity"] if "complexity" in tmp[d] else "NotAvailable"
                            tmp_dict["access_vector"] = tmp[d]["vector"] if "vector" in tmp[d] else "NotAvailable"
                            '''
                        else:
                            tmp_dict["access"] = self.control_access["NotAvailable"]

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


if __name__ == "__main__":
    pre_process = PreProcessDataSet()

    print("Leitura e pré-processamento do dataset ...")
    pre_process.read_dataset_to_list(True, 50000)
    print("Particionamento dos dados em 80% e 20% ...")
    pre_process.partition_80_20()
    print("Gravação dos datasets pré-processados em disco ...")
    pre_process.generate_csv_80_20()
    print("Finalizado!")
