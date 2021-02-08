import csv
import os
import sys
import time
from pymongo import MongoClient

"""
Class used to JSON from CSV file
This will be used to insert data on MongoDB Database
"""


class CsvCreatorJSON:
    dbname = "cve"
    url = "mongodb://192.168.0.19:27017/"

    def __init__(self, file_name_path, collection_name):
        self.file_name_path = file_name_path
        self.collection_name = collection_name
        self.n_columns = 0
        self.json = ""

    def read_csv(self):
        try:
            if os.path.exists(self.file_name_path):
                print(f"Arquivo \"{self.file_name_path}\" encontrado, iniciando importação CSV")

                with open(self.file_name_path, encoding="UTF-8") as pointer_file:
                    arq_in = csv.reader(pointer_file, delimiter=",")
                    # first line contains the name of the columns
                    first_line = next(arq_in)
                    # set the number of columns
                    self.n_columns = len(first_line)
                    # check all elements of the first line and change the name if it was empty (to col1, cols2..)
                    for idx, value in enumerate(first_line):
                        if value == "":
                            first_line[idx] = "col" + str(idx)

                    # iterate the following lines
                    # this will create json statements and insert it in a list.. all in memory
                    list_json = []
                    for line in arq_in:
                        d = {}
                        for idx, col in enumerate(line):
                            d[first_line[idx]] = col

                        list_json.append(d)

                    # insert all on mongodb
                    self.__insert_mongodb(list_json)
            else:
                print(f"Arquivo \"{self.file_name_path}\" não encontrado. Processo finalizado")
        except:
            print("Exceção gerada na leitura do arquivo. Processo finalizado")
            print(sys.exc_info())

    def __insert_mongodb(self, list_json):
        start = time.monotonic()
        print("MongoDB starting")
        client = MongoClient(self.url)
        # Select a database called CVE
        db = client.cve
        # Select a collection name CVEs
        col = db.cves

        result = col.insert_many(list_json)
        print(f"time spent on insert_many mongodb: " + str(time.monotonic() - start) + f"s. {len(result.inserted_ids)} "
                                                                                       f"documentos inseridos ")


