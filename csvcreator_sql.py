import csv
import os

"""
Class used to create SQL from CVE files
These SQL will be used to insert data to SQLite database or any other relational database
"""


class CsvCreatorSQL:

    def __init__(self, file_name_path, table_name):
        self.file_name_path = file_name_path
        self.table_name = table_name
        self.n_columns = 0
        self.sql_create_table = ""
        self.sql_insert_table = []

    def read_csv(self):
        try:
            if os.path.exists(self.file_name_path):
                print(f"Arquivo \"{self.file_name_path}\" encontrado, iniciando importação CSV")

                with open(self.file_name_path, encoding="UTF-8") as pointer_file:
                    arq_in = csv.reader(pointer_file, delimiter=",")
                    first_line = True
                    for line in arq_in:
                        if first_line is True:
                            first_line = False
                            self.__sql_create_table(line)
                        else:
                            self.__sql_create_insert(line)
            else:
                print(f"Arquivo \"{self.file_name_path}\" não encontrado. Processo finalizado")
        except:
            print("Exceção gerada na leitura do arquivo. Processo finalizado")
            print(sys.exc_info())

    def __sql_create_table(self, name_columns):
        try:
            string = "CREATE TABLE \"" + self.table_name + "\" ("
            column_n = 1
            for line in name_columns:
                self.n_columns += 1
                if line == "":
                    string += "\"col" + str(column_n) + "\" text, "
                    column_n += 1
                else:
                    string += "\"" + line + "\" text, "
            self.sql_create_table = string[:-2] + ");"
        except UnicodeDecodeError as UniExp:
            print(UniExp)

    def __sql_create_insert(self, columns):
        try:
            tmp = 0
            list_data = []

            if self.__check_line_pattern(columns):
                for c in columns:
                    list_data.append(c)
                    tmp += 1

                for i in range(tmp, self.n_columns):
                    list_data.append("")

                self.sql_insert_table.append(list_data)
        except UnicodeDecodeError as UniExp:
            print(f"erro ao processar a coluna {columns[0]} " + UniExp)

    def __check_line_pattern(self, columns):
        is_ok = False

        # Primeira coluna deve iniciar com CVE...
        if columns[0].startswith("CVE") is True:
            is_ok = True
        else:
            is_ok = False

        # Devem existir n coluns
        if len(columns) == self.n_columns:
            is_ok = True
        else:
            is_ok = False

        return is_ok
