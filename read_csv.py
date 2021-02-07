import csv
import os
import sys
import time
import sqlite3
from sqlite3 import Error


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


def process_sql(db_file, csv_class):
    conn = None
    sql = "INSERT INTO \""+csv_class.table_name+"\" VALUES ("
    for i in range(csv_class.n_columns):
        sql += "?,"
    sql = sql[:-1]+")"

    try:
        conn = sqlite3.connect(db_file)
        c = conn.cursor()
        c.execute(csv_class.sql_create_table)
        conn.commit()

        c.executemany(sql, csv_class.sql_insert_table)
        conn.commit()
    except Error as e:
        print(e)
    finally:
        if conn:
            conn.close()


if __name__ == "__main__":
    database_name = "work-"+str(time.time())+".db"
    """ 
    Read CVE Files
    """
    start = time.monotonic()
    csv_files = ["dataset/cve.csv", "dataset/products.csv", "dataset/vendor_product.csv", "dataset/vendors.csv"]
    csv_classes = []
    for csv_file in csv_files:
        tmp = CsvCreatorSQL(csv_file, os.path.basename(csv_file)[0:-4])
        tmp.read_csv()
        csv_classes.append(tmp)
    print("time spent to read CSVs: " + str(time.monotonic() - start) + "s")

    """ 
    Insert on SQLite
    """
    start = time.monotonic()
    for tmp in csv_classes:
        process_sql(database_name, tmp)

    print("time spent insert sqlite: " + str(time.monotonic() - start) + "s")
