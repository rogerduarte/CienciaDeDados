import os
import time
import sqlite3
from sqlite3 import Error
from csvcreator_sql import CsvCreatorSQL


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
