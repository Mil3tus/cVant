
import mysql.connector

conn = mysql.connector.connect(
    host="127.0.0.1",
    user="cvant",
    password="k6jg2210-30",
    database="cvant"
)

cursor = conn.cursor()

with open("2.txt", "r", encoding="utf-8") as arquivo:
    for linha in arquivo:
        dados = linha.strip().split("\t")

        if len(dados) != 2:
            continue

        mac_prefix, mac_vendor = dados

        sql = """
            INSERT INTO prefixes (mac_prefix, mac_vendor)
            VALUES (%s, %s)
        """

        cursor.execute(sql, (mac_prefix, mac_vendor))

conn.commit()

cursor.close()
conn.close()

print("Importação concluída!")
