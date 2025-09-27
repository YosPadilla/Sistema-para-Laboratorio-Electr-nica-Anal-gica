# db_test.py
import oracledb

USER = "PROYECTOREPO"
PASS = "proyecto123"
DSN  = "localhost:1521/XEPDB1"

con = oracledb.connect(user=USER, password=PASS, dsn=DSN)
cur = con.cursor()
cur.execute("select usuario, tipo from usuarios order by id")
print(cur.fetchall())  # Esperado: [('admin', 0), ('aux', 1)]
cur.close()
con.close()
print("OK: Conexión y query correctas.")