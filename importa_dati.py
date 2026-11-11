import math
from datetime import datetime
from dotenv import load_dotenv
load_dotenv()

from db import query
from dati import VENDITE

if query("SELECT COUNT(*) AS n FROM vendite", one=True)["n"] > 0:
    raise SystemExit("La tabella vendite non è vuota: importazione annullata.")

id_prodotti = {}
importate = 0
scartate = 0

for v in VENDITE:
    try:
        id_cliente = str(v["id_cliente"]).strip()
        nome = str(v["nome"]).strip()
        prodotto = str(v["prodotto"]).strip()
        prezzo = float(v["prezzo_vendita"])
        data = datetime.strptime(str(v["data_acquisto"]), "%Y-%m-%d").date()
        if not (id_cliente and nome and prodotto) or not math.isfinite(prezzo):
            raise ValueError("campo vuoto o non valido")
    except (KeyError, TypeError, ValueError):
        scartate += 1
        print("Scartata:", v)
        continue

    # Cliente: se esiste già non viene toccato
    query("INSERT IGNORE INTO clienti (id_cliente, nome) VALUES (%s, %s)",
          (id_cliente, nome), commit=True)

    # Prodotto: un solo record per nome
    if prodotto not in id_prodotti:
        riga = query("SELECT id FROM prodotti WHERE nome = %s", (prodotto,), one=True)
        if riga:
            id_prodotti[prodotto] = riga["id"]
        else:
            id_prodotti[prodotto] = query(
                "INSERT INTO prodotti (nome) VALUES (%s)", (prodotto,), commit=True)

    query("INSERT INTO vendite (id_cliente, id_prodotto, prezzo_vendita, data_acquisto) "
          "VALUES (%s, %s, %s, %s)",
          (id_cliente, id_prodotti[prodotto], round(prezzo, 2), data), commit=True)
    importate += 1

print(f"Importate: {importate} - Scartate: {scartate}")
