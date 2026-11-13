"""Ultima risorsa: cambia la password di un utente direttamente nel database.
Serve se un gestore dimentica la password e non riesce a ricevere la mail.

Uso (dalla cartella del progetto, con il venv attivo):
    python reimposta_password.py
"""
import getpass
from dotenv import load_dotenv
load_dotenv()

from werkzeug.security import generate_password_hash
from db import query

email = input("Email dell'utente: ").strip().lower()
utente = query("SELECT id, nome FROM utenti WHERE email = %s", (email,), one=True)
if not utente:
    raise SystemExit("Nessun utente con questa email.")

password = getpass.getpass(f"Nuova password per {utente['nome']}: ")
if len(password) < 8:
    raise SystemExit("La password deve avere almeno 8 caratteri.")

query("UPDATE utenti SET password_hash = %s, attivo = TRUE WHERE id = %s",
      (generate_password_hash(password), utente["id"]), commit=True)
print("Password aggiornata.")
