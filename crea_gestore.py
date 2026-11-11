import getpass
from dotenv import load_dotenv
load_dotenv()

from werkzeug.security import generate_password_hash
from db import query

nome = "Omar"
email = "angelottiomar@gmail.com"

password = getpass.getpass("Scegli la password del gestore: ")
if len(password) < 8:
    raise SystemExit("La password deve avere almeno 8 caratteri.")

query(
    "INSERT INTO utenti (nome, email, password_hash, ruolo, attivo) "
    "VALUES (%s, %s, %s, 'gestore', TRUE)",
    (nome, email, generate_password_hash(password)),
    commit=True,
)
print("Gestore creato.")
