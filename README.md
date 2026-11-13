# Registro vendite

Applicazione web Flask + MySQL per consultare e gestire le vendite di un negozio di informatica.
Progetto scolastico: registrazione con conferma email, ruoli, CRUD, immagini nel database.

## Funzionalità
- **Registrazione con mail di conferma**: l'account nasce disattivato e si attiva dal link firmato (valido 1 ora).
- **Due ruoli**: *base* (sola lettura) e *gestore* (CRUD su vendite, prodotti, clienti e utenti).
- **Password cifrate** con `scrypt` (Werkzeug) e **query parametrizzate** contro la SQL injection.
- **Dashboard** (`/dashboard`, tutti gli utenti): riepilogo, grafico, ricerca con filtro in tempo reale.
- **Gestione** (`/gestione/...`, solo gestori): crea, modifica ed elimina dati.
- **Immagini dei prodotti salvate nel database** (colonna `MEDIUMBLOB`), con controllo del formato dai primi byte del file.
- **JavaScript**: login senza ricarica, filtro righe, anteprima immagine, conferma prima di eliminare.

## Database
| Relazione | Tabelle |
|---|---|
| 1:N | `clienti` → `vendite`, `prodotti` → `vendite` |
| N:M | `prodotti` ↔ `categorie` (tabella ponte `prodotti_categorie`) |
| 1:1 | `utenti` – `profili_utente` |

## Architettura
- `app.py`: rotte, autenticazione (token in cookie `HttpOnly`), decoratori `login_required` e `solo_gestori`
- `db.py`: unico punto di accesso al database
- `templates/`: pagine Jinja2 · `static/`: CSS, JavaScript, logo
- `schema.sql`: tabelle aggiuntive · `importa_dati.py`, `crea_gestore.py`: script di avvio

## Avvio
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
mysql -h <host> -u <utente> -p <database> < schema.sql
python crea_gestore.py      # primo utente gestore
python importa_dati.py      # dati di esempio
python app.py               # http://localhost:5000
```

File `.env` (non va su GitHub):
```
SECRET_KEY=...
DB_HOST=...
DB_USER=...
DB_PASSWORD='...'
DB_NAME=...
MAIL_USER=...
MAIL_PASSWORD=...        # password per app
# facoltativi: MAIL_SERVER, MAIL_PORT, BASE_URL, MODALITA_SVILUPPO=1, FLASK_DEBUG=1
```
