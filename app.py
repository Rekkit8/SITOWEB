"""Registro vendite - applicazione web Flask + MySQL.

Architettura
------------
app.py        rotte, autenticazione, permessi e logica dell'applicazione
db.py         unico punto di accesso al database (query parametrizzate)
templates/    pagine HTML (Jinja2)
static/       CSS, logo e JavaScript
schema.sql    tabelle aggiuntive (categorie, prodotti_categorie, profili_utente)

Le credenziali stanno nel file .env (non va su GitHub).
"""
import hashlib
import math
import os
import re
import secrets
import smtplib
from datetime import date, datetime, timedelta
from email.message import EmailMessage
from email.utils import formataddr
from functools import wraps

from dotenv import load_dotenv

load_dotenv()  # legge .env prima di importare db

from flask import (Flask, Response, abort, flash, g, jsonify, make_response,
                   redirect, render_template, request, url_for)
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from mysql.connector import errors as db_errors
from werkzeug.security import check_password_hash, generate_password_hash

from db import query

app = Flask(__name__)

# ================================================================ Configurazione
if not os.environ.get("SECRET_KEY"):
    print("ATTENZIONE: SECRET_KEY non impostata nel .env, ne uso una temporanea "
          "(i link di conferma già inviati smettono di funzionare a ogni riavvio).")
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = 4 * 1024 * 1024      # limite di ogni richiesta (upload compresi)

serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])

COOKIE_NAME = "token"
TOKEN_DURATA = timedelta(minutes=30)
CONFERMA_SCADENZA = 3600                  # secondi di validità del link di conferma
MAX_LUNGHEZZA_RICERCA = 100
MAX_IMMAGINE = 2 * 1024 * 1024            # 2 MB per immagine
# Se vale 1 e la mail non parte, il link di conferma viene mostrato a schermo (solo per i test)
MODALITA_SVILUPPO = os.environ.get("MODALITA_SVILUPPO") == "1"

TOKENS = {}   # token -> {"scadenza": datetime, "id_utente": int}

# Hash usato per fare un confronto "finto" quando l'email non esiste:
# così il tempo di risposta non rivela se l'account c'è.
HASH_FINTO = generate_password_hash("password-finta")

# Prefissi internazionali (paese, prefisso)
PREFISSI = [
    ("Albania", "+355"), ("Argentina", "+54"), ("Australia", "+61"),
    ("Austria", "+43"), ("Belgio", "+32"), ("Brasile", "+55"),
    ("Bulgaria", "+359"), ("Canada", "+1"), ("Cile", "+56"),
    ("Cina", "+86"), ("Colombia", "+57"), ("Corea del Sud", "+82"),
    ("Croazia", "+385"), ("Danimarca", "+45"), ("Egitto", "+20"),
    ("Emirati Arabi Uniti", "+971"), ("Filippine", "+63"),
    ("Finlandia", "+358"), ("Francia", "+33"), ("Germania", "+49"),
    ("Giappone", "+81"), ("Grecia", "+30"), ("India", "+91"),
    ("Indonesia", "+62"), ("Irlanda", "+353"), ("Israele", "+972"),
    ("Italia", "+39"), ("Lussemburgo", "+352"), ("Malta", "+356"),
    ("Marocco", "+212"), ("Messico", "+52"), ("Moldavia", "+373"),
    ("Norvegia", "+47"), ("Paesi Bassi", "+31"), ("Perù", "+51"),
    ("Polonia", "+48"), ("Portogallo", "+351"), ("Regno Unito", "+44"),
    ("Repubblica Ceca", "+420"), ("Romania", "+40"), ("Russia", "+7"),
    ("San Marino", "+378"), ("Serbia", "+381"), ("Slovacchia", "+421"),
    ("Slovenia", "+386"), ("Spagna", "+34"), ("Stati Uniti", "+1"),
    ("Sudafrica", "+27"), ("Svezia", "+46"), ("Svizzera", "+41"),
    ("Tunisia", "+216"), ("Turchia", "+90"), ("Ucraina", "+380"),
    ("Ungheria", "+36"), ("Vaticano", "+379"),
]
PREFISSI_VALIDI = {prefisso for _, prefisso in PREFISSI}

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}")
TELEFONO_RE = re.compile(r"\d{6,12}")


# ================================================================ Autenticazione
def crea_token(id_utente):
    token = secrets.token_urlsafe(32)
    TOKENS[token] = {"scadenza": datetime.now() + TOKEN_DURATA, "id_utente": id_utente}
    return token


def token_valido(token):
    dati = TOKENS.get(token)
    if dati is None:
        return False
    if dati["scadenza"] < datetime.now():
        del TOKENS[token]
        return False
    return True


def revoca_token():
    """Invalida lato server il token presente nel cookie della richiesta."""
    TOKENS.pop(request.cookies.get(COOKIE_NAME), None)


def utente_corrente():
    """Utente collegato (dict) oppure None. Rilegge sempre il database:
    se un gestore disattiva un account, l'accesso cade subito."""
    token = request.cookies.get(COOKIE_NAME)
    if not token_valido(token):
        return None
    utente = query("SELECT id, nome, email, ruolo, attivo FROM utenti WHERE id = %s",
                   (TOKENS[token]["id_utente"],), one=True)
    if not utente or not utente["attivo"]:
        TOKENS.pop(token, None)
        return None
    return utente


def login_required(f):
    """Serve un utente collegato, altrimenti rimanda al login."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        utente = utente_corrente()
        if utente is None:
            return redirect(url_for("login_page"))
        g.utente = utente
        return f(*args, **kwargs)
    return wrapper


def solo_gestori(f):
    """Serve un utente collegato con ruolo 'gestore', altrimenti errore 403.
    Il controllo vero è qui sul server: nascondere i pulsanti non basta."""
    @login_required
    @wraps(f)
    def wrapper(*args, **kwargs):
        if g.utente["ruolo"] != "gestore":
            abort(403)
        return f(*args, **kwargs)
    return wrapper


@app.context_processor
def contesto():
    return {"utente": g.get("utente"), "max_ricerca": MAX_LUNGHEZZA_RICERCA}


@app.after_request
def intestazioni(risposta):
    # Niente cache per le pagine (le immagini la impostano da sole)
    risposta.headers.setdefault("Cache-Control", "no-store")
    risposta.headers["X-Content-Type-Options"] = "nosniff"
    return risposta


@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(413)
def errore(e):
    testi = {
        403: ("Accesso riservato", "Questa sezione è riservata agli utenti gestori."),
        404: ("Pagina non trovata", "L'indirizzo richiesto non esiste o l'elemento è stato eliminato."),
        413: ("File troppo grande", "Il file supera la dimensione massima consentita (2 MB per immagine)."),
    }
    titolo, testo = testi[e.code]
    utente = utente_corrente()
    g.utente = utente
    return render_template("errore.html", codice=e.code, titolo=titolo, testo=testo), e.code


# ================================================================ Mail
LOGO_EMAIL = os.path.join(app.root_path, "static", "logo-email.png")


def costruisci_messaggio(mittente, destinatario, oggetto, testo, html=None):
    """Crea il messaggio: versione testo semplice + (se c'è) versione HTML con il logo
    incorporato. Chi non può leggere l'HTML vede automaticamente il testo."""
    messaggio = EmailMessage()
    messaggio["From"] = formataddr(("Registro vendite", mittente))
    messaggio["To"] = destinatario
    messaggio["Subject"] = oggetto
    messaggio.set_content(testo)
    if html:
        messaggio.add_alternative(html, subtype="html")
        try:
            with open(LOGO_EMAIL, "rb") as f:
                logo = f.read()
            # Il logo viaggia dentro la mail e l'HTML lo richiama con src="cid:logo-registro"
            messaggio.get_body(preferencelist=("html",)).add_related(
                logo, "image", "png", cid="<logo-registro>")
        except OSError:
            print("Logo per la mail non trovato:", LOGO_EMAIL)
    return messaggio


def invia_mail(destinatario, oggetto, testo, html=None):
    """Invia una mail via SMTP. Ritorna True se è partita, False altrimenti
    (credenziali mancanti, rete bloccata, timeout...)."""
    mittente = os.environ.get("MAIL_USER")
    password = os.environ.get("MAIL_PASSWORD")
    if not mittente or not password:
        print("Mail non configurata: imposta MAIL_USER e MAIL_PASSWORD nel .env")
        return False

    server = os.environ.get("MAIL_SERVER", "smtp.gmail.com")
    porta = int(os.environ.get("MAIL_PORT", "587"))
    messaggio = costruisci_messaggio(mittente, destinatario, oggetto, testo, html)

    try:
        if porta == 465:
            smtp = smtplib.SMTP_SSL(server, porta, timeout=10)
        else:
            smtp = smtplib.SMTP(server, porta, timeout=10)
        with smtp:
            if porta != 465:
                smtp.starttls()
            smtp.login(mittente, password)
            smtp.send_message(messaggio)
        return True
    except (OSError, smtplib.SMTPException) as errore_smtp:
        print("Invio mail fallito:", errore_smtp)
        return False


def costruisci_link(endpoint, token):
    """Indirizzo completo da mettere nelle mail. Se nel .env c'è BASE_URL (sito pubblicato)
    si usa quello, altrimenti l'indirizzo con cui sta girando l'app."""
    base = os.environ.get("BASE_URL", "").rstrip("/")
    if base:
        return base + url_for(endpoint, token=token)
    return url_for(endpoint, token=token, _external=True)


def invia_mail_con_link(destinatario, oggetto, nome, titolo, intro, pulsante, link, scadenza, piede):
    """Mail nello stile del sito con un pulsante. Usata per conferma account e recupero password."""
    testo = (f"Ciao {nome},\n\n{intro}\n\n{link}\n\n"
             f"Il link è valido per {scadenza} minuti.\n\n{piede}")
    html = render_template("email_azione.html", nome=nome, titolo=titolo, intro=intro,
                           pulsante=pulsante, link=link, scadenza=scadenza, piede=piede)
    return invia_mail(destinatario, oggetto, testo, html)


# ================================================================ Funzioni di supporto
def come_testo(valore):
    """Il driver può restituire bytes per alcune colonne (es. GROUP_CONCAT)."""
    if valore is None:
        return ""
    if isinstance(valore, (bytes, bytearray)):
        return bytes(valore).decode("utf-8", "replace")
    return str(valore)


def tipo_immagine(dati):
    """Riconosce il formato dai primi byte del file, senza fidarsi del nome o del
    tipo dichiarato dal browser. Ritorna il mimetype oppure None."""
    if dati.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if dati.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if dati[:4] == b"RIFF" and dati[8:12] == b"WEBP":
        return "image/webp"
    return None


def prezzo_valido(testo):
    """Converte '12,50' o '12.50' in float positivo, altrimenti None."""
    try:
        valore = float(str(testo).strip().replace(",", "."))
    except ValueError:
        return None
    if not math.isfinite(valore) or valore <= 0 or valore > 1_000_000:
        return None
    return round(valore, 2)


def data_valida(testo):
    try:
        return datetime.strptime(testo, "%Y-%m-%d").date()
    except ValueError:
        return None


def nuovo_id_cliente():
    """Prossimo id nel formato CL001, CL002, ..."""
    ultimo = query("SELECT id_cliente FROM clienti WHERE id_cliente REGEXP '^CL[0-9]+$' "
                   "ORDER BY CAST(SUBSTRING(id_cliente, 3) AS UNSIGNED) DESC LIMIT 1")
    numero = int(ultimo[0]["id_cliente"][2:]) + 1 if ultimo else 1
    return f"CL{numero:03d}"


# ================================================================ Dati dashboard
SQL_VENDITE = """
    SELECT v.id, v.id_cliente, c.nome AS nome,
           p.id AS id_prodotto, p.nome AS prodotto,
           v.prezzo_vendita, v.data_acquisto,
           (p.immagine IS NOT NULL) AS ha_immagine,
           (SELECT GROUP_CONCAT(ca.nome ORDER BY ca.nome SEPARATOR ', ')
              FROM prodotti_categorie pc
              JOIN categorie ca ON ca.id = pc.id_categoria
             WHERE pc.id_prodotto = p.id) AS categorie
      FROM vendite v
      JOIN clienti c ON c.id_cliente = v.id_cliente
      JOIN prodotti p ON p.id = v.id_prodotto
"""


def formatta_importo(valore):
    """1234.5 -> ('1.234', '50'): parte intera col punto delle migliaia + decimali."""
    intero, decimali = f"{valore:.2f}".split(".")
    return f"{int(intero):,}".replace(",", "."), decimali


def importo_testo(valore):
    intero, decimali = formatta_importo(valore)
    return f"{intero},{decimali}"


def prepara_vendita(vendita):
    """Trasforma un record del database in valori pronti da mostrare e da cercare.

    Gestisce campi mancanti, date non valide e prezzi non numerici senza
    mandare in errore la pagina.
    """
    d = vendita.get("data_acquisto")
    if isinstance(d, datetime):
        data_valore = d.date()
    elif isinstance(d, date):
        data_valore = d
    else:
        data_valore = data_valida(str(d))
    data = data_valore.strftime("%d/%m/%Y") if data_valore else "n/d"

    try:
        prezzo_valore = float(vendita.get("prezzo_vendita"))
        if not math.isfinite(prezzo_valore):
            prezzo_valore = None
    except (TypeError, ValueError):
        prezzo_valore = None
    prezzo_num = f"{prezzo_valore:.2f}" if prezzo_valore is not None else ""
    prezzo = importo_testo(prezzo_valore) if prezzo_valore is not None else "n/d"

    id_cliente = come_testo(vendita.get("id_cliente"))
    nome = come_testo(vendita.get("nome")).strip()
    prodotto = come_testo(vendita.get("prodotto"))
    categorie = come_testo(vendita.get("categorie"))

    riga = {
        "id": vendita.get("id"),
        "id_cliente": id_cliente,
        "nome": nome,
        "id_prodotto": vendita.get("id_prodotto"),
        "prodotto": prodotto,
        "categorie": categorie,
        "ha_immagine": bool(vendita.get("ha_immagine")),
        "data_acquisto": data,
        "data_valore": data_valore,
        "prezzo": prezzo,
        "prezzo_valore": prezzo_valore,
        "iniziale": (nome[:1] or "?").upper(),
        # Tinta dell'avatar: stessa persona, stesso colore
        "tinta": sum(ord(c) for c in (id_cliente or nome)) * 37 % 360,
    }
    # Il prezzo si cerca come appare (1.099,00) ma anche 1099,00 e 1099.00
    riga["testo_ricerca"] = " ".join([
        id_cliente, nome, prodotto, categorie, data, prezzo,
        prezzo_num, prezzo_num.replace(".", ","),
    ]).lower()
    return riga


def filtra_vendite(testo=""):
    """(righe filtrate dalla più recente alla più vecchia, totale vendite)."""
    testo = testo.strip().lower()
    tutte = [prepara_vendita(v) for v in query(SQL_VENDITE)]
    righe = [r for r in tutte if testo in r["testo_ricerca"]] if testo else tutte
    con_data = sorted((r for r in righe if r["data_valore"]),
                      key=lambda r: r["data_valore"], reverse=True)
    senza_data = [r for r in righe if not r["data_valore"]]
    return con_data + senza_data, len(tutte)


def calcola_sintesi(righe):
    """Totali e barre del grafico per le righe attualmente mostrate."""
    con_prezzo = [r for r in righe if r["prezzo_valore"] is not None]
    totale = sum(r["prezzo_valore"] for r in con_prezzo)
    intero, decimali = formatta_importo(totale)

    if con_prezzo:
        massimo_valore = max(r["prezzo_valore"] for r in con_prezzo)
        media = importo_testo(totale / len(con_prezzo)) + " €"
        massimo = importo_testo(massimo_valore) + " €"
    else:
        massimo_valore = 0
        media = massimo = "n/d"

    # Grafico: una barra per vendita, in ordine cronologico
    cronologiche = sorted((r for r in con_prezzo if r["data_valore"]),
                          key=lambda r: r["data_valore"])
    barre = []
    picco_assegnato = False
    for r in cronologiche:
        altezza = 6
        if massimo_valore > 0:
            altezza = max(6, round(r["prezzo_valore"] / massimo_valore * 100))
        e_picco = not picco_assegnato and r["prezzo_valore"] == massimo_valore
        picco_assegnato = picco_assegnato or e_picco
        barre.append({
            "altezza": altezza,
            "max": e_picco,
            "titolo": f"{r['nome']}, {r['prodotto']}: {r['prezzo']} €",
        })

    return {
        "numero": len(righe),
        "intero": intero,
        "decimali": decimali,
        "media": media,
        "massimo": massimo,
        "barre": barre,
        "data_inizio": cronologiche[0]["data_valore"].strftime("%d/%m") if cronologiche else "",
        "data_fine": cronologiche[-1]["data_valore"].strftime("%d/%m") if cronologiche else "",
    }


# ================================================================ Rotte: accesso
@app.get("/")
def index():
    return redirect(url_for("dashboard"))


@app.get("/login")
def login_page():
    """Mostra sempre il login: eventuali token precedenti vengono annullati."""
    revoca_token()
    risposta = make_response(render_template("login.html"))
    risposta.delete_cookie(COOKIE_NAME)
    return risposta


@app.post("/login")
def login():
    """Riceve email e password in JSON, le verifica sul database e rilascia il token."""
    dati = request.get_json(silent=True) or {}
    email = str(dati.get("email", "")).strip().lower()
    password = str(dati.get("password", ""))

    utente = query("SELECT id, password_hash, attivo FROM utenti WHERE email = %s",
                   (email,), one=True)   # %s: query parametrizzata, niente SQL injection
    hash_salvato = utente["password_hash"] if utente else HASH_FINTO
    password_ok = check_password_hash(hash_salvato, password)

    if not utente or not password_ok:
        return jsonify({"successo": False,
                        "messaggio": "Email o password errati."}), 401
    if not utente["attivo"]:
        return jsonify({"successo": False,
                        "messaggio": "Account non ancora attivo: apri il link che ti abbiamo inviato per email."}), 403

    token = crea_token(utente["id"])
    risposta = make_response(jsonify({"successo": True,
                                      "redirect": url_for("dashboard")}))
    # Niente max_age -> cookie di sessione: sparisce alla chiusura del browser
    risposta.set_cookie(COOKIE_NAME, token, httponly=True, samesite="Lax")
    return risposta


@app.post("/logout")
def logout():
    """Logout: revoca il token lato server e cancella il cookie dal browser."""
    revoca_token()
    risposta = make_response(redirect(url_for("login_page"), code=303))
    risposta.delete_cookie(COOKIE_NAME)
    return risposta


# ================================================================ Rotte: registrazione
def render_registrazione(errori=None, status=200, valori=None):
    html = render_template("registrazione.html", pagina="registrazione",
                           errori=errori or [], prefissi=PREFISSI, v=valori or {})
    return html, status


@app.route("/registrazione", methods=["GET", "POST"])
def registrazione():
    if request.method == "GET":
        return render_registrazione()

    nome = request.form.get("nome", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    password2 = request.form.get("password2", "")
    data_nascita = request.form.get("data_nascita", "")
    prefisso = request.form.get("prefisso", "")
    telefono = request.form.get("telefono", "").replace(" ", "")
    genere = request.form.get("genere", "")
    newsletter = request.form.get("newsletter") == "si"

    errori = []
    if not nome or len(nome) > 100:
        errori.append("Il nome è obbligatorio (massimo 100 caratteri).")
    if not EMAIL_RE.fullmatch(email) or len(email) > 255:
        errori.append("L'indirizzo email non è valido.")
    if len(password) < 8:
        errori.append("La password deve avere almeno 8 caratteri.")
    elif password != password2:
        errori.append("Le due password non coincidono.")
    nascita = data_valida(data_nascita)
    if nascita is None or nascita > date.today():
        errori.append("La data di nascita non è valida.")
    if prefisso not in PREFISSI_VALIDI:
        errori.append("Seleziona un prefisso internazionale valido.")
    if not TELEFONO_RE.fullmatch(telefono):
        errori.append("Il numero di telefono deve contenere da 6 a 12 cifre.")
    if genere not in {"uomo", "donna", "altro"}:
        errori.append("Seleziona un genere valido.")
    if not errori and query("SELECT id FROM utenti WHERE email = %s", (email,), one=True):
        errori.append("Esiste già un account con questa email.")

    if errori:
        # Le password non vengono mai rimostrate; gli altri campi sì
        valori = {"nome": nome, "email": email, "data_nascita": data_nascita,
                  "prefisso": prefisso, "telefono": telefono,
                  "genere": genere, "newsletter": newsletter}
        return render_registrazione(errori, 400, valori)

    try:
        # Account creato NON attivo (attivo = FALSE): si attiva solo con il link inviato per email
        id_utente = query(
            "INSERT INTO utenti (nome, email, password_hash, ruolo, attivo) "
            "VALUES (%s, %s, %s, 'base', FALSE)",
            (nome, email, generate_password_hash(password)), commit=True)
    except db_errors.IntegrityError:
        return render_registrazione(["Esiste già un account con questa email."], 400,
                                    {"nome": nome, "email": email})
    # Relazione 1:1 utenti - profili_utente
    query("INSERT INTO profili_utente (id_utente, telefono, data_nascita, genere, newsletter) "
          "VALUES (%s, %s, %s, %s, %s)",
          (id_utente, f"{prefisso} {telefono}", nascita, genere, newsletter), commit=True)

    token = serializer.dumps(email, salt="conferma-email")
    link = costruisci_link("conferma", token)
    inviata = invia_mail_con_link(
        email, "Conferma il tuo account - Registro vendite", nome,
        titolo="Conferma il tuo account",
        intro="Grazie per esserti registrato. Per attivare l'account basta un clic: "
              "conferma che questo indirizzo email è tuo.",
        pulsante="Conferma l'account", link=link, scadenza=CONFERMA_SCADENZA // 60,
        piede=f"Hai ricevuto questa email perché l'indirizzo {email} è stato usato per "
              "registrarsi a Registro vendite. Se non sei stato tu, ignora questo messaggio: "
              "l'account non verrà attivato.")
    if not inviata:
        print("Link di conferma (mail non inviata):", link)
    return render_template("registrazione_ok.html", email=email, inviata=inviata,
                           link=link if (not inviata and MODALITA_SVILUPPO) else None)


@app.get("/conferma/<token>")
def conferma(token):
    """Attiva l'account se il link firmato è valido e non scaduto."""
    try:
        email = serializer.loads(token, salt="conferma-email", max_age=CONFERMA_SCADENZA)
    except SignatureExpired:
        flash("Il link di conferma è scaduto. Registrati di nuovo.", "errore")
        return redirect(url_for("login_page"))
    except BadSignature:
        flash("Link di conferma non valido.", "errore")
        return redirect(url_for("login_page"))
    query("UPDATE utenti SET attivo = TRUE WHERE email = %s", (email,), commit=True)
    flash("Account attivato: ora puoi accedere.", "ok")
    return redirect(url_for("login_page"))


# ================================================================ Rotte: password dimenticata
RESET_SCADENZA = 3600                  # il link per cambiare password vale 1 ora
RESET_MAX_RICHIESTE = 3                # al massimo 3 richieste ogni 15 minuti per indirizzo
RESET_FINESTRA = timedelta(minutes=15)
RESET_RICHIESTE = {}                   # email -> orari delle richieste recenti


def troppe_richieste(email):
    """Freno anti-spam: evita che qualcuno riempia di mail la casella di un utente."""
    ora = datetime.now()
    if len(RESET_RICHIESTE) > 1000:
        RESET_RICHIESTE.clear()
    recenti = [t for t in RESET_RICHIESTE.get(email, []) if ora - t < RESET_FINESTRA]
    if len(recenti) >= RESET_MAX_RICHIESTE:
        RESET_RICHIESTE[email] = recenti
        return True
    recenti.append(ora)
    RESET_RICHIESTE[email] = recenti
    return False


def impronta_password(password_hash):
    """Piccola impronta dell'hash attuale: dentro il link serve a farlo funzionare una sola volta
    (dopo il cambio password l'impronta cambia e il vecchio link non vale più)."""
    return hashlib.sha256(password_hash.encode()).hexdigest()[:16]


@app.route("/password-dimenticata", methods=["GET", "POST"])
def password_dimenticata():
    if request.method == "GET":
        return render_template("password_dimenticata.html", pagina="password")

    email = request.form.get("email", "").strip().lower()
    link = None
    inviata = True
    if EMAIL_RE.fullmatch(email) and len(email) <= 255 and not troppe_richieste(email):
        utente = query("SELECT id, nome, password_hash, attivo FROM utenti WHERE email = %s",
                       (email,), one=True)
        if utente and utente["attivo"]:
            token = serializer.dumps({"id": utente["id"],
                                      "h": impronta_password(utente["password_hash"])},
                                     salt="reset-password")
            link = costruisci_link("reimposta_password", token)
            inviata = invia_mail_con_link(
                email, "Reimposta la tua password - Registro vendite", utente["nome"],
                titolo="Reimposta la tua password",
                intro="Hai chiesto di cambiare la password del tuo account. "
                      "Usa il pulsante per sceglierne una nuova.",
                pulsante="Scegli una nuova password", link=link, scadenza=RESET_SCADENZA // 60,
                piede=f"Hai ricevuto questa email perché è stato chiesto il recupero della password "
                      f"per {email}. Se non sei stato tu, ignora questo messaggio: la tua password "
                      "non cambia.")
            if not inviata:
                print("Link per reimpostare la password (mail non inviata):", link)
    # Risposta identica sia che l'account esista sia che non esista: così nessuno può
    # scoprire quali email sono iscritte al sito.
    return render_template("password_dimenticata_ok.html", pagina="password",
                           link=link if (not inviata and MODALITA_SVILUPPO) else None)


@app.route("/reimposta-password/<token>", methods=["GET", "POST"])
def reimposta_password(token):
    try:
        dati = serializer.loads(token, salt="reset-password", max_age=RESET_SCADENZA)
    except SignatureExpired:
        flash("Il link è scaduto. Richiedine uno nuovo.", "errore")
        return redirect(url_for("password_dimenticata"))
    except BadSignature:
        flash("Link non valido. Richiedine uno nuovo.", "errore")
        return redirect(url_for("password_dimenticata"))

    utente = query("SELECT id, password_hash FROM utenti WHERE id = %s",
                   (dati.get("id") if isinstance(dati, dict) else 0,), one=True)
    if (not utente or not isinstance(dati, dict)
            or impronta_password(utente["password_hash"]) != dati.get("h")):
        flash("Questo link è già stato usato o non è più valido. Richiedine uno nuovo.", "errore")
        return redirect(url_for("password_dimenticata"))

    errori = []
    if request.method == "POST":
        password = request.form.get("password", "")
        password2 = request.form.get("password2", "")
        if len(password) < 8:
            errori.append("La password deve avere almeno 8 caratteri.")
        elif password != password2:
            errori.append("Le due password non coincidono.")
        if not errori:
            query("UPDATE utenti SET password_hash = %s WHERE id = %s",
                  (generate_password_hash(password), utente["id"]), commit=True)
            # Chiude le sessioni già aperte con la vecchia password
            for t in [t for t, d in TOKENS.items() if d["id_utente"] == utente["id"]]:
                del TOKENS[t]
            flash("Password aggiornata: ora puoi accedere.", "ok")
            return redirect(url_for("login_page"))
    return render_template("reimposta_password.html", pagina="password", errori=errori), (400 if errori else 200)


# ================================================================ Rotte: dashboard (tutti gli utenti)
@app.get("/dashboard")
@login_required
def dashboard():
    """Riepilogo, grafico e tabella delle vendite, filtrabili con ?q=testo.
    Sola lettura: la vedono utenti base e gestori."""
    q = request.args.get("q", "")[:MAX_LUNGHEZZA_RICERCA]
    righe, totale = filtra_vendite(q)
    return render_template("dashboard.html", pagina="dashboard", righe=righe,
                           s=calcola_sintesi(righe), totale=totale, q=q)


@app.get("/prodotti/<int:id>/immagine")
@login_required
def prodotto_immagine(id):
    """Restituisce l'immagine salvata nel database (colonna BLOB)."""
    p = query("SELECT immagine, immagine_tipo FROM prodotti WHERE id = %s", (id,), one=True)
    if not p or not p["immagine"]:
        abort(404)
    risposta = Response(bytes(p["immagine"]), mimetype=p["immagine_tipo"] or "application/octet-stream")
    risposta.headers["Cache-Control"] = "private, max-age=60"
    return risposta


# ================================================================ Rotte: gestione (solo gestori)
@app.get("/gestione")
@solo_gestori
def gestione():
    return redirect(url_for("gestione_vendite"))


# ---------------------------------------------------------------- vendite
@app.get("/gestione/vendite")
@solo_gestori
def gestione_vendite():
    righe, _ = filtra_vendite("")
    return render_template("gestione_vendite.html", pagina="gestione-vendite", righe=righe)


@app.route("/gestione/vendite/nuova", methods=["GET", "POST"])
@app.route("/gestione/vendite/<int:id>/modifica", methods=["GET", "POST"])
@solo_gestori
def vendita_salva(id=None):
    """Crea (Create) o modifica (Update) una vendita."""
    vendita = None
    if id is not None:
        vendita = query("SELECT * FROM vendite WHERE id = %s", (id,), one=True)
        if vendita is None:
            abort(404)

    errori = []
    valori = vendita or {"data_acquisto": date.today().isoformat()}

    if request.method == "POST":
        valori = {"id_cliente": request.form.get("id_cliente", ""),
                  "id_prodotto": request.form.get("id_prodotto", ""),
                  "prezzo_vendita": request.form.get("prezzo_vendita", "").strip(),
                  "data_acquisto": request.form.get("data_acquisto", "")}
        if not query("SELECT id_cliente FROM clienti WHERE id_cliente = %s",
                     (valori["id_cliente"],), one=True):
            errori.append("Seleziona un cliente valido.")
        if not valori["id_prodotto"].isdigit() or not query(
                "SELECT id FROM prodotti WHERE id = %s", (valori["id_prodotto"],), one=True):
            errori.append("Seleziona un prodotto valido.")
        prezzo = prezzo_valido(valori["prezzo_vendita"])
        if prezzo is None:
            errori.append("Il prezzo deve essere un numero maggiore di zero.")
        data = data_valida(valori["data_acquisto"])
        if data is None:
            errori.append("La data di acquisto non è valida.")

        if not errori:
            if id is None:
                query("INSERT INTO vendite (id_cliente, id_prodotto, prezzo_vendita, data_acquisto) "
                      "VALUES (%s, %s, %s, %s)",
                      (valori["id_cliente"], int(valori["id_prodotto"]), prezzo, data), commit=True)
                flash("Vendita aggiunta.", "ok")
            else:
                query("UPDATE vendite SET id_cliente = %s, id_prodotto = %s, "
                      "prezzo_vendita = %s, data_acquisto = %s WHERE id = %s",
                      (valori["id_cliente"], int(valori["id_prodotto"]), prezzo, data, id),
                      commit=True)
                flash("Vendita aggiornata.", "ok")
            return redirect(url_for("gestione_vendite"))

    return render_template("form_vendita.html", pagina="gestione-vendite", v=valori,
                           errori=errori, modifica=id is not None,
                           clienti=query("SELECT id_cliente, nome FROM clienti ORDER BY nome"),
                           prodotti=query("SELECT id, nome FROM prodotti ORDER BY nome")
                           ), (400 if errori else 200)


@app.post("/gestione/vendite/<int:id>/elimina")      # solo POST: mai eliminare con un link GET
@solo_gestori
def vendita_elimina(id):
    query("DELETE FROM vendite WHERE id = %s", (id,), commit=True)
    flash("Vendita eliminata.", "ok")
    return redirect(url_for("gestione_vendite"), code=303)


# ---------------------------------------------------------------- prodotti
@app.get("/gestione/prodotti")
@solo_gestori
def gestione_prodotti():
    righe = query("""
        SELECT p.id, p.nome, (p.immagine IS NOT NULL) AS ha_immagine,
               (SELECT GROUP_CONCAT(ca.nome ORDER BY ca.nome SEPARATOR ', ')
                  FROM prodotti_categorie pc
                  JOIN categorie ca ON ca.id = pc.id_categoria
                 WHERE pc.id_prodotto = p.id) AS categorie,
               (SELECT COUNT(*) FROM vendite v WHERE v.id_prodotto = p.id) AS n_vendite
          FROM prodotti p ORDER BY p.nome""")
    for r in righe:
        r["categorie"] = come_testo(r["categorie"])
    return render_template("gestione_prodotti.html", pagina="gestione-prodotti", righe=righe)


@app.route("/gestione/prodotti/nuovo", methods=["GET", "POST"])
@app.route("/gestione/prodotti/<int:id>/modifica", methods=["GET", "POST"])
@solo_gestori
def prodotto_salva(id=None):
    """Crea o modifica un prodotto: nome, categorie (N:M) e immagine (BLOB)."""
    prodotto = {"nome": "", "ha_immagine": False}
    selezionate = set()
    if id is not None:
        prodotto = query("SELECT id, nome, (immagine IS NOT NULL) AS ha_immagine "
                         "FROM prodotti WHERE id = %s", (id,), one=True)
        if prodotto is None:
            abort(404)
        selezionate = {r["id_categoria"] for r in query(
            "SELECT id_categoria FROM prodotti_categorie WHERE id_prodotto = %s", (id,))}

    categorie = query("SELECT id, nome FROM categorie ORDER BY nome")
    errori = []

    if request.method == "POST":
        nome = request.form.get("nome", "").strip()
        nuova_categoria = request.form.get("nuova_categoria", "").strip()
        validi = {c["id"] for c in categorie}
        scelte = {int(x) for x in request.form.getlist("categorie") if x.isdigit()} & validi
        rimuovi = request.form.get("rimuovi_immagine") == "si"
        prodotto = {**prodotto, "nome": nome}
        selezionate = scelte

        if not nome or len(nome) > 100:
            errori.append("Il nome del prodotto è obbligatorio (massimo 100 caratteri).")
        if len(nuova_categoria) > 50:
            errori.append("Il nome della nuova categoria è troppo lungo (massimo 50 caratteri).")

        dati_img, tipo_img = None, None
        file = request.files.get("immagine")
        if file and file.filename:
            dati_img = file.read(MAX_IMMAGINE + 1)
            if len(dati_img) > MAX_IMMAGINE:
                errori.append("L'immagine supera i 2 MB.")
            else:
                tipo_img = tipo_immagine(dati_img)
                if tipo_img is None:
                    errori.append("L'immagine deve essere un file JPG, PNG o WebP.")

        if not errori:
            if id is None:
                id = query("INSERT INTO prodotti (nome, immagine, immagine_tipo) VALUES (%s, %s, %s)",
                           (nome, dati_img, tipo_img), commit=True)
                flash("Prodotto aggiunto.", "ok")
            elif dati_img is not None:
                query("UPDATE prodotti SET nome = %s, immagine = %s, immagine_tipo = %s WHERE id = %s",
                      (nome, dati_img, tipo_img, id), commit=True)
                flash("Prodotto aggiornato.", "ok")
            elif rimuovi:
                query("UPDATE prodotti SET nome = %s, immagine = NULL, immagine_tipo = NULL WHERE id = %s",
                      (nome, id), commit=True)
                flash("Prodotto aggiornato.", "ok")
            else:
                query("UPDATE prodotti SET nome = %s WHERE id = %s", (nome, id), commit=True)
                flash("Prodotto aggiornato.", "ok")

            if nuova_categoria:
                query("INSERT IGNORE INTO categorie (nome) VALUES (%s)", (nuova_categoria,), commit=True)
                riga = query("SELECT id FROM categorie WHERE nome = %s", (nuova_categoria,), one=True)
                if riga:
                    scelte.add(riga["id"])
            # Relazione N:M prodotti - categorie: riscrivo i collegamenti
            query("DELETE FROM prodotti_categorie WHERE id_prodotto = %s", (id,), commit=True)
            for id_categoria in scelte:
                query("INSERT IGNORE INTO prodotti_categorie (id_prodotto, id_categoria) VALUES (%s, %s)",
                      (id, id_categoria), commit=True)
            return redirect(url_for("gestione_prodotti"))

    return render_template("form_prodotto.html", pagina="gestione-prodotti", p=prodotto,
                           categorie=categorie, selezionate=selezionate, errori=errori,
                           modifica=request.view_args.get("id") is not None
                           ), (400 if errori else 200)


@app.post("/gestione/prodotti/<int:id>/elimina")
@solo_gestori
def prodotto_elimina(id):
    try:
        query("DELETE FROM prodotti WHERE id = %s", (id,), commit=True)
        flash("Prodotto eliminato.", "ok")
    except db_errors.IntegrityError:
        flash("Il prodotto ha vendite collegate: elimina prima quelle vendite.", "errore")
    return redirect(url_for("gestione_prodotti"), code=303)


# ---------------------------------------------------------------- clienti
@app.get("/gestione/clienti")
@solo_gestori
def gestione_clienti():
    righe = query("""
        SELECT c.id_cliente, c.nome,
               (SELECT COUNT(*) FROM vendite v WHERE v.id_cliente = c.id_cliente) AS n_vendite
          FROM clienti c ORDER BY c.id_cliente""")
    return render_template("gestione_clienti.html", pagina="gestione-clienti", righe=righe)


@app.route("/gestione/clienti/nuovo", methods=["GET", "POST"])
@app.route("/gestione/clienti/<id_cliente>/modifica", methods=["GET", "POST"])
@solo_gestori
def cliente_salva(id_cliente=None):
    cliente = {"id_cliente": "", "nome": ""}
    if id_cliente is not None:
        cliente = query("SELECT id_cliente, nome FROM clienti WHERE id_cliente = %s",
                        (id_cliente,), one=True)
        if cliente is None:
            abort(404)

    errori = []
    if request.method == "POST":
        nome = request.form.get("nome", "").strip()
        cliente = {**cliente, "nome": nome}
        if not nome or len(nome) > 100:
            errori.append("Il nome è obbligatorio (massimo 100 caratteri).")
        if not errori:
            if id_cliente is None:
                query("INSERT INTO clienti (id_cliente, nome) VALUES (%s, %s)",
                      (nuovo_id_cliente(), nome), commit=True)
                flash("Cliente aggiunto.", "ok")
            else:
                query("UPDATE clienti SET nome = %s WHERE id_cliente = %s",
                      (nome, id_cliente), commit=True)
                flash("Cliente aggiornato.", "ok")
            return redirect(url_for("gestione_clienti"))

    return render_template("form_cliente.html", pagina="gestione-clienti", c=cliente,
                           errori=errori, modifica=id_cliente is not None
                           ), (400 if errori else 200)


@app.post("/gestione/clienti/<id_cliente>/elimina")
@solo_gestori
def cliente_elimina(id_cliente):
    try:
        query("DELETE FROM clienti WHERE id_cliente = %s", (id_cliente,), commit=True)
        flash("Cliente eliminato.", "ok")
    except db_errors.IntegrityError:
        flash("Il cliente ha vendite collegate: elimina prima quelle vendite.", "errore")
    return redirect(url_for("gestione_clienti"), code=303)


# ---------------------------------------------------------------- utenti
@app.get("/gestione/utenti")
@solo_gestori
def gestione_utenti():
    righe = query("""
        SELECT u.id, u.nome, u.email, u.ruolo, u.attivo, p.telefono, p.newsletter
          FROM utenti u LEFT JOIN profili_utente p ON p.id_utente = u.id
         ORDER BY u.id""")
    return render_template("gestione_utenti.html", pagina="gestione-utenti", righe=righe)


@app.route("/gestione/utenti/nuovo", methods=["GET", "POST"])
@app.route("/gestione/utenti/<int:id>/modifica", methods=["GET", "POST"])
@solo_gestori
def utente_salva(id=None):
    """Il gestore crea (già attivo) o modifica un utente, scegliendone il ruolo."""
    utente = {"nome": "", "email": "", "ruolo": "base", "attivo": 1}
    if id is not None:
        utente = query("SELECT id, nome, email, ruolo, attivo FROM utenti WHERE id = %s",
                       (id,), one=True)
        if utente is None:
            abort(404)
    se_stesso = id is not None and id == g.utente["id"]

    errori = []
    if request.method == "POST":
        nome = request.form.get("nome", "").strip()
        email = request.form.get("email", "").strip().lower()
        ruolo = request.form.get("ruolo", "base")
        attivo = request.form.get("attivo") == "si"
        password = request.form.get("password", "")
        if ruolo not in {"base", "gestore"}:
            ruolo = "base"
        if se_stesso:                     # un gestore non può togliersi i permessi da solo
            ruolo, attivo = "gestore", True
        utente = {**utente, "nome": nome, "email": email, "ruolo": ruolo, "attivo": attivo}

        if not nome or len(nome) > 100:
            errori.append("Il nome è obbligatorio (massimo 100 caratteri).")
        if not EMAIL_RE.fullmatch(email) or len(email) > 255:
            errori.append("L'indirizzo email non è valido.")
        elif query("SELECT id FROM utenti WHERE email = %s AND id <> %s",
                   (email, id or 0), one=True):
            errori.append("Esiste già un utente con questa email.")
        if id is None and len(password) < 8:
            errori.append("La password è obbligatoria (almeno 8 caratteri).")
        elif password and len(password) < 8:
            errori.append("La nuova password deve avere almeno 8 caratteri.")

        if not errori:
            if id is None:
                query("INSERT INTO utenti (nome, email, password_hash, ruolo, attivo) "
                      "VALUES (%s, %s, %s, %s, %s)",
                      (nome, email, generate_password_hash(password), ruolo, attivo), commit=True)
                flash("Utente creato.", "ok")
            elif password:
                query("UPDATE utenti SET nome = %s, email = %s, ruolo = %s, attivo = %s, "
                      "password_hash = %s WHERE id = %s",
                      (nome, email, ruolo, attivo, generate_password_hash(password), id), commit=True)
                flash("Utente aggiornato (password cambiata).", "ok")
            else:
                query("UPDATE utenti SET nome = %s, email = %s, ruolo = %s, attivo = %s WHERE id = %s",
                      (nome, email, ruolo, attivo, id), commit=True)
                flash("Utente aggiornato.", "ok")
            return redirect(url_for("gestione_utenti"))

    return render_template("form_utente.html", pagina="gestione-utenti", u=utente,
                           errori=errori, modifica=id is not None, se_stesso=se_stesso
                           ), (400 if errori else 200)


@app.post("/gestione/utenti/<int:id>/elimina")
@solo_gestori
def utente_elimina(id):
    if id == g.utente["id"]:
        flash("Non puoi eliminare il tuo stesso account.", "errore")
    else:
        query("DELETE FROM utenti WHERE id = %s", (id,), commit=True)
        flash("Utente eliminato.", "ok")
    return redirect(url_for("gestione_utenti"), code=303)


if __name__ == "__main__":
    # debug=True solo se lo chiedi tu (FLASK_DEBUG=1): il debugger di Flask non va lasciato attivo in rete
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1", port=5000)
