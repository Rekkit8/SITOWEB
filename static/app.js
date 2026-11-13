/* JavaScript del frontend: tutto opzionale, le pagine funzionano anche senza. */
document.addEventListener("DOMContentLoaded", () => {

  /* 1. Conferma prima di eliminare: i form con data-conferma chiedono "Sei sicuro?" */
  document.addEventListener("submit", (e) => {
    const messaggio = e.target.dataset && e.target.dataset.conferma;
    if (messaggio && !window.confirm(messaggio)) e.preventDefault();
  });

  /* 2. Login: invia email e password in JSON e mostra l'errore senza ricaricare la pagina */
  const formLogin = document.getElementById("login-form");
  if (formLogin) {
    const boxErrore = document.getElementById("errore");
    const testoErrore = document.getElementById("testo-errore");
    const campoPassword = document.getElementById("password");
    const pulsante = document.getElementById("accedi");
    const mostra = document.getElementById("mostra");

    mostra.addEventListener("click", () => {
      const nascosta = campoPassword.type === "password";
      campoPassword.type = nascosta ? "text" : "password";
      mostra.textContent = nascosta ? "Nascondi" : "Mostra";
      mostra.setAttribute("aria-pressed", String(nascosta));
    });

    const mostraErrore = (msg) => {
      testoErrore.textContent = msg;
      boxErrore.hidden = false;
      campoPassword.value = "";
      campoPassword.focus();
    };

    formLogin.addEventListener("submit", async (e) => {
      e.preventDefault();
      boxErrore.hidden = true;
      pulsante.disabled = true;
      pulsante.textContent = "Accesso in corso…";
      try {
        const res = await fetch(formLogin.dataset.url, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email: formLogin.email.value, password: formLogin.password.value }),
        });
        const dati = await res.json();
        if (res.ok) { window.location.href = dati.redirect; return; }
        mostraErrore(dati.messaggio || "Credenziali non valide.");
      } catch (err) {
        mostraErrore("Impossibile contattare il server. Riprova tra poco.");
      }
      pulsante.disabled = false;
      pulsante.textContent = "Accedi";
    });
  }

  /* 3. Dashboard: filtra le righe mentre scrivi (il server filtra comunque con Invio) */
  const campoRicerca = document.querySelector("[data-filtro-righe]");
  if (campoRicerca) {
    const righe = Array.from(document.querySelectorAll("tbody tr[data-testo]"));
    const conteggio = document.getElementById("conteggio");
    const totale = Number(document.querySelector("[data-totale]").dataset.totale);
    const nessuno = document.getElementById("nessun-risultato");
    const tabella = document.querySelector(".tabella table");

    campoRicerca.addEventListener("input", () => {
      const testo = campoRicerca.value.trim().toLowerCase();
      let visibili = 0;
      righe.forEach((riga) => {
        const ok = !testo || riga.dataset.testo.includes(testo);
        riga.hidden = !ok;
        if (ok) visibili += 1;
      });
      conteggio.textContent = testo ? `${visibili} di ${totale}` : String(totale);
      if (nessuno && tabella) {
        nessuno.hidden = visibili > 0;
        tabella.hidden = visibili === 0;
      }
    });
  }

  /* 4. Registrazione: controlla subito se le due password coincidono */
  const p1 = document.getElementById("password");
  const p2 = document.getElementById("password2");
  const esito = document.getElementById("esito-password");
  if (p1 && p2 && esito) {
    const controlla = () => {
      if (!p2.value) { esito.textContent = ""; esito.classList.remove("errore"); return; }
      const uguali = p1.value === p2.value;
      esito.textContent = uguali ? "Le password coincidono." : "Le password non coincidono.";
      esito.classList.toggle("errore", !uguali);
    };
    p1.addEventListener("input", controlla);
    p2.addEventListener("input", controlla);
  }

  /* 5. Immagine prodotto: anteprima e controllo di dimensione prima dell'invio */
  const campoImmagine = document.getElementById("immagine");
  if (campoImmagine) {
    const anteprima = document.getElementById(campoImmagine.dataset.anteprima);
    const esitoImmagine = document.getElementById("esito-immagine");
    campoImmagine.addEventListener("change", () => {
      const file = campoImmagine.files[0];
      esitoImmagine.textContent = "";
      esitoImmagine.classList.remove("errore");
      if (!file) return;
      if (file.size > Number(campoImmagine.dataset.maxByte)) {
        esitoImmagine.textContent = "L'immagine supera i 2 MB: scegline una più leggera.";
        esitoImmagine.classList.add("errore");
        campoImmagine.value = "";
        return;
      }
      anteprima.src = URL.createObjectURL(file);
      anteprima.hidden = false;
    });
  }
});
