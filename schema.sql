-- Tabelle aggiuntive per il Registro vendite.
-- Si esegue una sola volta, dal terminale del server:
--   mysql -h 10.10.0.10 -u angelotti.omar -p oangelotti < schema.sql
--
-- Relazioni del database:
--   1:N  clienti   -> vendite            (un cliente ha molte vendite)
--   1:N  prodotti  -> vendite            (un prodotto compare in molte vendite)
--   N:M  prodotti <-> categorie          (tabella ponte prodotti_categorie)
--   1:1  utenti    -  profili_utente     (ogni utente ha al massimo un profilo)

CREATE TABLE IF NOT EXISTS categorie (
  id INT AUTO_INCREMENT PRIMARY KEY,
  nome VARCHAR(50) NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS prodotti_categorie (
  id_prodotto INT NOT NULL,
  id_categoria INT NOT NULL,
  PRIMARY KEY (id_prodotto, id_categoria),
  FOREIGN KEY (id_prodotto)  REFERENCES prodotti(id)  ON DELETE CASCADE,
  FOREIGN KEY (id_categoria) REFERENCES categorie(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS profili_utente (
  id_utente INT PRIMARY KEY,
  telefono VARCHAR(30),
  data_nascita DATE,
  genere ENUM('uomo','donna','altro'),
  newsletter BOOLEAN NOT NULL DEFAULT FALSE,
  FOREIGN KEY (id_utente) REFERENCES utenti(id) ON DELETE CASCADE
);

INSERT IGNORE INTO categorie (nome) VALUES
  ('Computer'), ('Monitor'), ('Periferiche'), ('Audio'),
  ('Stampanti'), ('Archiviazione'), ('Accessori');

-- Assegna una categoria ai prodotti già importati
INSERT IGNORE INTO prodotti_categorie (id_prodotto, id_categoria)
SELECT p.id, c.id
  FROM prodotti p
  JOIN categorie c ON
       (p.nome LIKE 'Notebook%'            AND c.nome = 'Computer')
    OR (p.nome LIKE 'Monitor%'             AND c.nome = 'Monitor')
    OR (p.nome IN ('Tastiera meccanica', 'Mouse wireless', 'Webcam Full HD') AND c.nome = 'Periferiche')
    OR (p.nome = 'Cuffie Bluetooth'        AND c.nome = 'Audio')
    OR (p.nome = 'Stampante laser'         AND c.nome = 'Stampanti')
    OR (p.nome LIKE 'Hard disk%'           AND c.nome = 'Archiviazione')
    OR (p.nome LIKE 'Docking station%'     AND c.nome = 'Accessori');
