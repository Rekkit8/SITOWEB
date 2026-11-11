from PyQt6.QtWidgets import QDialog, QLineEdit, QFormLayout
import json
import hashlib
from PyQt6.QtCore import QTimer
import sys
import os
import shutil
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QSlider, QFileDialog, QStyle, QListWidget, QMessageBox
)
from PyQt6.QtMultimedia import QMediaPlayer, QAudioOutput
from PyQt6.QtMultimediaWidgets import QVideoWidget
from PyQt6.QtCore import Qt, QUrl

def hash_password(password: str) -> str:
    """Restituisce hash SHA256 della password"""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def load_users(file_path: str) -> dict:
    """Carica utenti dal file JSON"""
    if not os.path.exists(file_path):
        return {}
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_users(file_path: str, users: dict):
    """Salva utenti su file JSON"""
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=4)


class LoginDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Login")
        self.setFixedSize(300, 200)

        self.users_file = os.path.join(
            os.path.abspath(os.path.dirname(__file__)),
            "users.json"
        )

        # Carica utenti
        self.users = load_users(self.users_file)

        # Se non esiste nessun utente, ne creiamo uno di default
        if not self.users:
            self.users["admin"] = hash_password("1234")
            save_users(self.users_file, self.users)

        self.attempts = 0
        self.locked = False

        layout = QVBoxLayout(self)

        form = QFormLayout()
        self.username_edit = QLineEdit()
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)

        form.addRow("Username:", self.username_edit)
        form.addRow("Password:", self.password_edit)
        layout.addLayout(form)

        self.info_label = QLabel("")
        self.info_label.setStyleSheet("color: red;")
        layout.addWidget(self.info_label)

        self.login_button = QPushButton("Accedi")
        self.login_button.clicked.connect(self.check_login)
        layout.addWidget(self.login_button)

        self.lock_timer = QTimer(self)
        self.lock_timer.setSingleShot(True)
        self.lock_timer.timeout.connect(self.unlock)

    def check_login(self):
        if self.locked:
            return

        username = self.username_edit.text().strip()
        password = self.password_edit.text()

        if username in self.users:
            if hash_password(password) == self.users[username]:
                self.accept()
                return

        self.attempts += 1
        self.info_label.setText(f"Credenziali errate ({self.attempts}/3)")

        if self.attempts >= 3:
            self.lock()

    def lock(self):
        self.locked = True
        self.login_button.setEnabled(False)
        self.info_label.setText("Troppi tentativi. Bloccato per 30 secondi.")
        self.lock_timer.start(30000)

    def unlock(self):
        self.locked = False
        self.attempts = 0
        self.login_button.setEnabled(True)
        self.info_label.setText("")


class DualMediaPlayer(QWidget):
    """
    Media player per audio e video in stile moderno con colori sobri.
    Salva i file nelle cartelle dedicate e riproduce playlist.
    """
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Glass Media Player")
        self.resize(1200, 650)

        # --- Stile generale ---
        self.setStyleSheet("""
            QWidget {
                background-color: #ECECEC;  /* colore chiaro di sfondo */
                color: #222222;  /* testo scuro */
                font-family: 'Segoe UI', sans-serif;
            }
            QPushButton {
                background-color: #DDDDDD;  /* pulsanti chiari */
                border: 1px solid #AAAAAA;
                border-radius: 6px;
                padding: 5px 12px;
            }
            QPushButton:hover {
                background-color: #CCCCCC;
            }
            QSlider::groove:horizontal {
                height: 6px;
                background: #BBBBBB;
                border-radius: 3px;
            }
            QSlider::handle:horizontal {
                background: #555555;
                width: 14px;
                border-radius: 7px;
            }
            QListWidget {
                background-color: #F5F5F5;
                border: 1px solid #CCCCCC;
                border-radius: 6px;
            }
            QLabel {
                font-weight: bold;
                font-size: 14px;
            }
        """)

        # --- Directory dei media ---
        self.base_dir = os.path.abspath(os.path.dirname(__file__))
        self.audio_dir = os.path.join(self.base_dir, "audio_files")
        self.video_dir = os.path.join(self.base_dir, "video_files")
        os.makedirs(self.audio_dir, exist_ok=True)
        os.makedirs(self.video_dir, exist_ok=True)

        # --- Player video ---
        self.video_player = QMediaPlayer(self)
        self.video_audio_output = QAudioOutput(self)
        self.video_player.setAudioOutput(self.video_audio_output)
        self.video_widget = QVideoWidget(self)
        self.video_player.setVideoOutput(self.video_widget)

        # --- Player audio ---
        self.audio_player = QMediaPlayer(self)
        self.audio_audio_output = QAudioOutput(self)
        self.audio_player.setAudioOutput(self.audio_audio_output)

        # --- Playlist e indici ---
        self.audio_playlist = []
        self.audio_index = -1
        self.video_playlist = []
        self.video_index = -1

        # --- Layout principale ---
        main_layout = QHBoxLayout()
        self.setLayout(main_layout)

        # ---------------- Video layout ----------------
        video_layout = QVBoxLayout()
        main_layout.addLayout(video_layout, 2)

        # Widget video
        video_layout.addWidget(self.video_widget, stretch=5)

        # Label video
        self.label_video = QLabel("Nessun video selezionato")
        video_layout.addWidget(self.label_video)

        # Controlli video
        video_controls = QHBoxLayout()
        video_layout.addLayout(video_controls)

        self.btn_load_video = QPushButton("Carica Video")
        self.btn_prev_video = QPushButton("⏮")
        self.btn_play_video = QPushButton()
        self.btn_play_video.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MediaPlay))
        self.btn_stop_video = QPushButton()
        self.btn_stop_video.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MediaStop))
        self.btn_next_video = QPushButton("⏭")
        self.volume_slider_video = QSlider(Qt.Orientation.Horizontal)
        self.volume_slider_video.setRange(0, 100)
        self.volume_slider_video.setValue(70)
        self.volume_slider_video.setFixedWidth(120)

        for w in [self.btn_load_video, self.btn_prev_video, self.btn_play_video,
                  self.btn_stop_video, self.btn_next_video, QLabel("Volume"), self.volume_slider_video]:
            video_controls.addWidget(w)

        # Slider posizione video
        self.position_slider_video = QSlider(Qt.Orientation.Horizontal)
        self.position_slider_video.setRange(0, 0)
        video_layout.addWidget(self.position_slider_video)

        # Lista video
        self.video_list = QListWidget()
        video_layout.addWidget(self.video_list, stretch=3)

        # ---------------- Audio layout ----------------
        audio_layout = QVBoxLayout()
        main_layout.addLayout(audio_layout, 1)

        # Label audio
        self.label_audio = QLabel("Nessun audio selezionato")
        audio_layout.addWidget(self.label_audio)

        # Controlli audio
        audio_controls = QHBoxLayout()
        audio_layout.addLayout(audio_controls)

        self.btn_load_audio = QPushButton("Carica Audio")
        self.btn_prev_audio = QPushButton("⏮")
        self.btn_play_audio = QPushButton()
        self.btn_play_audio.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MediaPlay))
        self.btn_stop_audio = QPushButton()
        self.btn_stop_audio.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MediaStop))
        self.btn_next_audio = QPushButton("⏭")
        self.volume_slider_audio = QSlider(Qt.Orientation.Horizontal)
        self.volume_slider_audio.setRange(0, 100)
        self.volume_slider_audio.setValue(70)
        self.volume_slider_audio.setFixedWidth(120)

        for w in [self.btn_load_audio, self.btn_prev_audio, self.btn_play_audio,
                  self.btn_stop_audio, self.btn_next_audio, QLabel("Volume"), self.volume_slider_audio]:
            audio_controls.addWidget(w)

        # Slider posizione audio
        self.position_slider_audio = QSlider(Qt.Orientation.Horizontal)
        self.position_slider_audio.setRange(0, 0)
        audio_layout.addWidget(self.position_slider_audio)

        # Lista audio
        self.audio_list = QListWidget()
        audio_layout.addWidget(self.audio_list, stretch=3)

        # --- Connessioni segnali video ---
        self.btn_load_video.clicked.connect(self.load_video_files)
        self.btn_play_video.clicked.connect(self.play_pause_video)
        self.btn_stop_video.clicked.connect(self.stop_video)
        self.btn_prev_video.clicked.connect(self.prev_video)
        self.btn_next_video.clicked.connect(self.next_video)
        self.volume_slider_video.valueChanged.connect(lambda v: self.video_audio_output.setVolume(v / 100))
        self.position_slider_video.sliderMoved.connect(self.set_position_video)
        self.video_player.positionChanged.connect(self.position_changed_video)
        self.video_player.durationChanged.connect(self.duration_changed_video)
        self.video_player.mediaStatusChanged.connect(self.media_status_changed_video)
        self.video_list.itemDoubleClicked.connect(self.video_item_double_clicked)

        # --- Connessioni segnali audio ---
        self.btn_load_audio.clicked.connect(self.load_audio_files)
        self.btn_play_audio.clicked.connect(self.play_pause_audio)
        self.btn_stop_audio.clicked.connect(self.stop_audio)
        self.btn_prev_audio.clicked.connect(self.prev_audio)
        self.btn_next_audio.clicked.connect(self.next_audio)
        self.volume_slider_audio.valueChanged.connect(lambda v: self.audio_audio_output.setVolume(v / 100))
        self.position_slider_audio.sliderMoved.connect(self.set_position_audio)
        self.audio_player.positionChanged.connect(self.position_changed_audio)
        self.audio_player.durationChanged.connect(self.duration_changed_audio)
        self.audio_player.mediaStatusChanged.connect(self.media_status_changed_audio)
        self.audio_list.itemDoubleClicked.connect(self.audio_item_double_clicked)

        # Volume iniziale
        self.video_audio_output.setVolume(0.7)
        self.audio_audio_output.setVolume(0.7)

    # ---------------- Funzioni Video ----------------
    def load_video_files(self):
        """Carica video dalla cartella dedicata"""
        files, _ = QFileDialog.getOpenFileNames(self, "Seleziona video", self.video_dir,
                                                "Video (*.mp4 *.avi *.mkv *.mov)")
        for f in files:
            dest = os.path.join(self.video_dir, os.path.basename(f))
            if not os.path.exists(dest):
                shutil.copy(f, dest)
            if dest not in self.video_playlist:
                self.video_playlist.append(dest)
                self.video_list.addItem(os.path.basename(dest))
        if self.video_index == -1 and self.video_playlist:
            self.video_index = 0
            self.load_video()

    def load_video(self):
        """Carica il video selezionato dalla playlist"""
        if 0 <= self.video_index < len(self.video_playlist):
            path = self.video_playlist[self.video_index]
            self.video_player.setSource(QUrl.fromLocalFile(path))
            self.label_video.setText(f"Video: {os.path.basename(path)}")
            self.video_list.setCurrentRow(self.video_index)
            self.video_player.play()
            self.btn_play_video.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MediaPause))

    def play_pause_video(self):
        """Play / Pause video"""
        if self.video_player.playbackState() == QMediaPlayer.PlaybackState.PlayingState:
            self.video_player.pause()
            self.btn_play_video.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MediaPlay))
        else:
            self.video_player.play()
            self.btn_play_video.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MediaPause))

    def stop_video(self):
        """Stop video"""
        self.video_player.stop()
        self.btn_play_video.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MediaPlay))

    def prev_video(self):
        """Video precedente"""
        if self.video_index > 0:
            self.video_index -= 1
            self.load_video()

    def next_video(self):
        """Video successivo"""
        if self.video_index < len(self.video_playlist) - 1:
            self.video_index += 1
            self.load_video()

    def position_changed_video(self, pos):
        self.position_slider_video.setValue(pos)

    def duration_changed_video(self, dur):
        self.position_slider_video.setRange(0, dur)

    def set_position_video(self, pos):
        self.video_player.setPosition(pos)

    def media_status_changed_video(self, status):
        if status == QMediaPlayer.MediaStatus.EndOfMedia:
            self.next_video()

    def video_item_double_clicked(self, item):
        self.video_index = self.video_list.row(item)
        self.load_video()

    # ---------------- Funzioni Audio ----------------
    def load_audio_files(self):
        """Carica audio dalla cartella dedicata"""
        files, _ = QFileDialog.getOpenFileNames(self, "Seleziona audio", self.audio_dir,
                                                "Audio (*.mp3 *.wav *.ogg)")
        for f in files:
            dest = os.path.join(self.audio_dir, os.path.basename(f))
            if not os.path.exists(dest):
                shutil.copy(f, dest)
            if dest not in self.audio_playlist:
                self.audio_playlist.append(dest)
                self.audio_list.addItem(os.path.basename(dest))
        if self.audio_index == -1 and self.audio_playlist:
            self.audio_index = 0
            self.load_audio()

    def load_audio(self):
        """Carica l'audio selezionato dalla playlist"""
        if 0 <= self.audio_index < len(self.audio_playlist):
            path = self.audio_playlist[self.audio_index]
            self.audio_player.setSource(QUrl.fromLocalFile(path))
            self.label_audio.setText(f"Audio: {os.path.basename(path)}")
            self.audio_list.setCurrentRow(self.audio_index)
            self.audio_player.play()
            self.btn_play_audio.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MediaPause))

    def play_pause_audio(self):
        """Play / Pause audio"""
        if self.audio_player.playbackState() == QMediaPlayer.PlaybackState.PlayingState:
            self.audio_player.pause()
            self.btn_play_audio.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MediaPlay))
        else:
            self.audio_player.play()
            self.btn_play_audio.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MediaPause))

    def stop_audio(self):
        """Stop audio"""
        self.audio_player.stop()
        self.btn_play_audio.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MediaPlay))

    def prev_audio(self):
        """Audio precedente"""
        if self.audio_index > 0:
            self.audio_index -= 1
            self.load_audio()

    def next_audio(self):
        """Audio successivo"""
        if self.audio_index < len(self.audio_playlist) - 1:
            self.audio_index += 1
            self.load_audio()

    def position_changed_audio(self, pos):
        self.position_slider_audio.setValue(pos)

    def duration_changed_audio(self, dur):
        self.position_slider_audio.setRange(0, dur)

    def set_position_audio(self, pos):
        self.audio_player.setPosition(pos)

    def media_status_changed_audio(self, status):
        if status == QMediaPlayer.MediaStatus.EndOfMedia:
            self.next_audio()

    def audio_item_double_clicked(self, item):
        self.audio_index = self.audio_list.row(item)
        self.load_audio()


    if __name__ == "__main__":
        app = QApplication(sys.argv)

        login = LoginDialog()
        if login.exec() == QDialog.DialogCode.Accepted:
            player = DualMediaPlayer()
            player.show()
            sys.exit(app.exec())
        else:
            sys.exit()
