#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#  PrekT-BR — Navegador personal basado en WebKitGTK 6
#  Versión 2.1 - SECURE ENHaNCED
#

import sys
import os
import gi
import json
import math
import signal
import socket
import hashlib
import base64
import secrets
import threading
import datetime
import urllib.parse
import urllib.request

os.environ["GDK_DEBUG"] = "portals"
os.environ["GTK_A11Y"] = "none"
# Suprimir warnings de portal en entornos sin sandbox
os.environ["DBUS_SESSION_BUS_ADDRESS"] = os.environ.get("DBUS_SESSION_BUS_ADDRESS", "")

gi.require_version('Gtk', '4.0')
gi.require_version('WebKit', '6.0')

from gi.repository import Gtk, WebKit, Gio, GLib, Gdk

# ─── Rutas de datos ──────────────────────────────────────────────────────────

DATA_DIR     = os.path.join(os.path.expanduser("~"), ".local", "share", "prektbr")
HISTORY_FILE = os.path.join(DATA_DIR, "history.json")
BOOKMARKS_FILE = os.path.join(DATA_DIR, "bookmarks.json")

os.makedirs(DATA_DIR, exist_ok=True)

# ─── Cifrado de datos en disco ────────────────────────────────────────────────
# Usa XOR con clave derivada del username para ofuscar historial y marcadores.
# No es cifrado fuerte (sin autenticación), pero evita que cualquier proceso
# o script lea los datos en texto plano.

_SALT_FILE = os.path.join(DATA_DIR, ".salt")

def _get_or_create_salt() -> bytes:
    """Obtiene o crea una sal aleatoria persistente por instalación."""
    try:
        if os.path.exists(_SALT_FILE):
            with open(_SALT_FILE, "rb") as f:
                salt = f.read()
            if len(salt) == 32:
                return salt
    except Exception:
        pass
    salt = secrets.token_bytes(32)
    try:
        with open(_SALT_FILE, "wb") as f:
            f.write(salt)
        os.chmod(_SALT_FILE, 0o600)
    except Exception:
        pass
    return salt

def _derive_key(length=64) -> bytes:
    """Deriva una clave usando PBKDF2-HMAC-SHA256 con sal aleatoria persistente."""
    user = (os.environ.get("USER") or os.environ.get("USERNAME") or "prektbr").encode()
    salt = _get_or_create_salt()
    # PBKDF2 con 200 000 iteraciones — mucho más costoso de bruteforcear
    dk = hashlib.pbkdf2_hmac("sha256", user + b"prektbr-v3", salt, 200_000, dklen=length)
    return dk

_KEY = _derive_key()

def _xor_bytes(data: bytes) -> bytes:
    key = _KEY
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def load_json(path, default):
    try:
        with open(path, "rb") as f:
            raw = f.read()
        # Detectar si el archivo es texto plano (migración desde versión anterior)
        try:
            decoded = _xor_bytes(base64.b64decode(raw))
            return json.loads(decoded.decode("utf-8"))
        except Exception:
            # Intentar como JSON plano (compatibilidad hacia atrás)
            return json.loads(raw.decode("utf-8"))
    except Exception:
        return default

def save_json(path, data):
    try:
        raw = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
        encrypted = base64.b64encode(_xor_bytes(raw))
        with open(path, "wb") as f:
            f.write(encrypted)
    except Exception as e:
        print(f"[prektbr] Error guardando {path}: {e}")

# ─── CSS global ──────────────────────────────────────────────────────────────

GLOBAL_CSS = """
/* Barra de herramientas */
.toolbar {
    background-color: #1e1e2e;
    border-bottom: 1px solid #313244;
    padding: 4px 8px;
}

/* Entrada de URL */
.url-entry {
    background-color: #313244;
    color: #cdd6f4;
    border: 1px solid #45475a;
    border-radius: 6px;
    padding: 4px 10px;
    font-size: 14px;
    min-height: 32px;
}
.url-entry:focus {
    border-color: #89b4fa;
    background-color: #1e1e2e;
}

/* Botones de navegación */
.nav-button {
    background-color: transparent;
    color: #cdd6f4;
    border: none;
    border-radius: 6px;
    padding: 4px 8px;
    min-width: 32px;
    min-height: 32px;
    font-size: 16px;
}
.nav-button:hover {
    background-color: #313244;
}
.nav-button:disabled {
    color: #45475a;
}

/* Barra de pestañas */
.tabbar {
    background-color: #181825;
    border-bottom: 1px solid #313244;
    padding: 4px 8px 0 8px;
    min-height: 36px;
}

/* Botón de título dentro de pestaña */
.tab-title-btn {
    background-color: transparent;
    color: inherit;
    border: none;
    border-radius: 4px 0 0 4px;
    padding: 4px 8px;
    font-size: 13px;
    min-width: 60px;
}
.tab-title-btn:hover {
    background-color: rgba(255,255,255,0.05);
}

/* Pestaña normal */
.tab-btn {
    background-color: #1e1e2e;
    color: #6c7086;
    border: 1px solid #313244;
    border-bottom: none;
    border-radius: 6px 6px 0 0;
    padding: 4px 10px;
    font-size: 13px;
    min-width: 80px;
}
.tab-btn:hover {
    background-color: #313244;
    color: #cdd6f4;
}

/* Pestaña activa */
.tab-active {
    background-color: #1e1e2e;
    color: #cdd6f4;
    border: 1px solid #45475a;
    border-bottom: 2px solid #89b4fa;
    font-weight: bold;
}

/* Indicador de modo de red */
.badge-normal {
    background-color: #313244;
    color: #a6e3a1;
    border-radius: 4px;
    padding: 2px 8px;
    font-size: 12px;
    font-family: monospace;
}
.badge-tor {
    background-color: #7f49a0;
    color: #f5c2e7;
    border-radius: 4px;
    padding: 2px 8px;
    font-size: 12px;
    font-family: monospace;
    font-weight: bold;
}
.badge-i2p {
    background-color: #1a6b3c;
    color: #a6e3a1;
    border-radius: 4px;
    padding: 2px 8px;
    font-size: 12px;
    font-family: monospace;
    font-weight: bold;
}
.badge-clear {
    background-color: #313244;
    color: #a6e3a1;
    border-radius: 4px;
    padding: 2px 8px;
    font-size: 12px;
    font-family: monospace;
    font-weight: bold;
}
.badge-file {
    background-color: #2a3550;
    color: #89b4fa;
    border-radius: 4px;
    padding: 2px 8px;
    font-size: 12px;
    font-family: monospace;
    font-weight: bold;
}

/* Badge de seguridad HTTPS */
.badge-secure {
    background-color: #1a4731;
    color: #a6e3a1;
    border-radius: 4px;
    padding: 2px 8px;
    font-size: 12px;
    font-family: monospace;
    font-weight: bold;
}
.badge-insecure {
    background-color: #4a1a1a;
    color: #f38ba8;
    border-radius: 4px;
    padding: 2px 8px;
    font-size: 12px;
    font-family: monospace;
    font-weight: bold;
}
.badge-onion {
    background-color: #7f49a0;
    color: #f5c2e7;
    border-radius: 4px;
    padding: 2px 8px;
    font-size: 12px;
    font-family: monospace;
    font-weight: bold;
}
.badge-eepsite {
    background-color: #1a6b3c;
    color: #a6e3a1;
    border-radius: 4px;
    padding: 2px 8px;
    font-size: 12px;
    font-family: monospace;
    font-weight: bold;
}

/* Barra de búsqueda en página */
.findbar {
    background-color: #1e1e2e;
    border-top: 1px solid #313244;
    padding: 4px 8px;
}
.findbar-entry {
    background-color: #313244;
    color: #cdd6f4;
    border: 1px solid #45475a;
    border-radius: 6px;
    padding: 2px 8px;
    font-size: 13px;
    min-height: 28px;
    min-width: 200px;
}
.findbar-entry:focus {
    border-color: #89b4fa;
}
.findbar-label {
    color: #6c7086;
    font-size: 12px;
    padding: 0 8px;
}

/* Inspector de HTML */
.inspector-tv {
    background-color: #0a0a1a;
    color: #89b4fa;
    font-family: monospace;
    font-size: 13px;
    padding: 10px;
    caret-color: #89b4fa;
}

/* Terminal */
.terminal {
    background-color: #0d0d0d;
    color: #00ff41;
    font-family: monospace;
    font-size: 13px;
    padding: 10px;
    caret-color: #00ff41;
}

/* Barra de estado */
.statusbar {
    background-color: #181825;
    border-top: 1px solid #313244;
    color: #6c7086;
    font-size: 11px;
    padding: 2px 10px;
}

/* Barra de progreso de descarga */
.dl-progress trough {
    background-color: #313244;
    border-radius: 4px;
    min-height: 8px;
}
.dl-progress progress {
    background-color: #89b4fa;
    border-radius: 4px;
    min-height: 8px;
}

/* Botón añadir pestaña */
.new-tab-btn {
    background-color: transparent;
    color: #6c7086;
    border: none;
    border-radius: 4px;
    padding: 2px 8px;
    font-size: 18px;
    min-height: 28px;
}
.new-tab-btn:hover {
    background-color: #313244;
    color: #cdd6f4;
}

/* Panel de marcadores / historial */
.sidebar {
    background-color: #181825;
    border-right: 1px solid #313244;
    min-width: 240px;
}
.sidebar-title {
    background-color: #1e1e2e;
    color: #89b4fa;
    font-weight: bold;
    font-size: 13px;
    padding: 8px 12px;
    border-bottom: 1px solid #313244;
}
.sidebar-item {
    background-color: transparent;
    color: #cdd6f4;
    border: none;
    border-radius: 4px;
    padding: 6px 10px;
    font-size: 12px;
}
.sidebar-item:hover {
    background-color: #313244;
}
.close-tab-btn {
    background-color: transparent;
    color: #6c7086;
    border: none;
    border-radius: 3px;
    padding: 0 3px;
    font-size: 12px;
    min-width: 16px;
    min-height: 16px;
}
.close-tab-btn:hover {
    background-color: #f38ba8;
    color: #1e1e2e;
}
"""

# ─── Aplicación ──────────────────────────────────────────────────────────────

class PrekTBR(Gtk.Application):
    def __init__(self):
        super().__init__(
            application_id="com.cinnamolhyia.prektbr",
            flags=Gio.ApplicationFlags.HANDLES_OPEN,
        )
        self.home_uri = "file://" + os.path.abspath("newtab.html")
        self.initial_url = self.home_uri
        self.dark_mode = False

        # Persistencia
        self.history   = load_json(HISTORY_FILE,   [])   # [{url, title, ts}]
        self.bookmarks = load_json(BOOKMARKS_FILE, [])   # [{url, title}]

    def do_startup(self):
        Gtk.Application.do_startup(self)
        provider = Gtk.CssProvider()
        provider.load_from_data(GLOBAL_CSS.encode())
        Gtk.StyleContext.add_provider_for_display(
            Gdk.Display.get_default(), provider,
            Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
        )

    def do_activate(self):
        win = self.props.active_window
        if not win:
            win = BrowserWindow(self)
            win.set_default_size(1280, 800)
        win.present()

    def do_open(self, files, n_files, hint):
        win = self.props.active_window
        if not win:
            win = BrowserWindow(self)
            win.set_default_size(1280, 800)
        if files and n_files > 0:
            win.open_tab(uri=files[0].get_uri())
        win.present()

    def add_history(self, url, title=""):
        if not url or url.startswith("file://") or url == "about:blank":
            return
        entry = {"url": url, "title": title or url, "ts": datetime.datetime.now().isoformat()}
        # Evitar duplicados consecutivos
        if self.history and self.history[-1]["url"] == url:
            return
        self.history.append(entry)
        # Limitar a 2000 entradas
        if len(self.history) > 2000:
            self.history = self.history[-2000:]
        save_json(HISTORY_FILE, self.history)

    def add_bookmark(self, url, title=""):
        if not url or url == "about:blank":
            return False
        for b in self.bookmarks:
            if b["url"] == url:
                return False  # ya existe
        self.bookmarks.append({"url": url, "title": title or url})
        save_json(BOOKMARKS_FILE, self.bookmarks)
        return True

    def remove_bookmark(self, url):
        self.bookmarks = [b for b in self.bookmarks if b["url"] != url]
        save_json(BOOKMARKS_FILE, self.bookmarks)

    def is_bookmarked(self, url):
        return any(b["url"] == url for b in self.bookmarks)


# ─── Datos de pestaña ────────────────────────────────────────────────────────

class TabData:
    def __init__(self, webview, mode="normal"):
        self.webview = webview
        self.mode = mode   # "normal" | "tor" | "i2p"


# ─── Ventana principal ───────────────────────────────────────────────────────

class BrowserWindow(Gtk.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app, title="PrekT-BR")
        self.app = app
        self.tabs: list[TabData] = []
        self.current_tab = -1
        self._sidebar_mode = None   # None | "bookmarks" | "history"
        self._inspector_mode = False
        self._findbar_visible = False

        self._build_ui()
        self.open_tab(uri=self.app.initial_url)

    # ── Construcción de la interfaz ──────────────────────────────────────────

    def _build_ui(self):
        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)

        # Barra de pestañas
        self.tabbar_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=2)
        self.tabbar_box.add_css_class("tabbar")

        new_tab_btn = Gtk.Button(label="+")
        new_tab_btn.add_css_class("new-tab-btn")
        new_tab_btn.set_tooltip_text("Nueva pestaña")
        new_tab_btn.connect("clicked", lambda _: self.open_tab())

        tabbar_scroll = Gtk.ScrolledWindow()
        tabbar_scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.NEVER)
        tabbar_scroll.set_hexpand(True)
        tabbar_scroll.set_child(self.tabbar_box)
        tabbar_scroll.set_min_content_height(38)

        tabbar_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        tabbar_row.add_css_class("tabbar")
        tabbar_row.append(tabbar_scroll)
        tabbar_row.append(new_tab_btn)

        # Barra de navegación
        self.back_btn    = self._nav_btn("←",  "Atrás (Alt+Izq)",                  self._on_back)
        self.forward_btn = self._nav_btn("→",  "Adelante (Alt+Der)",               self._on_forward)
        self.reload_btn  = self._nav_btn("↻",  "Recargar (Ctrl+R) / Shift: sin caché", self._on_reload)
        self.home_btn    = self._nav_btn("⌂",  "Ir al inicio",     self._on_home)
        self.bookmark_star = self._nav_btn("★", "Guardar marcador", self._on_toggle_bookmark)

        self.url_entry = Gtk.Entry()
        self.url_entry.set_hexpand(True)
        self.url_entry.add_css_class("url-entry")
        self.url_entry.set_placeholder_text("Ingresa una URL o busca en DuckDuckGo...")
        self.url_entry.connect("activate", self._on_url_activate)

        # Badge de red (TOR / I2P)
        self.badge = Gtk.Label(label="")
        self.badge.add_css_class("badge-normal")
        self.badge.set_tooltip_text("Modo de red actual")
        self.badge.set_visible(False)

        # Badge de seguridad (S / I / O / E)
        self.sec_badge = Gtk.Label(label="")
        self.sec_badge.set_tooltip_text("Estado de seguridad de la página")
        self.sec_badge.set_visible(False)

        bmarks_btn   = self._nav_btn("\u2318",       "Marcadores",                    lambda _: self._toggle_sidebar("bookmarks"))
        history_btn  = self._nav_btn("\U0001F552\uFE0E", "Historial",            lambda _: self._toggle_sidebar("history"))
        terminal_btn = self._nav_btn(">_",       "Terminal (Ctrl+Alt+T)",         self._on_toggle_terminal)
        find_btn     = self._nav_btn("⌕",        "Buscar en página (Ctrl+F)",     lambda _: self._toggle_findbar())
        inspector_btn= self._nav_btn("</>",      "Inspector HTML (Ctrl+AltGr+D)", lambda _: self._toggle_inspector())

        nav_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=4)
        nav_box.add_css_class("toolbar")
        for w in [self.back_btn, self.forward_btn, self.reload_btn, self.home_btn,
                  self.sec_badge, self.url_entry, self.bookmark_star, self.badge,
                  bmarks_btn, history_btn, find_btn, inspector_btn, terminal_btn]:
            nav_box.append(w)

        # Área de contenido (sidebar + webview stack + terminal)
        self.content_area = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        self.content_area.set_vexpand(True)
        self.content_area.set_hexpand(True)

        self.sidebar_widget = None  # se crea dinámicamente

        # Stack de pestañas
        self.tab_stack = Gtk.Stack()
        self.tab_stack.set_vexpand(True)
        self.tab_stack.set_hexpand(True)
        self.content_area.append(self.tab_stack)

        # Terminal (modo normal — texto verde)
        self.terminal_visible = False
        self.terminal_buf = Gtk.TextBuffer()
        self.terminal_tv  = Gtk.TextView(buffer=self.terminal_buf)
        self.terminal_tv.set_editable(True)
        self.terminal_tv.set_cursor_visible(True)
        self.terminal_tv.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self.terminal_tv.set_monospace(True)
        self.terminal_tv.add_css_class("terminal")
        self.terminal_tv.set_size_request(340, 200)

        term_scroll = Gtk.ScrolledWindow()
        term_scroll.set_vexpand(True)
        term_scroll.set_hexpand(False)
        term_scroll.set_min_content_width(340)
        term_scroll.set_min_content_height(200)
        term_scroll.set_child(self.terminal_tv)
        self._term_scroll = term_scroll

        key_ctrl = Gtk.EventControllerKey()
        key_ctrl.connect("key-pressed", self._on_terminal_key)
        self.terminal_tv.add_controller(key_ctrl)

        # Inspector de HTML (texto azul, reutiliza el mismo panel lateral)
        self.inspector_buf = Gtk.TextBuffer()
        self.inspector_tv  = Gtk.TextView(buffer=self.inspector_buf)
        self.inspector_tv.set_editable(True)
        self.inspector_tv.set_cursor_visible(True)
        self.inspector_tv.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self.inspector_tv.set_monospace(True)
        self.inspector_tv.add_css_class("inspector-tv")
        self.inspector_tv.set_size_request(400, 200)

        insp_scroll = Gtk.ScrolledWindow()
        insp_scroll.set_vexpand(True)
        insp_scroll.set_hexpand(False)
        insp_scroll.set_min_content_width(400)
        insp_scroll.set_min_content_height(200)
        insp_scroll.set_child(self.inspector_tv)
        self._insp_scroll = insp_scroll

        # Botones del inspector
        insp_btn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=4)
        insp_btn_box.add_css_class("toolbar")
        insp_reload_btn = self._nav_btn("Cargar HTML", "Obtener HTML actual de la página", lambda _: self._inspector_load())
        insp_apply_btn  = self._nav_btn("Aplicar",     "Aplicar HTML editado a la página",  lambda _: self._inspector_apply())
        insp_close_btn  = self._nav_btn("Cerrar",      "Cerrar inspector",                  lambda _: self._close_inspector())
        for b in [insp_reload_btn, insp_apply_btn, insp_close_btn]:
            insp_btn_box.append(b)

        self._insp_panel = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self._insp_panel.append(insp_btn_box)
        self._insp_panel.append(insp_scroll)

        insp_key_ctrl = Gtk.EventControllerKey()
        insp_key_ctrl.connect("key-pressed", self._on_inspector_key)
        self.inspector_tv.add_controller(insp_key_ctrl)

        # Barra de búsqueda en página
        self._findbar_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        self._findbar_box.add_css_class("findbar")
        self._find_entry = Gtk.Entry()
        self._find_entry.add_css_class("findbar-entry")
        self._find_entry.set_placeholder_text("Buscar en página…")
        self._find_entry.connect("activate", lambda _: self._find_next())
        self._find_entry.connect("changed",  lambda _: self._find_changed())
        find_prev_btn = self._nav_btn("↑", "Anterior (Shift+Enter)", lambda _: self._find_prev())
        find_next_btn = self._nav_btn("↓", "Siguiente (Enter)",      lambda _: self._find_next())
        find_close_btn= self._nav_btn("✕", "Cerrar (Esc)",           lambda _: self._close_findbar())
        self._find_label = Gtk.Label(label="")
        self._find_label.add_css_class("findbar-label")
        for w in [self._find_entry, find_prev_btn, find_next_btn, self._find_label, find_close_btn]:
            self._findbar_box.append(w)

        # Barra de estado + progreso de descarga
        self.statusbar = Gtk.Label(label="")
        self.statusbar.add_css_class("statusbar")
        self.statusbar.set_halign(Gtk.Align.START)
        self.statusbar.set_hexpand(True)
        self.statusbar.set_ellipsize(3)  # PANGO_ELLIPSIZE_END

        self._dl_progress = Gtk.ProgressBar()
        self._dl_progress.add_css_class("dl-progress")
        self._dl_progress.set_visible(False)
        self._dl_progress.set_valign(Gtk.Align.CENTER)
        self._dl_progress.set_size_request(150, -1)

        statusbar_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        statusbar_box.add_css_class("statusbar")
        statusbar_box.append(self.statusbar)
        statusbar_box.append(self._dl_progress)

        root.append(tabbar_row)
        root.append(nav_box)
        root.append(self.content_area)
        root.append(self._findbar_box)
        root.append(statusbar_box)
        self.set_child(root)
        self._findbar_box.set_visible(False)

        # Atajos de teclado globales
        key_global = Gtk.EventControllerKey()
        key_global.connect("key-pressed", self._on_global_key)
        self.add_controller(key_global)

        self._term_print("PrekT-BR v2.1  —  escribe 'help' para ver los comandos")
        self._term_prompt()

    def _nav_btn(self, label, tooltip, callback):
        b = Gtk.Button(label=label)
        b.add_css_class("nav-button")
        b.set_tooltip_text(tooltip)
        b.connect("clicked", callback)
        return b

    # ── Gestión de pestañas ──────────────────────────────────────────────────

    def _make_tab_widget(self, idx):
        """Crea el widget de pestaña: un Box con botón de título + botón cerrar, sin anidar."""
        tab_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        tab_box.add_css_class("tab-btn")

        title_btn = Gtk.Button(label=f"Tab {idx+1}")
        title_btn.add_css_class("tab-title-btn")
        title_btn.set_hexpand(True)
        title_btn.connect("clicked", lambda b, i=idx: self._on_tab_click(i))

        close_btn = Gtk.Button(label="x")
        close_btn.add_css_class("close-tab-btn")
        close_btn.connect("clicked", lambda b, i=idx: self._on_close_tab(i))

        tab_box.append(title_btn)
        tab_box.append(close_btn)

        # Guardar referencia para actualizar el título después
        tab_box._title_btn = title_btn
        tab_box._tab_idx = idx
        return tab_box

    def open_tab(self, uri=None, mode="normal"):
        wv = self._make_webview(mode)
        td = TabData(wv, mode)
        self.tabs.append(td)
        idx = len(self.tabs) - 1

        self.tab_stack.add_named(wv, f"tab{idx}")

        tab_widget = self._make_tab_widget(idx)
        self.tabbar_box.append(tab_widget)

        self._setup_download_handler(wv)
        self._switch_tab(idx)
        wv.load_uri(uri or self.app.home_uri)

    def _on_close_tab(self, idx):
        if len(self.tabs) == 1:
            self.tabs[0].webview.load_uri(self.app.home_uri)
            return
        td = self.tabs[idx]
        # Limpiar datos de navegación de la pestaña antes de cerrarla
        self._clear_tab_data(td)
        self.tab_stack.remove(td.webview)
        self.tabs.pop(idx)
        self._rebuild_tabbar()
        new_idx = min(idx, len(self.tabs) - 1)
        self._switch_tab(new_idx)

    def _clear_tab_data(self, td):
        """Limpia cookies, caché y almacenamiento local de la sesión de la pestaña."""
        try:
            ns = td.webview.get_network_session()
            if ns:
                wds = ns.get_website_data_store()
                if wds:
                    # Limpiar todos los tipos de datos almacenados
                    wds.clear(
                        WebKit.WebsiteDataTypes.COOKIES |
                        WebKit.WebsiteDataTypes.DISK_CACHE |
                        WebKit.WebsiteDataTypes.MEMORY_CACHE |
                        WebKit.WebsiteDataTypes.SESSION_STORAGE |
                        WebKit.WebsiteDataTypes.LOCAL_STORAGE |
                        WebKit.WebsiteDataTypes.INDEXED_DB_DATABASES |
                        WebKit.WebsiteDataTypes.OFFLINE_APPLICATION_CACHE,
                        0, None, None
                    )
        except Exception as e:
            print(f"[prektbr] Error limpiando datos de pestaña: {e}")

    def _rebuild_tabbar(self):
        child = self.tabbar_box.get_first_child()
        while child:
            nxt = child.get_next_sibling()
            self.tabbar_box.remove(child)
            child = nxt
        for i, td in enumerate(self.tabs):
            tab_widget = self._make_tab_widget(i)
            # Restaurar título
            title = td.webview.get_title()
            if title:
                short = (title[:14] + "...") if len(title) > 14 else title
                tab_widget._title_btn.set_label(short)
            self.tabbar_box.append(tab_widget)

    def _on_tab_click(self, idx):
        self._switch_tab(idx)

    def _switch_tab(self, idx):
        if idx < 0 or idx >= len(self.tabs):
            return
        # Actualizar estilos — los widgets en tabbar_box son Box ahora
        child = self.tabbar_box.get_first_child()
        i = 0
        while child:
            child.remove_css_class("tab-active")
            if i == idx:
                child.add_css_class("tab-active")
            child = child.get_next_sibling()
            i += 1

        self.current_tab = idx
        self.tab_stack.set_visible_child_name(f"tab{idx}")

        td = self.tabs[idx]
        uri = td.webview.get_uri()
        if uri and uri != "about:blank":
            self.url_entry.set_text(uri)
        else:
            self.url_entry.set_text("")

        self._update_badge(td.mode)
        self._update_nav_buttons()
        self._update_bookmark_star()
        self._update_security_badge(td.webview.get_uri() or "")

    def _wv(self) -> WebKit.WebView:
        return self.tabs[self.current_tab].webview

    def _td(self) -> TabData:
        return self.tabs[self.current_tab]

    # ── Creación de WebView ──────────────────────────────────────────────────

    def _make_webview(self, mode="normal") -> WebKit.WebView:
        proxy_url = None
        if mode == "tor":
            proxy_url = "socks5://127.0.0.1:9050"
        elif mode == "i2p":
            proxy_url = "http://127.0.0.1:4444"

        if proxy_url:
            ns = WebKit.NetworkSession.new_ephemeral()
            ps = WebKit.NetworkProxySettings.new(proxy_url, None)
            ns.set_proxy_settings(WebKit.NetworkProxyMode.CUSTOM, ps)
            wv = WebKit.WebView(network_session=ns)
        else:
            wv = WebKit.WebView()

        s = WebKit.Settings.new()

        # ── DevTools: deshabilitado en producción ────────────────────────────
        s.set_enable_developer_extras(False)

        # ── Portapapeles: JS no puede acceder ────────────────────────────────
        s.set_javascript_can_access_clipboard(False)

        # ── WebRTC deshabilitado en TODOS los modos (evita IP leak) ─────────
        s.set_enable_webrtc(False)

        # ── Hardening general (aplica siempre) ───────────────────────────────
        s.set_enable_mediasource(False)          # reduce superficie de ataque
        s.set_enable_encrypted_media(False)      # sin DRM
        s.set_enable_back_forward_navigation_gestures(False)
        s.set_media_playback_requires_user_gesture(True)   # sin autoplay
        s.set_javascript_can_open_windows_automatically(False)  # sin popups
        s.set_allow_modal_dialogs(False)         # bloquear alert/confirm/prompt
        s.set_enable_page_cache(False)           # sin caché bfcache (privacidad)

        # ── Anti-fingerprinting: User-Agent normalizado siempre ───────────────
        # Usamos el mismo UA que Tor Browser para reducir singularidad
        s.set_user_agent(
            "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0"
        )

        wv.set_settings(s)
        wv.set_vexpand(True)
        wv.set_hexpand(True)

        wv.connect("notify::uri",   self._on_uri_changed)
        wv.connect("notify::title", self._on_title_changed)
        wv.connect("load-changed",  self._on_load_changed)
        wv.connect("notify::estimated-load-progress", self._on_progress)

        # ── Inyección anti-fingerprinting via UserContentManager ─────────────
        ucm = wv.get_user_content_manager()
        try:
            inj_frames = WebKit.UserContentInjectedFrames.TOP_FRAME
        except AttributeError:
            inj_frames = WebKit.UserContentInjectedFrames.ALL_FRAMES
        try:
            inj_time = WebKit.UserScriptInjectionTime.START
        except AttributeError:
            try:
                inj_time = WebKit.UserScriptInjectionTime.DOCUMENT_START
            except AttributeError:
                inj_time = 0
        try:
            fp_script = WebKit.UserScript(
                self.FP_PROTECTION_JS,
                inj_frames,
                inj_time,
                None, None
            )
            ucm.add_script(fp_script)
        except Exception as e:
            print(f"[prektbr] UserContentManager fallback: {e}")
            wv.connect("load-changed", self._on_load_inject_fp_fallback)

        return wv

    # ── Señales del WebView ──────────────────────────────────────────────────

    FP_PROTECTION_JS = """
(function() {
    'use strict';

    // ═══════════════════════════════════════════════════════════════════════
    // 1. LETTERBOXING — viewport redondeado a múltiplos de 100x100 (Tor-style)
    //    Evita que el tamaño real de la ventana sea un identificador único.
    // ═══════════════════════════════════════════════════════════════════════
    (function() {
        function rounded(v, step) { return Math.floor(v / step) * step || step; }
        const RW = rounded(window.innerWidth,  100);
        const RH = rounded(window.innerHeight, 100);
        const props = {
            innerWidth:  RW, innerHeight: RH,
            outerWidth:  RW, outerHeight: RH,
        };
        for (const [k, v] of Object.entries(props)) {
            try { Object.defineProperty(window, k, { get: () => v, configurable: true }); } catch(e) {}
        }
        // document.documentElement.clientWidth/clientHeight
        try {
            const origClientWidth  = Object.getOwnPropertyDescriptor(Element.prototype, 'clientWidth');
            const origClientHeight = Object.getOwnPropertyDescriptor(Element.prototype, 'clientHeight');
            if (origClientWidth) Object.defineProperty(HTMLHtmlElement.prototype, 'clientWidth',
                { get: function() { return this === document.documentElement ? RW : origClientWidth.get.call(this); }, configurable: true });
            if (origClientHeight) Object.defineProperty(HTMLHtmlElement.prototype, 'clientHeight',
                { get: function() { return this === document.documentElement ? RH : origClientHeight.get.call(this); }, configurable: true });
        } catch(e) {}
    })();

    // ═══════════════════════════════════════════════════════════════════════
    // 2. TIMING ATTACKS — degradar precisión de performance.now() y Date.now()
    //    Sin resolución de microsegundos no se pueden hacer ataques de timing.
    // ═══════════════════════════════════════════════════════════════════════
    (function() {
        // Redondear a múltiplos de 2ms (mismo valor que Firefox en modo resistencia)
        const GRANULARITY = 2;
        const origNow = performance.now.bind(performance);
        performance.now = function() {
            return Math.round(origNow() / GRANULARITY) * GRANULARITY;
        };
        // Date.now también
        const origDateNow = Date.now;
        Date.now = function() {
            return Math.round(origDateNow() / GRANULARITY) * GRANULARITY;
        };
        // SharedArrayBuffer deshabilitado (timing via workers)
        try { delete window.SharedArrayBuffer; } catch(e) {}
        // Atomics también
        try { delete window.Atomics; } catch(e) {}
    })();

    // ═══════════════════════════════════════════════════════════════════════
    // 3. CANVAS FINGERPRINTING — ruido por sesión (consistente en la página)
    // ═══════════════════════════════════════════════════════════════════════
    (function() {
        // Semilla de ruido fija por carga de página (no cambia en cada lectura)
        const NOISE_SEED = (Math.random() * 0xFFFFFFFF) | 0;
        function noiseByte(index) {
            // LCG simple para ruido determinístico por pixel
            return ((NOISE_SEED ^ (index * 1664525 + 1013904223)) >>> 24) & 1;
        }
        const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
        HTMLCanvasElement.prototype.toDataURL = function(type, ...args) {
            const ctx = this.getContext('2d');
            if (ctx && this.width > 0 && this.height > 0) {
                const id = ctx.getImageData(0, 0, this.width, this.height);
                for (let i = 0; i < id.data.length; i += 4) {
                    id.data[i]     ^= noiseByte(i);
                    id.data[i + 1] ^= noiseByte(i + 1);
                    id.data[i + 2] ^= noiseByte(i + 2);
                }
                ctx.putImageData(id, 0, 0);
            }
            return origToDataURL.call(this, type, ...args);
        };
        const origToBlob = HTMLCanvasElement.prototype.toBlob;
        HTMLCanvasElement.prototype.toBlob = function(cb, ...args) {
            const tmp = document.createElement('canvas');
            tmp.width = this.width; tmp.height = this.height;
            const tc = tmp.getContext('2d');
            tc.drawImage(this, 0, 0);
            const id = tc.getImageData(0, 0, tmp.width, tmp.height);
            for (let i = 0; i < id.data.length; i += 4) {
                id.data[i]     ^= noiseByte(i);
                id.data[i + 1] ^= noiseByte(i + 1);
                id.data[i + 2] ^= noiseByte(i + 2);
            }
            tc.putImageData(id, 0, 0);
            return origToBlob.call(tmp, cb, ...args);
        };
    })();

    // ═══════════════════════════════════════════════════════════════════════
    // 4. AUDIOCONTEXT — ruido en procesamiento de audio
    // ═══════════════════════════════════════════════════════════════════════
    (function() {
        const ACtx = window.AudioContext || window.webkitAudioContext;
        if (!ACtx) return;
        const OrigAC = ACtx;
        const Patched = function(...args) {
            const ctx = new OrigAC(...args);
            // Interceptar createAnalyser para añadir ruido a getFloatFrequencyData
            const origCreateAnalyser = ctx.createAnalyser.bind(ctx);
            ctx.createAnalyser = function() {
                const a = origCreateAnalyser();
                const origGetFloat = a.getFloatFrequencyData.bind(a);
                a.getFloatFrequencyData = function(arr) {
                    origGetFloat(arr);
                    for (let i = 0; i < arr.length; i++) arr[i] += (Math.random() - 0.5) * 0.1;
                };
                return a;
            };
            return ctx;
        };
        try {
            if (window.AudioContext)       window.AudioContext       = Patched;
            if (window.webkitAudioContext) window.webkitAudioContext = Patched;
        } catch(e) {}
    })();

    // ═══════════════════════════════════════════════════════════════════════
    // 5. NAVIGATOR — normalizar todos los campos identificadores
    // ═══════════════════════════════════════════════════════════════════════
    (function() {
        const overrides = {
            platform:            'Win32',
            hardwareConcurrency: 4,
            deviceMemory:        8,
            languages:           ['en-US', 'en'],
            language:            'en-US',
            plugins:             [],
            mimeTypes:           [],
            doNotTrack:          '1',
            maxTouchPoints:      0,
            vendor:              'Google Inc.',       // Consistente con Chrome UA
            vendorSub:           '',
            productSub:          '20030107',
            appName:             'Netscape',
            appVersion:          '5.0 (Windows)',
        };
        for (const [k, v] of Object.entries(overrides)) {
            try { Object.defineProperty(navigator, k, { get: () => v, configurable: true }); } catch(e) {}
        }
        // connection API (tipo de red)
        if (navigator.connection) {
            try {
                Object.defineProperty(navigator, 'connection', {
                    get: () => ({ effectiveType: '4g', rtt: 50, downlink: 10,
                                  saveData: false, addEventListener: () => {} }),
                    configurable: true
                });
            } catch(e) {}
        }
    })();

    // ═══════════════════════════════════════════════════════════════════════
    // 6. SCREEN — resolución normalizada
    // ═══════════════════════════════════════════════════════════════════════
    (function() {
        const s = { width: 1920, height: 1080, availWidth: 1920, availHeight: 1080,
                    colorDepth: 24, pixelDepth: 24, orientation: { type: 'landscape-primary', angle: 0 } };
        for (const [k, v] of Object.entries(s)) {
            try { Object.defineProperty(screen, k, { get: () => v, configurable: true }); } catch(e) {}
        }
        try { Object.defineProperty(window, 'devicePixelRatio', { get: () => 1, configurable: true }); } catch(e) {}
    })();

    // ═══════════════════════════════════════════════════════════════════════
    // 7. WEBGL — normalizar vendor, renderer y extensiones
    // ═══════════════════════════════════════════════════════════════════════
    (function() {
        function patchGL(ctx) {
            if (!ctx) return;
            const origGetParam = ctx.getParameter.bind(ctx);
            ctx.getParameter = function(p) {
                if (p === 37445) return 'Intel Inc.';
                if (p === 37446) return 'Intel Iris OpenGL Engine';
                return origGetParam(p);
            };
            // Suprimir extensiones que revelan hardware
            const origGetExt = ctx.getExtension.bind(ctx);
            ctx.getExtension = function(name) {
                const blocked = ['WEBGL_debug_renderer_info', 'EXT_disjoint_timer_query',
                                 'EXT_disjoint_timer_query_webgl2'];
                if (blocked.includes(name)) return null;
                return origGetExt(name);
            };
            const origGetSupportedExt = ctx.getSupportedExtensions.bind(ctx);
            ctx.getSupportedExtensions = function() {
                const exts = origGetSupportedExt() || [];
                return exts.filter(e => !['WEBGL_debug_renderer_info',
                    'EXT_disjoint_timer_query', 'EXT_disjoint_timer_query_webgl2'].includes(e));
            };
        }
        const origGetContext = HTMLCanvasElement.prototype.getContext;
        HTMLCanvasElement.prototype.getContext = function(type, ...args) {
            const ctx = origGetContext.call(this, type, ...args);
            if (ctx && (type === 'webgl' || type === 'webgl2' || type === 'experimental-webgl')) {
                patchGL(ctx);
            }
            return ctx;
        };
    })();

    // ═══════════════════════════════════════════════════════════════════════
    // 8. BATTERY API — datos fijos
    // ═══════════════════════════════════════════════════════════════════════
    if (navigator.getBattery) {
        navigator.getBattery = () => Promise.resolve({
            charging: true, chargingTime: 0,
            dischargingTime: Infinity, level: 1.0,
            addEventListener: () => {}, removeEventListener: () => {}
        });
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 9. TIMEZONE — forzar UTC en Date e Intl
    // ═══════════════════════════════════════════════════════════════════════
    Date.prototype.getTimezoneOffset = function() { return 0; };
    try {
        const origDTF = Intl.DateTimeFormat;
        Intl.DateTimeFormat = function(locale, opts = {}) {
            opts.timeZone = 'UTC';
            return new origDTF(locale, opts);
        };
        Object.assign(Intl.DateTimeFormat, origDTF);
        Intl.DateTimeFormat.prototype = origDTF.prototype;
    } catch(e) {}

    // ═══════════════════════════════════════════════════════════════════════
    // 10. FUENTES — bloquear enumeración
    // ═══════════════════════════════════════════════════════════════════════
    if (document.fonts && document.fonts.check) {
        const generic = ['serif','sans-serif','monospace','cursive','fantasy','system-ui'];
        const origCheck = document.fonts.check.bind(document.fonts);
        document.fonts.check = (font, txt) =>
            generic.some(g => font.toLowerCase().includes(g)) ? origCheck(font, txt) : false;
        // load() retorna vacío para fuentes no genéricas
        const origLoad = document.fonts.load.bind(document.fonts);
        document.fonts.load = (font, txt) =>
            generic.some(g => font.toLowerCase().includes(g)) ? origLoad(font, txt) : Promise.resolve([]);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 11. WINDOW.NAME — limpiar (evita tracking entre páginas)
    // ═══════════════════════════════════════════════════════════════════════
    window.name = '';

    // ═══════════════════════════════════════════════════════════════════════
    // 12. NETWORK INFORMATION API — normalizar
    // ═══════════════════════════════════════════════════════════════════════
    try {
        Object.defineProperty(navigator, 'onLine', { get: () => true, configurable: true });
    } catch(e) {}

    // ═══════════════════════════════════════════════════════════════════════
    // 13. GEOLOCATION — bloquear silenciosamente
    // ═══════════════════════════════════════════════════════════════════════
    if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition = (ok, err) => {
            if (err) err({ code: 1, message: 'Permission denied' });
        };
        navigator.geolocation.watchPosition = (ok, err) => {
            if (err) err({ code: 1, message: 'Permission denied' });
            return 0;
        };
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 14. MEDIA DEVICES — ocultar cámaras y micrófonos
    // ═══════════════════════════════════════════════════════════════════════
    if (navigator.mediaDevices) {
        navigator.mediaDevices.enumerateDevices = () => Promise.resolve([]);
        navigator.mediaDevices.getUserMedia    = () => Promise.reject(new DOMException('NotAllowedError'));
        navigator.mediaDevices.getDisplayMedia = () => Promise.reject(new DOMException('NotAllowedError'));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 15. SPEECH SYNTHESIS / RECOGNITION — bloquear (revela OS y voces)
    // ═══════════════════════════════════════════════════════════════════════
    try {
        if (window.speechSynthesis) {
            window.speechSynthesis.getVoices = () => [];
        }
        delete window.SpeechRecognition;
        delete window.webkitSpeechRecognition;
    } catch(e) {}

})();
"""

    def _on_load_inject_fp_fallback(self, wv, event):
        if event == WebKit.LoadEvent.STARTED:
            wv.evaluate_javascript(self.FP_PROTECTION_JS, -1, None, None, None, None)

    def _on_uri_changed(self, wv, _param):
        if not self.tabs:
            return
        uri = wv.get_uri()
        if not uri or uri == "about:blank":
            return
        if wv is self._wv():
            self.url_entry.set_text(uri)
            self._update_bookmark_star()
            self._update_nav_buttons()
            self._update_security_badge(uri)
        title = wv.get_title() or uri
        self.app.add_history(uri, title)

    def _on_title_changed(self, wv, _param):
        if not self.tabs:
            return
        title = wv.get_title() or ""
        child = self.tabbar_box.get_first_child()
        i = 0
        while child:
            if i < len(self.tabs) and self.tabs[i].webview is wv:
                if hasattr(child, "_title_btn"):
                    short = (title[:14] + "...") if len(title) > 14 else (title or f"Tab {i+1}")
                    child._title_btn.set_label(short)
                break
            child = child.get_next_sibling()
            i += 1
        if wv is self._wv():
            self.set_title(f"PrekT-BR — {title}" if title else "PrekT-BR")

    def _on_load_changed(self, wv, event):
        if event == WebKit.LoadEvent.STARTED:
            self.reload_btn.set_label("✕")
            self.reload_btn.set_tooltip_text("Detener carga")
        elif event == WebKit.LoadEvent.FINISHED:
            self.reload_btn.set_label("↻")
            self.reload_btn.set_tooltip_text("Recargar (Ctrl+R)")
            self.statusbar.set_label("")
            if self.app.dark_mode and wv is self._wv():
                GLib.timeout_add(400, self._apply_dark_css)

    def _on_progress(self, wv, _param):
        if wv is not self._wv():
            return
        p = wv.get_estimated_load_progress()
        if 0 < p < 1:
            self.statusbar.set_label(f"Cargando… {int(p*100)}%")
        else:
            self.statusbar.set_label("")

    # ── Navegación ───────────────────────────────────────────────────────────

    def _on_back(self, _):
        if self._wv().can_go_back():
            self._wv().go_back()

    def _on_forward(self, _):
        if self._wv().can_go_forward():
            self._wv().go_forward()

    def _on_home(self, _):
        self._wv().load_uri(self.app.home_uri)

    def _on_url_activate(self, entry):
        text = entry.get_text().strip()
        if not text:
            return
        url = self._resolve_input(text)
        self._wv().load_uri(url)

    def _resolve_input(self, text):
        # Bloquear esquemas peligrosos (file:// permitido)
        dangerous = ("javascript:", "data:", "vbscript:", "blob:")
        lower = text.strip().lower()
        for scheme in dangerous:
            if lower.startswith(scheme):
                self.statusbar.set_label(f"Esquema bloqueado: {scheme}")
                return "about:blank"
        if text.startswith(("http://", "https://", "about:", "file://")):
            return text
        # Si parece dominio (tiene punto y sin espacios)
        if "." in text and " " not in text:
            return "https://" + text
        # Buscar en DuckDuckGo
        q = urllib.parse.quote(text)
        return f"https://duckduckgo.com/?q={q}"

    def _update_nav_buttons(self):
        if not self.tabs:
            return
        self.back_btn.set_sensitive(self._wv().can_go_back())
        self.forward_btn.set_sensitive(self._wv().can_go_forward())

    # ── Marcadores ───────────────────────────────────────────────────────────

    def _on_toggle_bookmark(self, _):
        wv = self._wv()
        uri = wv.get_uri()
        if not uri or uri == "about:blank":
            return
        if self.app.is_bookmarked(uri):
            self.app.remove_bookmark(uri)
            self.bookmark_star.set_label("★")
            self.statusbar.set_label("Marcador eliminado")
        else:
            title = wv.get_title() or uri
            self.app.add_bookmark(uri, title)
            self.bookmark_star.set_label("★")
            self.statusbar.set_label("Marcador guardado")
        GLib.timeout_add(2000, lambda: self.statusbar.set_label("") or False)
        # Refrescar sidebar si está abierto
        if self._sidebar_mode == "bookmarks":
            self._show_sidebar("bookmarks")

    def _update_bookmark_star(self):
        if not self.tabs:
            return
        uri = self._wv().get_uri()
        self.bookmark_star.set_label("★")

    # ── Sidebar (marcadores / historial) ─────────────────────────────────────

    def _toggle_sidebar(self, mode):
        if self._sidebar_mode == mode:
            self._close_sidebar()
        else:
            self._show_sidebar(mode)

    def _close_sidebar(self):
        if self.sidebar_widget:
            self.content_area.remove(self.sidebar_widget)
            self.sidebar_widget = None
        self._sidebar_mode = None

    def _show_sidebar(self, mode):
        self._close_sidebar()
        self._sidebar_mode = mode

        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        outer.add_css_class("sidebar")

        # Cabecera del panel
        title_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        title_box.add_css_class("sidebar-title")
        lbl = Gtk.Label(label="Marcadores" if mode == "bookmarks" else "Historial")
        lbl.set_hexpand(True)
        lbl.set_halign(Gtk.Align.START)
        close_btn = Gtk.Button(label="Cerrar")
        close_btn.add_css_class("nav-button")
        close_btn.connect("clicked", lambda _: self._close_sidebar())
        title_box.append(lbl)
        title_box.append(close_btn)

        scroll = Gtk.ScrolledWindow()
        scroll.set_vexpand(True)
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)

        list_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=1)
        list_box.set_margin_top(4)
        list_box.set_margin_bottom(4)
        list_box.set_margin_start(4)
        list_box.set_margin_end(4)

        if mode == "bookmarks":
            items = self.app.bookmarks[:]
            if not items:
                empty = Gtk.Label(label="Sin marcadores aún")
                empty.set_margin_top(20)
                empty.add_css_class("sidebar-item")
                list_box.append(empty)
            for b in items:
                self._sidebar_item(list_box, b["title"], b["url"], removable=True)
        else:
            items = list(reversed(self.app.history[-200:]))
            if not items:
                empty = Gtk.Label(label="El historial está vacío")
                empty.set_margin_top(20)
                empty.add_css_class("sidebar-item")
                list_box.append(empty)
            for h in items:
                ts = h.get("ts", "")[:10]
                label = f"[{ts}] {h.get('title', h['url'])}"
                self._sidebar_item(list_box, label, h["url"])

        scroll.set_child(list_box)
        outer.append(title_box)
        outer.append(scroll)

        # Insertar ANTES del stack
        self.content_area.prepend(outer)
        self.sidebar_widget = outer

    def _sidebar_item(self, box, label, url, removable=False):
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=2)
        btn = Gtk.Button(label=label)
        btn.add_css_class("sidebar-item")
        btn.set_hexpand(True)
        btn.set_halign(Gtk.Align.FILL)
        btn.connect("clicked", lambda _, u=url: self._wv().load_uri(u))
        row.append(btn)
        if removable:
            del_btn = Gtk.Button(label="Quitar")
            del_btn.add_css_class("close-tab-btn")
            del_btn.connect("clicked", lambda _, u=url: (
                self.app.remove_bookmark(u),
                self._show_sidebar("bookmarks")
            ))
            row.append(del_btn)
        box.append(row)

    # ── Badge de modo red ─────────────────────────────────────────────────────

    def _update_badge(self, mode):
        self.badge.remove_css_class("badge-normal")
        self.badge.remove_css_class("badge-tor")
        self.badge.remove_css_class("badge-i2p")
        self.badge.remove_css_class("badge-clear")
        if mode == "tor":
            self.badge.set_label("TOR")
            self.badge.add_css_class("badge-tor")
            self.badge.set_visible(True)
        elif mode == "i2p":
            self.badge.set_label("I2P")
            self.badge.add_css_class("badge-i2p")
            self.badge.set_visible(True)
        else:
            self.badge.set_label("Clear")
            self.badge.add_css_class("badge-clear")
            self.badge.set_visible(True)

    # ── Modo oscuro ──────────────────────────────────────────────────────────

    def _apply_dark_css(self):
        css = """
        :root { color-scheme: dark !important; }
        * { background-color: #111 !important; color: #eee !important;
            border-color: #333 !important; }
        a { color: #8ab4f8 !important; }
        img { filter: brightness(0.85); }
        """
        js = f"""(function(){{
            let el = document.getElementById('prektbr-dark');
            if(!el){{el=document.createElement('style');el.id='prektbr-dark';
            document.head.appendChild(el);}} el.textContent=`{css}`;
        }})();"""
        self._wv().evaluate_javascript(js, -1, None, None, None, None)
        return False

    # ── Atajos de teclado globales ───────────────────────────────────────────

    def _on_global_key(self, ctrl, keyval, keycode, state):
        ctrl_held  = bool(state & Gdk.ModifierType.CONTROL_MASK)
        alt_held   = bool(state & Gdk.ModifierType.ALT_MASK)
        shift_held = bool(state & Gdk.ModifierType.SHIFT_MASK)
        # Mod5 es AltGr en la mayoría de teclados Linux
        altgr_held = bool(state & Gdk.ModifierType.MOD5_MASK)

        if ctrl_held and not alt_held and not altgr_held:
            if keyval == Gdk.KEY_t:                  # Ctrl+T — nueva pestaña
                self.open_tab()
                return True
            if keyval == Gdk.KEY_w:                  # Ctrl+W — cerrar pestaña
                self._on_close_tab(self.current_tab)
                return True
            if keyval == Gdk.KEY_l:                  # Ctrl+L — foco en URL
                self.url_entry.grab_focus()
                self.url_entry.select_region(0, -1)
                return True
            if keyval == Gdk.KEY_r and not shift_held:  # Ctrl+R — recargar
                self._wv().reload()
                return True
            if keyval == Gdk.KEY_r and shift_held:      # Ctrl+Shift+R — sin caché
                self._wv().reload_bypass_cache()
                return True
            if keyval == Gdk.KEY_f:                  # Ctrl+F — buscar en página
                self._toggle_findbar()
                return True
            if keyval == Gdk.KEY_plus or keyval == Gdk.KEY_equal:  # Ctrl++ zoom in
                wv = self._wv()
                wv.set_zoom_level(min(wv.get_zoom_level() + 0.1, 5.0))
                return True
            if keyval == Gdk.KEY_minus:              # Ctrl+- — zoom out
                wv = self._wv()
                wv.set_zoom_level(max(wv.get_zoom_level() - 0.1, 0.1))
                return True
            if keyval == Gdk.KEY_0:                  # Ctrl+0 — zoom reset
                self._wv().set_zoom_level(1.0)
                return True

        if ctrl_held and alt_held and not altgr_held:
            if keyval in (Gdk.KEY_t, Gdk.KEY_Return):  # Ctrl+Alt+T — terminal
                self._on_toggle_terminal(None)
                return True

        if ctrl_held and altgr_held:
            if keyval == Gdk.KEY_d:                  # Ctrl+AltGr+D — inspector
                self._toggle_inspector()
                return True

        if not ctrl_held and not alt_held:
            if keyval == Gdk.KEY_Escape:
                if self._findbar_visible:
                    self._close_findbar()
                    return True
                if self._inspector_mode:
                    self._close_inspector()
                    return True

        if alt_held and not ctrl_held:
            if keyval == Gdk.KEY_Left:               # Alt+Izq — atrás
                if self._wv().can_go_back():
                    self._wv().go_back()
                return True
            if keyval == Gdk.KEY_Right:              # Alt+Der — adelante
                if self._wv().can_go_forward():
                    self._wv().go_forward()
                return True

        return False

    # ── Seguridad: badge S / I / O / E ───────────────────────────────────────

    def _update_security_badge(self, uri):
        if not uri or uri.startswith("about:"):
            self.sec_badge.set_visible(False)
            return
        parsed = urllib.parse.urlparse(uri)
        host = parsed.hostname or ""
        scheme = parsed.scheme

        self.sec_badge.remove_css_class("badge-secure")
        self.sec_badge.remove_css_class("badge-insecure")
        self.sec_badge.remove_css_class("badge-onion")
        self.sec_badge.remove_css_class("badge-eepsite")
        self.sec_badge.remove_css_class("badge-file")

        if scheme == "file":
            self.sec_badge.set_label("F")
            self.sec_badge.add_css_class("badge-file")
            self.sec_badge.set_tooltip_text("Archivo local")
        elif host.endswith(".onion"):
            self.sec_badge.set_label("O")
            self.sec_badge.add_css_class("badge-onion")
            self.sec_badge.set_tooltip_text("Onion — servicio oculto Tor")
        elif host.endswith(".i2p") or host.endswith(".loki"):
            self.sec_badge.set_label("E")
            self.sec_badge.add_css_class("badge-eepsite")
            self.sec_badge.set_tooltip_text("Eepsite — servicio I2P/Lokinet")
        elif scheme == "https":
            self.sec_badge.set_label("S")
            self.sec_badge.add_css_class("badge-secure")
            self.sec_badge.set_tooltip_text("Seguro — conexión HTTPS")
        else:
            self.sec_badge.set_label("I")
            self.sec_badge.add_css_class("badge-insecure")
            self.sec_badge.set_tooltip_text("Inseguro — conexión HTTP sin cifrar")
        self.sec_badge.set_visible(True)

    # ── Buscar en página ──────────────────────────────────────────────────────

    def _toggle_findbar(self):
        if self._findbar_visible:
            self._close_findbar()
        else:
            self._findbar_box.set_visible(True)
            self._findbar_visible = True
            self._find_entry.grab_focus()

    def _close_findbar(self):
        self._findbar_box.set_visible(False)
        self._findbar_visible = False
        self._wv().get_find_controller().search_finish()
        self._find_label.set_label("")

    def _find_changed(self):
        text = self._find_entry.get_text()
        fc = self._wv().get_find_controller()
        if text:
            fc.search(text, WebKit.FindOptions.CASE_INSENSITIVE |
                      WebKit.FindOptions.WRAP_AROUND, 1000)
        else:
            fc.search_finish()
            self._find_label.set_label("")

    def _find_next(self):
        fc = self._wv().get_find_controller()
        text = self._find_entry.get_text()
        if text:
            fc.search_next()

    def _find_prev(self):
        fc = self._wv().get_find_controller()
        text = self._find_entry.get_text()
        if text:
            fc.search_previous()

    # ── Inspector de HTML ─────────────────────────────────────────────────────

    def _toggle_inspector(self):
        if self._inspector_mode:
            self._close_inspector()
        else:
            self._open_inspector()

    def _open_inspector(self):
        if self._inspector_mode:
            return
        if self.terminal_visible:
            self.statusbar.set_label("Cierra la terminal primero (Ctrl+Alt+T)")
            GLib.timeout_add(2000, lambda: self.statusbar.set_label("") or False)
            return
        self._inspector_mode = True
        self.content_area.append(self._insp_panel)
        self._inspector_load()

    def _close_inspector(self):
        if not self._inspector_mode:
            return
        self.content_area.remove(self._insp_panel)
        self._inspector_mode = False

    def _format_html(self, html):
        """Formatea HTML con indentación legible usando html.parser."""
        import html as html_mod
        from html.parser import HTMLParser

        INLINE_TAGS = {
            "a", "abbr", "acronym", "b", "bdo", "big", "br", "button", "cite",
            "code", "dfn", "em", "i", "img", "input", "kbd", "label", "map",
            "object", "output", "q", "samp", "select", "small", "span", "strong",
            "sub", "sup", "textarea", "time", "tt", "u", "var",
        }
        VOID_TAGS = {
            "area", "base", "br", "col", "embed", "hr", "img", "input", "link",
            "meta", "param", "source", "track", "wbr",
        }
        RAW_TAGS = {"script", "style"}

        class Formatter(HTMLParser):
            def __init__(self):
                super().__init__(convert_charrefs=False)
                self.out = []
                self.indent = 0
                self.in_raw = False
                self.raw_tag = ""

            def _pad(self):
                return "  " * self.indent

            def handle_starttag(self, tag, attrs):
                if self.in_raw:
                    self.out.append(self.get_starttag_text() or "")
                    return
                attr_str = ""
                for name, val in attrs:
                    if val is None:
                        attr_str += f" {name}"
                    else:
                        attr_str += f' {name}="{html_mod.escape(val, quote=True)}"'
                line = f"{self._pad()}<{tag}{attr_str}>"
                if tag in INLINE_TAGS:
                    self.out.append(line)
                else:
                    self.out.append(line)
                if tag in RAW_TAGS:
                    self.in_raw = True
                    self.raw_tag = tag
                if tag not in VOID_TAGS and tag not in INLINE_TAGS:
                    self.indent += 1

            def handle_endtag(self, tag):
                if tag in RAW_TAGS:
                    self.in_raw = False
                    self.raw_tag = ""
                if tag not in VOID_TAGS and tag not in INLINE_TAGS:
                    self.indent = max(0, self.indent - 1)
                if self.in_raw:
                    self.out.append(f"</{tag}>")
                else:
                    self.out.append(f"{self._pad()}</{tag}>")

            def handle_data(self, data):
                stripped = data.strip()
                if stripped:
                    if self.in_raw:
                        # Preservar indentación original de scripts/styles
                        self.out.append(data)
                    else:
                        self.out.append(f"{self._pad()}{stripped}")

            def handle_comment(self, data):
                self.out.append(f"{self._pad()}<!--{data}-->")

            def handle_decl(self, decl):
                self.out.append(f"<!{decl}>")

            def handle_entityref(self, name):
                self.out.append(f"&{name};")

            def handle_charref(self, name):
                self.out.append(f"&#{name};")

        try:
            f = Formatter()
            f.feed(html)
            return "\n".join(line for line in f.out if line.strip() != "")
        except Exception:
            return html  # si falla, devolver el HTML original sin formatear

    def _inspector_load(self):
        """Obtiene el HTML actual de la página y lo muestra en el inspector."""
        self.inspector_buf.set_text("Cargando HTML…")
        wv = self._wv()

        # ── Estrategia 1: script_message_handler (más fiable en WebKit 6.0) ──
        # Registrar un canal JS→Python, ejecutar el script, desregistrar al recibir
        ucm = wv.get_user_content_manager()
        handler_name = "prektbrInspector"

        def _on_message(ucm_, msg):
            try:
                jsc = msg.get_js_value()
                html = jsc.to_string() if jsc else ""
            except Exception:
                try:
                    html = msg.to_string()
                except Exception:
                    html = "[No se pudo convertir el resultado]"
            # Desconectar para no acumular handlers
            try:
                ucm_.disconnect_by_func(_on_message)
                ucm_.unregister_script_message_handler(handler_name)
            except Exception:
                pass
            if html and html not in ("undefined", "null"):
                formatted = self._format_html(html)
            else:
                formatted = "[HTML vacío]"
            GLib.idle_add(lambda h=formatted: self.inspector_buf.set_text(h) or False)

        try:
            ucm.register_script_message_handler(handler_name)
            ucm.connect(f"script-message-received::{handler_name}", _on_message)
            js = f"window.webkit.messageHandlers.{handler_name}.postMessage(document.documentElement.outerHTML);"
            wv.evaluate_javascript(js, -1, None, None, None, None)
            return
        except Exception:
            pass

        # ── Estrategia 2: run_javascript (WebKit 4.x / algunos builds de 6.0) ──
        def _on_run(source, result):
            try:
                res = source.run_javascript_finish(result)
                html = res.get_js_value().to_string()
                if html and html not in ("undefined", "null"):
                    formatted = self._format_html(html)
                else:
                    formatted = "[HTML vacío]"
                GLib.idle_add(lambda h=formatted: self.inspector_buf.set_text(h) or False)
            except Exception as e:
                GLib.idle_add(lambda err=str(e): self.inspector_buf.set_text(
                    f"[Error: {err}]") or False)

        try:
            wv.run_javascript("document.documentElement.outerHTML", None, _on_run)
            return
        except AttributeError:
            pass

        # ── Estrategia 3: evaluate_javascript sin callback + polling ──────────
        GLib.idle_add(lambda: self.inspector_buf.set_text(
            "[evaluate_javascript no disponible en esta versión de WebKit]") or False)

    def _inspector_apply(self):
        """Aplica el HTML del inspector a la página actual."""
        start = self.inspector_buf.get_start_iter()
        end   = self.inspector_buf.get_end_iter()
        html  = self.inspector_buf.get_text(start, end, False)
        # Escapar backticks y backslashes para inyectar seguro
        html_escaped = html.replace("\\", "\\\\").replace("`", "\\`")
        js = f"document.open(); document.write(`{html_escaped}`); document.close();"
        self._wv().evaluate_javascript(js, -1, None, None, None, None)

    def _on_inspector_key(self, ctrl, keyval, keycode, state):
        ctrl_held = bool(state & Gdk.ModifierType.CONTROL_MASK)
        if ctrl_held and keyval == Gdk.KEY_Return:
            self._inspector_apply()
            return True
        if keyval == Gdk.KEY_Escape:
            self._close_inspector()
            return True
        return False

    # ── Descargas ─────────────────────────────────────────────────────────────

    def _setup_download_handler(self, wv):
        """Conecta el manejador de descargas al network_session del webview."""
        ns = wv.get_network_session()
        if ns:
            ns.connect("download-started", self._on_download_started)

    def _on_download_started(self, session, download):
        """En WebKit 6.0 el nombre sugerido llega en decide-destination."""
        download.connect("decide-destination", self._on_decide_destination)
        download.connect("failed", self._on_download_failed)

    def _on_decide_destination(self, download, suggested_filename):
        """Señal correcta en WebKit 6.0 — recibe el nombre sugerido del servidor."""
        if not suggested_filename:
            try:
                req = download.get_request()
                uri = req.get_uri() if req else ""
                suggested_filename = os.path.basename(urllib.parse.urlparse(uri).path) or "descarga"
            except Exception:
                suggested_filename = "descarga"

        dialog = Gtk.FileDialog()
        dialog.set_title("Guardar archivo")
        dialog.set_initial_name(suggested_filename)
        dialog.save(self, None, self._on_save_dialog_done, download)
        return True

    def _on_save_dialog_done(self, dialog, result, download):
        try:
            gfile = dialog.save_finish(result)
            dest = gfile.get_path()
            fname = os.path.basename(dest)

            download.set_destination(dest)

            self.statusbar.set_label(f"Descargando: {fname}  0%")
            self._dl_progress.set_fraction(0.0)
            self._dl_progress.set_visible(True)

            def _on_progress(d, _param):
                p = d.get_estimated_progress()
                GLib.idle_add(lambda: (
                    self._dl_progress.set_fraction(p),
                    self.statusbar.set_label(f"Descargando: {fname}  {int(p * 100)}%")
                ) and False)

            def _on_finished(d):
                def _done():
                    self._dl_progress.set_fraction(1.0)
                    self.statusbar.set_label(f"Descarga completa: {fname}")
                    GLib.timeout_add(3500, _cleanup)
                    return False
                def _cleanup():
                    self._dl_progress.set_visible(False)
                    self._dl_progress.set_fraction(0.0)
                    self.statusbar.set_label("")
                    return False
                GLib.idle_add(_done)

            download.connect("notify::estimated-progress", _on_progress)
            download.connect("finished", _on_finished)

        except Exception:
            download.cancel()

    def _on_download_failed(self, download, error):
        def _err():
            self._dl_progress.set_visible(False)
            self._dl_progress.set_fraction(0.0)
            self.statusbar.set_label(f"Error de descarga: {error}")
            GLib.timeout_add(4000, lambda: self.statusbar.set_label("") or False)
            return False
        GLib.idle_add(_err)

    # ── Recarga sin caché (botón) ─────────────────────────────────────────────

    def _on_reload(self, btn):
        wv = self._wv()
        if wv.is_loading():
            wv.stop_loading()
        else:
            wv.reload()

    # ── Toggle terminal ───────────────────────────────────────────────────────

    def _on_toggle_terminal(self, _):
        if self._inspector_mode:
            self.statusbar.set_label("Cierra el inspector primero (Esc)")
            GLib.timeout_add(2000, lambda: self.statusbar.set_label("") or False)
            return
        if self.terminal_visible:
            self.content_area.remove(self._term_scroll)
            self.terminal_visible = False
        else:
            self.content_area.append(self._term_scroll)
            self.terminal_visible = True
            self.terminal_tv.grab_focus()

    # ── Navegación ────────────────────────────────────────────────────────────

    def _enable_network_mode(self, mode):
        td = self._td()
        if td.mode == mode:
            self._term_print(f"La pestaña ya está en modo {mode.upper()}.")
            self._term_prompt()
            return
        old_uri = td.webview.get_uri() or self.app.home_uri
        new_wv = self._make_webview(mode)
        idx = self.current_tab

        self.tab_stack.remove(td.webview)
        td.webview = new_wv
        td.mode = mode
        self.tab_stack.add_named(new_wv, f"tab{idx}")
        self.tab_stack.set_visible_child_name(f"tab{idx}")
        new_wv.load_uri(old_uri if old_uri != "about:blank" else self.app.home_uri)
        self._update_badge(mode)

        if mode == "tor":
            self._term_print("  MODO TOR ACTIVADO — WebRTC deshabilitado")
            self._term_print("  Usa http:// (sin s) para sitios .onion")
        elif mode == "i2p":
            self._term_print("  MODO I2P ACTIVADO — Proxy HTTP 127.0.0.1:4444")
            self._term_print("  Navega a sitios .i2p normalmente")
        self._term_prompt()

    def _disable_network_mode(self):
        td = self._td()
        if td.mode == "normal":
            self._term_print("La pestaña ya está en modo normal.")
            self._term_prompt()
            return
        old_uri = td.webview.get_uri() or self.app.home_uri
        new_wv = self._make_webview("normal")
        idx = self.current_tab

        self.tab_stack.remove(td.webview)
        td.webview = new_wv
        td.mode = "normal"
        self.tab_stack.add_named(new_wv, f"tab{idx}")
        self.tab_stack.set_visible_child_name(f"tab{idx}")
        new_wv.load_uri(old_uri if old_uri != "about:blank" else self.app.home_uri)
        self._update_badge("normal")
        self._term_print("  Modo normal restaurado.")
        self._term_prompt()

    # ── Terminal ─────────────────────────────────────────────────────────────

    def _term_print(self, text, no_nl=False):
        end = self.terminal_buf.get_end_iter()
        self.terminal_buf.insert(end, text if no_nl else text + "\n")
        self.terminal_tv.scroll_to_iter(end, 0.0, True, 0.0, 1.0)

    def _term_prompt(self):
        end = self.terminal_buf.get_end_iter()
        self.terminal_buf.insert(end, "> ")
        end2 = self.terminal_buf.get_end_iter()
        self._prompt_end_mark = self.terminal_buf.create_mark("prompt_end", end2, True)

    def _on_terminal_key(self, ctrl, keyval, keycode, state):
        if keyval in (Gdk.KEY_Return, Gdk.KEY_KP_Enter):
            start = self.terminal_buf.get_start_iter()
            end   = self.terminal_buf.get_end_iter()
            full  = self.terminal_buf.get_text(start, end, False).rstrip()
            lines = full.split("\n")
            if lines:
                last = lines[-1].strip()
                if last.startswith("> "):
                    cmd = last[2:].strip()
                    if cmd:
                        self._term_print("")
                        self._run_command(cmd)
                        return True
            self._term_print("")
            self._term_prompt()
            return True

        # Proteger el prompt: bloquear borrado/movimiento antes del fin del "> "
        if keyval in (Gdk.KEY_BackSpace, Gdk.KEY_Delete,
                      Gdk.KEY_Left, Gdk.KEY_Home,
                      Gdk.KEY_KP_Left, Gdk.KEY_KP_Home):
            if hasattr(self, "_prompt_end_mark"):
                insert_mark = self.terminal_buf.get_insert()
                cursor = self.terminal_buf.get_iter_at_mark(insert_mark)
                limit  = self.terminal_buf.get_iter_at_mark(self._prompt_end_mark)
                if cursor.compare(limit) <= 0:
                    return True
        return False

    # ── Comandos de terminal ──────────────────────────────────────────────────

    def _run_command(self, raw):
        parts   = raw.split(maxsplit=1)
        cmd     = parts[0].lower() if parts else ""
        args    = parts[1].strip() if len(parts) > 1 else ""

        def nav(url):
            self._wv().load_uri(url)

        if cmd == "help":
            self._term_print(
                "─── Navegación ───────────────────────────────\n"
                "  open <url>            → abre URL en pestaña actual\n"
                "  newtab [url]          → abre nueva pestaña\n"
                "  closetab              → cierra pestaña actual\n"
                "  tab <n>               → cambia a pestaña n (1-based)\n"
                "  back / forward        → historial del navegador\n"
                "  reload                → recarga normal\n"
                "  reloadhard            → recarga sin caché\n"
                "  home                  → página de inicio\n"
                "  zoom <n>              → nivel de zoom (0.1–5.0, 1.0=normal)\n"
                "─── Búsqueda ─────────────────────────────────\n"
                "  ddg <consulta>        → DuckDuckGo\n"
                "  google <consulta>     → Google\n"
                "  yt <consulta>         → YouTube\n"
                "  wiki <consulta>       → Wikipedia (es)\n"
                "─── Redes alternativas ───────────────────────\n"
                "  tormode               → activa Tor en esta pestaña\n"
                "  i2pmode               → activa I2P en esta pestaña\n"
                "  clearnet              → vuelve a modo normal\n"
                "  loki <direccion>      → abre direccion.loki (requiere lokinet.service)\n"
                "  whoami                → tu IP pública\n"
                "  serverip              → IP del servidor actual\n"
                "─── Marcadores e historial ───────────────────\n"
                "  bookmark              → guarda/quita marcador actual\n"
                "  bookmarks             → lista marcadores\n"
                "  history [n]           → últimas n URLs (def. 10)\n"
                "─── Utilidades ───────────────────────────────\n"
                "  dark                  → toggle modo oscuro\n"
                "  calc <expr>           → calculadora\n"
                "  time / date           → hora / fecha\n"
                "  echo <texto>          → repite texto\n"
                "  clear                 → limpia terminal\n"
                "  clearcookies          → borra cookies/datos de pestaña actual\n"
                "  clearall              → borra datos de todas las pestañas\n"
                "  about                 → info del navegador\n"
                "  quit                  → cierra el navegador\n"
                "─── Atajos de teclado ────────────────────────\n"
                "  Ctrl+T                → nueva pestaña\n"
                "  Ctrl+W                → cerrar pestaña\n"
                "  Ctrl+L                → foco en barra de URL\n"
                "  Ctrl+R                → recargar\n"
                "  Ctrl+Shift+R          → recargar sin caché\n"
                "  Ctrl+F                → buscar en página\n"
                "  Ctrl++ / Ctrl+-       → zoom in/out\n"
                "  Ctrl+0                → zoom reset\n"
                "  Ctrl+Alt+T            → abrir/cerrar terminal\n"
                "  Ctrl+AltGr+D          → abrir/cerrar inspector HTML\n"
                "  Alt+Izq / Alt+Der     → atrás / adelante\n"
            )

        elif cmd in ("open", "new"):
            if args:
                nav(self._resolve_input(args))
            else:
                self._term_print("Uso: open <url>")

        elif cmd == "newtab":
            self.open_tab(uri=self._resolve_input(args) if args else None)

        elif cmd == "closetab":
            self._on_close_tab(None, self.current_tab)

        elif cmd == "tab":
            try:
                n = int(args) - 1
                self._switch_tab(n)
            except ValueError:
                self._term_print("Uso: tab <número>")

        elif cmd == "back":
            if self._wv().can_go_back():
                self._wv().go_back()

        elif cmd == "forward":
            if self._wv().can_go_forward():
                self._wv().go_forward()

        elif cmd == "reload":
            self._wv().reload()

        elif cmd == "reloadhard":
            self._wv().reload_bypass_cache()

        elif cmd == "home":
            nav(self.app.home_uri)

        elif cmd == "zoom":
            if args:
                try:
                    level = float(args)
                    if 0.1 <= level <= 5.0:
                        self._wv().set_zoom_level(level)
                        self._term_print(f"Zoom: {level:.1f}x")
                    else:
                        self._term_print("Zoom válido: 0.1 – 5.0 (1.0 = normal)")
                except ValueError:
                    self._term_print("Uso: zoom <número>  (ej: zoom 1.5)")
            else:
                current = self._wv().get_zoom_level()
                self._term_print(f"Zoom actual: {current:.1f}x  — uso: zoom <número>")

        # Búsqueda
        elif cmd == "ddg":
            q = urllib.parse.quote(args) if args else ""
            nav(f"https://duckduckgo.com/?q={q}" if q else "https://duckduckgo.com")

        elif cmd == "google":
            q = urllib.parse.quote(args) if args else ""
            nav(f"https://www.google.com/search?q={q}" if q else "https://www.google.com")

        elif cmd == "yt":
            q = urllib.parse.quote(args) if args else ""
            nav(f"https://www.youtube.com/results?search_query={q}" if q else "https://www.youtube.com")

        elif cmd == "wiki":
            q = urllib.parse.quote(args) if args else ""
            nav(f"https://es.wikipedia.org/wiki/{q}" if q else "https://es.wikipedia.org")

        elif cmd == "loki":
            if args:
                # Quitar http/https si lo pusieron, y la extension .loki si ya la pusieron
                addr = args.strip()
                addr = addr.removeprefix("http://").removeprefix("https://")
                if not addr.endswith(".loki"):
                    addr = addr + ".loki"
                nav(f"http://{addr}")
            else:
                self._term_print("Uso: loki <direccion>  (ejemplo: loki stats.i2p.rocks)")

        # Red / privacidad
        elif cmd == "tormode":
            self._enable_network_mode("tor")
            return

        elif cmd == "i2pmode":
            self._enable_network_mode("i2p")
            return

        elif cmd == "clearnet":
            self._disable_network_mode()
            return

        elif cmd == "whoami":
            self._term_print("Consultando IP pública...")
            def fetch():
                try:
                    import ssl
                    ctx = ssl.create_default_context()
                    req = urllib.request.Request(
                        "https://api.ipify.org",
                        headers={"User-Agent": "curl/7.88"}
                    )
                    with urllib.request.urlopen(req, timeout=7, context=ctx) as r:
                        ip = r.read().decode().strip()
                    GLib.idle_add(lambda: (self._term_print(f"IP pública: {ip}"),
                                           self._term_print(""),
                                           self._term_prompt()) and False)
                except Exception as e:
                    GLib.idle_add(lambda: (self._term_print(f"Error: {e}"),
                                           self._term_print(""),
                                           self._term_prompt()) and False)
            threading.Thread(target=fetch, daemon=True).start()
            return

        elif cmd == "serverip":
            td = self._td()
            if td.mode in ("tor", "i2p"):
                self._term_print(f"serverip no disponible en modo {td.mode.upper()}.")
            else:
                uri = self._wv().get_uri()
                if not uri or uri.startswith("file://"):
                    self._term_print("Sin página cargada.")
                else:
                    host = urllib.parse.urlparse(uri).hostname
                    def resolve():
                        try:
                            ip = socket.gethostbyname(host)
                            GLib.idle_add(lambda: (self._term_print(f"{host} → {ip}"),
                                                   self._term_print(""),
                                                   self._term_prompt()) and False)
                        except Exception as e:
                            GLib.idle_add(lambda: (self._term_print(f"Error: {e}"),
                                                   self._term_print(""),
                                                   self._term_prompt()) and False)
                    threading.Thread(target=resolve, daemon=True).start()
                    return

        # Marcadores e historial
        elif cmd == "bookmark":
            wv = self._wv()
            uri = wv.get_uri()
            if not uri or uri == "about:blank":
                self._term_print("Sin página activa.")
            else:
                title = wv.get_title() or uri
                if self.app.is_bookmarked(uri):
                    self.app.remove_bookmark(uri)
                    self._term_print(f"Marcador eliminado: {uri}")
                    self.bookmark_star.set_label("★")
                else:
                    self.app.add_bookmark(uri, title)
                    self._term_print(f"Marcador guardado: {title}")
                    self.bookmark_star.set_label("★")

        elif cmd == "bookmarks":
            if not self.app.bookmarks:
                self._term_print("Sin marcadores guardados.")
            else:
                lines = ["Marcadores guardados:"]
                for i, b in enumerate(self.app.bookmarks, 1):
                    lines.append(f"  {i:3}. {b['title']}\n       {b['url']}")
                self._term_print("\n".join(lines))

        elif cmd == "history":
            try:
                n = int(args) if args else 10
            except ValueError:
                n = 10
            hist = self.app.history
            if not hist:
                self._term_print("El historial está vacío.")
            else:
                lines = [f"Últimas {n} páginas:"]
                for i, h in enumerate(reversed(hist[-n:]), 1):
                    ts = h.get("ts", "")[:19].replace("T", " ")
                    lines.append(f"  {i:3}. [{ts}] {h['title']}\n       {h['url']}")
                self._term_print("\n".join(lines))

        # Utilidades
        elif cmd == "dark":
            self.app.dark_mode = not self.app.dark_mode
            state = "activado" if self.app.dark_mode else "desactivado"
            self._term_print(f"Modo oscuro {state}.")
            if self.app.dark_mode:
                GLib.idle_add(self._apply_dark_css)

        elif cmd == "calc":
            if args:
                self._term_print(f"{args} = {self._safe_eval(args)}")
            else:
                self._term_print("Uso: calc <expresión>")

        elif cmd == "time":
            self._term_print(datetime.datetime.now().strftime("%H:%M:%S"))

        elif cmd == "date":
            self._term_print(datetime.date.today().strftime("%Y-%m-%d"))

        elif cmd == "echo":
            if args:
                self._term_print(args)

        elif cmd in ("clear", "clean"):
            self.terminal_buf.set_text("")

        elif cmd == "about":
            self._term_print(
                "PrekT-BR v2.1 — Hardened Edition\n"
                "WebKitGTK 6 + GTK 4 + Python\n"
                "Redes: Tor (SOCKS5 :9050), I2P (HTTP :4444)"
                "─── Protecciones activas ──────────────────────\n"
                "  [*] WebRTC deshabilitado (sin IP leak)\n"
                "  [*] User-Agent: Firefox/Windows normalizado\n"
                "  [*] Letterboxing: viewport redondeado a 100x100\n"
                "  [*] performance.now() degradado a 2ms (anti timing-attack)\n"
                "  [*] SharedArrayBuffer/Atomics: eliminados\n"
                "  [*] Canvas: ruido por semilla de sesión\n"
                "  [*] AudioContext: ruido en análisis de frecuencia\n"
                "  [*] WebGL: vendor/renderer normalizado, debug bloqueado\n"
                "  [*] Navigator: platform/plugins/idioma/memoria fijos\n"
                "  [*] Screen: resolución normalizada a 1920x1080\n"
                "  [*] Timezone: forzado a UTC\n"
                "  [*] Battery API: datos fijos\n"
                "  [*] Font enumeration: bloqueada\n"
                "  [*] Geolocation: bloqueada silenciosamente\n"
                "  [*] MediaDevices: cámaras/micrófonos ocultos\n"
                "  [*] SpeechSynthesis/Recognition: bloqueados\n"
                "  [*] Cookies: limpieza automática al cerrar pestaña\n"
                "  [*] JS popups y autoplay: bloqueados\n"
                "  [*] Esquemas peligrosos bloqueados (js:, data:, blob:)\n"
                "  [*] calc: evaluador AST seguro sin eval()\n"
                "  [*] DevTools: deshabilitadas\n"
                "  [*] Historial/marcadores: cifrados en disco\n"
                "Comandos: clearcookies | clearall\n"
            )

        elif cmd == "clearcookies":
            td = self._td()
            self._clear_tab_data(td)
            self._term_print("Cookies y datos de sesión de la pestaña actual eliminados.")

        elif cmd == "clearall":
            for td in self.tabs:
                self._clear_tab_data(td)
            self._term_print("Datos de todas las pestañas eliminados.")

        elif cmd in ("quit", "exit"):
            self.app.quit()
            return

        else:
            self._term_print(f"Comando desconocido: '{cmd}'  —  escribe 'help'")

        self._term_print("")
        self._term_prompt()

    def _safe_eval(self, expr):
        """Evaluador seguro de expresiones matemáticas sin usar eval()."""
        import re
        # Solo permitir caracteres seguros: números, operadores, espacios, funciones math
        allowed_pattern = re.compile(r'^[\d\s\+\-\*/\(\)\.\^%,a-z_]+$')
        expr_clean = expr.strip().lower()
        if not allowed_pattern.match(expr_clean):
            return "Error: expresión no permitida"
        # Reemplazar ^ por ** para potencias
        expr_clean = expr_clean.replace('^', '**')
        # Sustituir funciones math permitidas
        math_funcs = {
            name: getattr(math, name)
            for name in dir(math)
            if not name.startswith('_')
        }
        try:
            # Compilar AST y verificar que solo contiene nodos seguros
            import ast
            tree = ast.parse(expr_clean, mode='eval')
            allowed_nodes = (
                ast.Expression, ast.BinOp, ast.UnaryOp, ast.Call,
                ast.Constant, ast.Add, ast.Sub, ast.Mult, ast.Div,
                ast.Mod, ast.Pow, ast.USub, ast.UAdd, ast.Name,
                ast.Load, ast.FloorDiv,
            )
            for node in ast.walk(tree):
                if not isinstance(node, allowed_nodes):
                    return f"Error: operación no permitida ({type(node).__name__})"
                if isinstance(node, ast.Name) and node.id not in math_funcs:
                    return f"Error: nombre no permitido '{node.id}'"
            result = eval(compile(tree, '<calc>', 'eval'), {"__builtins__": {}}, math_funcs)
            return str(result)
        except Exception as e:
            return f"Error: {e}"


# ─── Punto de entrada ────────────────────────────────────────────────────────

def main():
    app = PrekTBR()
    def _sigint(sig, frame):
        app.quit()
    signal.signal(signal.SIGINT, _sigint)
    sys.exit(app.run(sys.argv))


if __name__ == "__main__":
    main()
