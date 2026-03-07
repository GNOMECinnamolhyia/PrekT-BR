#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#  PrekT-BR — Navegador personal basado en WebKitGTK 6
#  Versión 2.0
#

import sys
import os
import gi
import json
import math
import signal
import socket
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

# ─── Persistencia ────────────────────────────────────────────────────────────

def load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default

def save_json(path, data):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
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
        self.back_btn    = self._nav_btn("Atras",    "Atras",            self._on_back)
        self.forward_btn = self._nav_btn("Adelante", "Adelante",         self._on_forward)
        self.reload_btn  = self._nav_btn("Recargar", "Recargar",         self._on_reload)
        self.home_btn    = self._nav_btn("Inicio",   "Ir al inicio",     self._on_home)
        self.bookmark_star = self._nav_btn("Marcar", "Guardar marcador", self._on_toggle_bookmark)

        self.url_entry = Gtk.Entry()
        self.url_entry.set_hexpand(True)
        self.url_entry.add_css_class("url-entry")
        self.url_entry.set_placeholder_text("Ingresa una URL o busca en DuckDuckGo...")
        self.url_entry.connect("activate", self._on_url_activate)

        self.badge = Gtk.Label(label="")
        self.badge.add_css_class("badge-normal")
        self.badge.set_tooltip_text("Modo de red actual")
        self.badge.set_visible(False)

        bmarks_btn = self._nav_btn("Marcadores", "Marcadores", lambda _: self._toggle_sidebar("bookmarks"))
        history_btn = self._nav_btn("Historial", "Historial", lambda _: self._toggle_sidebar("history"))
        terminal_btn = self._nav_btn("Terminal", "Terminal", self._on_toggle_terminal)

        nav_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=4)
        nav_box.add_css_class("toolbar")
        for w in [self.back_btn, self.forward_btn, self.reload_btn, self.home_btn,
                  self.url_entry, self.bookmark_star, self.badge,
                  bmarks_btn, history_btn, terminal_btn]:
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

        # Terminal
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

        # Barra de estado
        self.statusbar = Gtk.Label(label="")
        self.statusbar.add_css_class("statusbar")
        self.statusbar.set_halign(Gtk.Align.START)
        self.statusbar.set_ellipsize(3)  # PANGO_ELLIPSIZE_END

        root.append(tabbar_row)
        root.append(nav_box)
        root.append(self.content_area)
        root.append(self.statusbar)
        self.set_child(root)

        self._term_print("PrekT-BR v2.0  —  escribe 'help' para ver los comandos")
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

        self._switch_tab(idx)
        wv.load_uri(uri or self.app.home_uri)

    def _on_close_tab(self, idx):
        if len(self.tabs) == 1:
            self.tabs[0].webview.load_uri(self.app.home_uri)
            return
        td = self.tabs[idx]
        self.tab_stack.remove(td.webview)
        self.tabs.pop(idx)
        self._rebuild_tabbar()
        new_idx = min(idx, len(self.tabs) - 1)
        self._switch_tab(new_idx)

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
        s.set_enable_developer_extras(True)
        s.set_javascript_can_access_clipboard(False)
        if mode in ("tor", "i2p"):
            s.set_enable_webrtc(False)
            s.set_enable_mediasource(False)
            s.set_enable_encrypted_media(False)
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
        return wv

    # ── Señales del WebView ──────────────────────────────────────────────────

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
            self.reload_btn.set_label("Detener")
            self.reload_btn.set_tooltip_text("Detener carga")
        elif event == WebKit.LoadEvent.FINISHED:
            self.reload_btn.set_label("Recargar")
            self.reload_btn.set_tooltip_text("Recargar")
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

    def _on_reload(self, _):
        wv = self._wv()
        if wv.is_loading():
            wv.stop_loading()
        else:
            wv.reload()

    def _on_home(self, _):
        self._wv().load_uri(self.app.home_uri)

    def _on_url_activate(self, entry):
        text = entry.get_text().strip()
        if not text:
            return
        url = self._resolve_input(text)
        self._wv().load_uri(url)

    def _resolve_input(self, text):
        if text.startswith(("http://", "https://", "file://", "about:")):
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
            self.bookmark_star.set_label("Marcar")
            self.statusbar.set_label("Marcador eliminado")
        else:
            title = wv.get_title() or uri
            self.app.add_bookmark(uri, title)
            self.bookmark_star.set_label("[Marcado]")
            self.statusbar.set_label("Marcador guardado")
        GLib.timeout_add(2000, lambda: self.statusbar.set_label("") or False)
        # Refrescar sidebar si está abierto
        if self._sidebar_mode == "bookmarks":
            self._show_sidebar("bookmarks")

    def _update_bookmark_star(self):
        if not self.tabs:
            return
        uri = self._wv().get_uri()
        self.bookmark_star.set_label("[Marcado]" if self.app.is_bookmarked(uri or "") else "Marcar")

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
        if mode == "tor":
            self.badge.set_label("TOR")
            self.badge.add_css_class("badge-tor")
            self.badge.set_visible(True)
        elif mode == "i2p":
            self.badge.set_label("I2P")
            self.badge.add_css_class("badge-i2p")
            self.badge.set_visible(True)
        else:
            self.badge.set_label("")
            self.badge.set_visible(False)

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

    # ── Tor / I2P ────────────────────────────────────────────────────────────

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

    def _on_toggle_terminal(self, _):
        if self.terminal_visible:
            self.content_area.remove(self._term_scroll)
            self.terminal_visible = False
        else:
            self.content_area.append(self._term_scroll)
            self.terminal_visible = True
            self.terminal_tv.grab_focus()

    def _term_print(self, text, no_nl=False):
        end = self.terminal_buf.get_end_iter()
        self.terminal_buf.insert(end, text if no_nl else text + "\n")
        self.terminal_tv.scroll_to_iter(end, 0.0, True, 0.0, 1.0)

    def _term_prompt(self):
        self._term_print("> ", no_nl=True)

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
                "  reload                → recarga\n"
                "  home                  → página de inicio\n"
                "─── Búsqueda ─────────────────────────────────\n"
                "  ddg <consulta>        → DuckDuckGo\n"
                "  google <consulta>     → Google\n"
                "  yt <consulta>         → YouTube\n"
                "  wiki <consulta>       → Wikipedia (es)\n"
                "─── Privacidad / Red ─────────────────────────\n"
                "  tormode               → activa Tor en esta pestaña\n"
                "  i2pmode               → activa I2P en esta pestaña\n"
                "  clearnet              → vuelve a modo normal\n"
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
                "  about                 → info del navegador\n"
                "  quit                  → cierra el navegador\n"
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

        elif cmd == "home":
            nav(self.app.home_uri)

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
                    with urllib.request.urlopen("https://api.ipify.org", timeout=7) as r:
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
                    self.bookmark_star.set_label("Marcar")
                else:
                    self.app.add_bookmark(uri, title)
                    self._term_print(f"Marcador guardado: {title}")
                    self.bookmark_star.set_label("[Marcado]")

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
                "PrekT-BR v2.0\n"
                "WebKitGTK 6 + GTK 4 + Python\n"
                "Soporta Tor (SOCKS5 :9050) e I2P (HTTP :4444)\n"
                "Historial y marcadores persistentes en ~/.local/share/prektbr/"
            )

        elif cmd in ("quit", "exit"):
            self.app.quit()
            return

        elif cmd == "arburarbustribiet":
            self._term_print("Arbur Arbustribiet!!!")

        else:
            self._term_print(f"Comando desconocido: '{cmd}'  —  escribe 'help'")

        self._term_print("")
        self._term_prompt()

    def _safe_eval(self, expr):
        allowed = {"__builtins__": {}, "math": math}
        try:
            return str(eval(expr, allowed, {}))
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
