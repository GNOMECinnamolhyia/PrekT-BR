#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import gi
import urllib.parse
import datetime
import math
import signal
import socket
import threading
import urllib.request

os.environ["GDK_DEBUG"] = "portals"  # Silencia warnings de portal

gi.require_version('Gtk', '4.0')
gi.require_version('WebKit', '6.0')

from gi.repository import Gtk, WebKit, Gio, GLib, Gdk


def sigint_handler(app):
    def handler(sig, frame):
        app.quit()
    return handler


class PrekTBR(Gtk.Application):
    def __init__(self):
        super().__init__(
            application_id='com.cinnamolhyia.prektbr',
            flags=Gio.ApplicationFlags.HANDLES_OPEN
        )
        self.home_uri = "file://" + os.path.abspath("newtab.html")
        self.initial_url = self.home_uri
        self.dark_mode = False
        self.url_history = []  # historial global de URLs visitadas

    def do_startup(self):
        Gtk.Application.do_startup(self)

    def do_activate(self):
        win = self.props.active_window
        if not win:
            win = BrowserWindow(self)
            win.set_default_size(1200, 800)
        win.present()

    def do_open(self, files, n_files, hint):
        win = self.props.active_window
        if not win:
            win = BrowserWindow(self)
            win.set_default_size(1200, 800)
        if files and n_files > 0:
            win.load_uri(files[0].get_uri())
        else:
            win.load_uri(self.home_uri)
        win.present()


class BrowserWindow(Gtk.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app, title="PrekT-BR")

        self.app = app
        self.tor_active = False

        # --- Sistema de 3 pestañas ---
        # Cada pestaña tiene su propio WebView y estado tor
        self.tabs = []       # lista de dicts: {webview, tor_active}
        self.current_tab = 0

        for i in range(3):
            wv = self._create_webview(tor=False)
            wv.load_uri(self.app.home_uri)
            self.tabs.append({"webview": wv, "tor_active": False})

        # La pestaña activa se accede con self._wv() — ver método más abajo

        self.settings = self.tabs[0]["webview"].get_settings()

        # --- CSS ---
        provider = Gtk.CssProvider()
        css = b"""
        .matrix-terminal {
            background-color: #000000;
            color: #00FF00;
            font-family: monospace;
            font-size: 14px;
            padding: 8px;
            caret-color: #00FF00;
        }
        .tab-active {
            background: #444;
            color: #fff;
            font-weight: bold;
        }
        """
        provider.load_from_data(css)
        display = self.get_display()
        Gtk.StyleContext.add_provider_for_display(display, provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)

        # --- Barra de pestañas ---
        self.tab_buttons = []
        tab_bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=4)
        tab_bar.set_margin_start(12)
        tab_bar.set_margin_top(4)
        for i in range(3):
            btn = Gtk.Button(label=f" Tab {i+1} ")
            btn.connect('clicked', self._on_tab_clicked, i)
            self.tab_buttons.append(btn)
            tab_bar.append(btn)
        self.tab_buttons[0].add_css_class("tab-active")

        # --- Barra de navegación ---
        self.url_entry = Gtk.Entry()
        self.url_entry.set_text(self.app.initial_url)
        self.url_entry.set_hexpand(True)
        self.url_entry.connect('activate', self.on_url_activate)

        go_button = Gtk.Button(label="Ir")
        go_button.connect('clicked', self.on_go_clicked)

        back_button = Gtk.Button(label=" ← ")
        back_button.connect('clicked', lambda b: self._wv().go_back() if self._wv().can_go_back() else None)

        forward_button = Gtk.Button(label=" → ")
        forward_button.connect('clicked', lambda b: self._wv().go_forward() if self._wv().can_go_forward() else None)

        reload_button = Gtk.Button(label=" ↻ ")
        reload_button.connect('clicked', lambda b: self._wv().reload())

        home_button = Gtk.Button(label="Home")
        home_button.connect('clicked', self.on_home_clicked)

        self.terminal_button = Gtk.Button(label="Terminal")
        self.terminal_button.connect('clicked', self.on_toggle_terminal)

        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        header.set_margin_top(6)
        header.set_margin_bottom(6)
        header.set_margin_start(12)
        header.set_margin_end(12)

        header.append(back_button)
        header.append(forward_button)
        header.append(reload_button)
        header.append(home_button)
        header.append(self.terminal_button)
        header.append(self.url_entry)
        header.append(go_button)

        # --- Terminal ---
        self.terminal_buffer = Gtk.TextBuffer()
        self.terminal_view = Gtk.TextView(buffer=self.terminal_buffer)
        self.terminal_view.set_editable(True)
        self.terminal_view.set_cursor_visible(True)
        self.terminal_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self.terminal_view.set_monospace(True)
        self.terminal_view.add_css_class("matrix-terminal")

        self.scroll_terminal = Gtk.ScrolledWindow()
        self.scroll_terminal.set_vexpand(True)
        self.scroll_terminal.set_hexpand(True)
        self.scroll_terminal.set_min_content_width(300)
        self.scroll_terminal.set_child(self.terminal_view)

        key_controller = Gtk.EventControllerKey()
        key_controller.connect('key-pressed', self.on_terminal_key_pressed)
        self.terminal_view.add_controller(key_controller)

        # --- Stack para las 3 pestañas ---
        self.tab_stack = Gtk.Stack()
        self.tab_stack.set_vexpand(True)
        self.tab_stack.set_hexpand(True)
        for i, tab in enumerate(self.tabs):
            self.tab_stack.add_named(tab["webview"], f"tab{i}")
        self.tab_stack.set_visible_child_name("tab0")

        self.content_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        self.content_box.set_vexpand(True)
        self.content_box.set_hexpand(True)
        self.content_box.append(self.tab_stack)

        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        main_box.append(tab_bar)
        main_box.append(header)
        main_box.append(self.content_box)

        self.set_child(main_box)

        self.print_to_terminal("PrekT-BR terminal\nFUNCIONES: 'help' para ver todos los comandos\n")
        self.print_prompt()

        self.terminal_visible = False

    def _wv(self):
        """Devuelve el WebView de la pestaña activa."""
        return self.tabs[self.current_tab]["webview"]

    def _on_tab_clicked(self, button, index):
        """Cambia a la pestaña indicada."""
        # Quitar estilo activo de todas
        for btn in self.tab_buttons:
            btn.remove_css_class("tab-active")
        self.current_tab = index
        self.tab_buttons[index].add_css_class("tab-active")
        self.tab_stack.set_visible_child_name(f"tab{index}")
        # Actualizar URL entry con la URL de la nueva pestaña
        uri = self._wv().get_uri()
        if uri and uri != "about:blank":
            self.url_entry.set_text(uri)
        else:
            self.url_entry.set_text(self.app.home_uri)
        # Actualizar título
        title = self._wv().get_title()
        self.set_title(f"[Tab {index+1}] {title}" if title else f"PrekT-BR — Tab {index+1}")

    def _update_tab_label(self):
        """Actualiza el label del botón de pestaña activa con el título de la página."""
        title = self._wv().get_title()
        short = (title[:12] + "…") if title and len(title) > 12 else (title or f"Tab {self.current_tab+1}")
        self.tab_buttons[self.current_tab].set_label(f" {short} ")

    def _create_webview(self, tor=False):
        """Crea un WebView nuevo, con o sin proxy Tor."""
        if tor:
            try:
                network_session = WebKit.NetworkSession.new_ephemeral()
                proxy_settings = WebKit.NetworkProxySettings.new(
                    "socks5://127.0.0.1:9050", None
                )
                network_session.set_proxy_settings(
                    WebKit.NetworkProxyMode.CUSTOM, proxy_settings
                )
                webview = WebKit.WebView(network_session=network_session)
            except Exception:
                os.environ["SOCKS_PROXY"] = "socks5://127.0.0.1:9050"
                webview = WebKit.WebView()

            settings = WebKit.Settings.new()
            settings.set_enable_webrtc(False)
            settings.set_enable_mediasource(False)
            settings.set_enable_encrypted_media(False)
            settings.set_user_agent(
                "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0"
            )
            webview.set_settings(settings)
        else:
            webview = WebKit.WebView()

        webview.set_vexpand(True)
        webview.set_hexpand(True)

        webview.connect('notify::uri', self.on_uri_changed)
        webview.connect('notify::title', self.on_title_changed)
        webview.connect('load-changed', self.on_load_changed)

        return webview

    def _swap_webview_in_tab(self, tab_index, new_webview, load_uri=None):
        """Reemplaza el WebView de una pestaña específica."""
        old_wv = self.tabs[tab_index]["webview"]
        current_uri = old_wv.get_uri()
        self.tab_stack.remove(old_wv)
        self.tabs[tab_index]["webview"] = new_webview
        self.tab_stack.add_named(new_webview, f"tab{tab_index}")
        if tab_index == self.current_tab:
            self.tab_stack.set_visible_child_name(f"tab{tab_index}")
        uri_to_load = load_uri or current_uri
        if uri_to_load and uri_to_load != "about:blank":
            new_webview.load_uri(uri_to_load)
        else:
            new_webview.load_uri(self.app.home_uri)

    def print_prompt(self):
        self.print_to_terminal("> ", no_newline=True)

    def print_to_terminal(self, text, no_newline=False):
        end_iter = self.terminal_buffer.get_end_iter()
        if no_newline:
            self.terminal_buffer.insert(end_iter, text)
        else:
            self.terminal_buffer.insert(end_iter, text + "\n")
        self.terminal_view.scroll_to_iter(end_iter, 0.0, True, 0.0, 1.0)

    def clear_terminal(self):
        self.terminal_buffer.set_text("")
        self.print_prompt()

    def on_toggle_terminal(self, button):
        if self.terminal_visible:
            self.content_box.remove(self.scroll_terminal)
            self.terminal_visible = False
        else:
            self.content_box.append(self.scroll_terminal)
            self.terminal_visible = True
            self.terminal_view.grab_focus()

    def on_terminal_key_pressed(self, controller, keyval, keycode, state):
        if keyval == Gdk.KEY_Return or keyval == Gdk.KEY_KP_Enter:
            start = self.terminal_buffer.get_start_iter()
            end = self.terminal_buffer.get_end_iter()
            full_text = self.terminal_buffer.get_text(start, end, False).rstrip()
            lines = full_text.split('\n')
            if lines:
                last_line = lines[-1].strip()
                if last_line.startswith("> "):
                    command = last_line[2:].strip()
                    if command:
                        self.print_to_terminal("")
                        self.process_command(command)
                        self.print_to_terminal("")
            self.print_prompt()
            return True
        return False

    def safe_eval(self, expr):
        allowed_names = {"__builtins__": {}, "math": math}
        try:
            result = eval(expr, allowed_names, {})
            return str(result)
        except Exception as e:
            return f"Error: {str(e)}"

    def on_load_changed(self, webview, load_event):
        if load_event == WebKit.LoadEvent.FINISHED and self.app.dark_mode:
            GLib.timeout_add(600, self.apply_dark_css)

    def apply_dark_css(self):
        css_dark = """
        :root { color-scheme: dark !important; }
        * { background: #111 !important; color: #eee !important; border-color: #333 !important; }
        a { color: #8cf !important; }
        """
        js = f"""
        (function() {{
            let style = document.getElementById('prekt-dark');
            if (!style) {{
                style = document.createElement('style');
                style.id = 'prekt-dark';
                style.textContent = `{css_dark}`;
                document.head.appendChild(style);
            }}
        }})();
        """
        self._wv().evaluate_javascript(js, -1, None, None, None, None)
        return False

    def enable_tor_mode(self):
        tab = self.tabs[self.current_tab]
        if tab["tor_active"]:
            self.print_to_terminal(f"La Tab {self.current_tab+1} ya tiene Tor activo.")
            return
        try:
            os.environ["SOCKS5_SERVER"] = "127.0.0.1:9050"
            os.environ["SOCKS_PROXY"] = "socks5://127.0.0.1:9050"
            new_webview = self._create_webview(tor=True)
            self._swap_webview_in_tab(self.current_tab, new_webview)
            tab["tor_active"] = True
            self.tor_active = True  # para compatibilidad con apply_dark_css etc.
            self.print_to_terminal(f"  MODO TOR ACTIVADO EN TAB {self.current_tab+1}")
            self.print_to_terminal("  WebRTC DESACTIVADO.")
            self.print_to_terminal("  TEN CUIDADO.")
            self.print_to_terminal("  QUITA LA S DE LOS HTTPS:// EN SITIOS .ONION.")
        except Exception as e:
            self.print_to_terminal(f"Error al activar Tor: {str(e)}")

    def disable_tor_mode(self):
        tab = self.tabs[self.current_tab]
        if not tab["tor_active"]:
            self.print_to_terminal(f"La Tab {self.current_tab+1} no tiene Tor activo.")
            return
        try:
            new_webview = self._create_webview(tor=False)
            self._swap_webview_in_tab(self.current_tab, new_webview)
            tab["tor_active"] = False
            # Actualizar self.tor_active global
            self.tor_active = any(t["tor_active"] for t in self.tabs)
            self.print_to_terminal(f"  MODO TOR DESACTIVADO EN TAB {self.current_tab+1}")
            self.print_to_terminal("  Volviendo a sesión normal.")
        except Exception as e:
            self.print_to_terminal(f"Error al desactivar Tor: {str(e)}")

    def process_command(self, cmd):
        parts = cmd.split(maxsplit=1)
        command = parts[0].lower() if parts else ""
        args = parts[1].strip() if len(parts) > 1 else ""

        if command == "help":
            self.print_to_terminal(
                "Comandos disponibles:\n"
                "  help                      → esta lista\n"
                "  home                      → va a newtab.html\n"
                "  google algo               → busca en Google\n"
                "  yt video                  → busca en YouTube\n"
                "  wiki algo                 → Wikipedia (es)\n"
                "  cat                       → imágenes de gatos\n"
                "  calc 2+3*4                → evalúa matemática\n"
                "  time                      → hora actual\n"
                "  date                      → fecha actual\n"
                "  duckduckgo [algo]         → abre DDG\n"
                "  new https://...           → abre URL\n"
                "  dark                      → toggle modo oscuro\n"
                "  say hola                  → popup\n"
                "  clear / clean             → limpia terminal\n"
                "  about                     → info del navegador\n"
                "  reload                    → recarga página\n"
                "  back                      → atrás\n"
                "  forward                   → adelante\n"
                "  echo algo                 → repite texto\n"
                "  quit / exit               → cierra el navegador\n"
                "  arburarbustribiet         → Arbur Arbustribiet!!!\n"
                "  tormode                   → activa Tor en la pestaña activa\n"
                "  untor                     → desactiva Tor en la pestaña activa\n"
                "  whoami                    → tu IP pública (funciona siempre)\n"
                "  serverip                  → IPs de los servidores de las 3 pestañas\n"
                "  historyten                → últimas 10 páginas visitadas\n"
            )

        elif command == "tormode":
            self.enable_tor_mode()

        elif command == "untor":
            self.disable_tor_mode()

        elif command == "whoami":
            self.print_to_terminal("Consultando IP pública...")
            def fetch_ip():
                try:
                    with urllib.request.urlopen("https://api.ipify.org", timeout=5) as resp:
                        ip = resp.read().decode().strip()
                    def show(ip=ip):
                        self.print_to_terminal(f"Tu IP pública: {ip}")
                        self.print_to_terminal("")
                        self.print_prompt()
                    GLib.idle_add(show)
                except Exception as e:
                    def show_err(e=e):
                        self.print_to_terminal(f"No se pudo obtener la IP: {e}")
                        self.print_to_terminal("")
                        self.print_prompt()
                    GLib.idle_add(show_err)
            threading.Thread(target=fetch_ip, daemon=True).start()
            return  # no imprimir prompt doble

        elif command == "serverip":
            if self.tabs[self.current_tab]["tor_active"]:
                self.print_to_terminal("serverip no está disponible en modo Tor (por tu seguridad).")
            else:
                self.print_to_terminal("Resolviendo IPs de las 3 pestañas...")
                def resolve_all():
                    lines = []
                    for i, tab in enumerate(self.tabs):
                        uri = tab["webview"].get_uri()
                        if not uri or uri.startswith("file://") or uri == "about:blank":
                            lines.append(f"  Tab {i+1}: sin página cargada")
                            continue
                        try:
                            parsed = urllib.parse.urlparse(uri)
                            host = parsed.hostname
                            ip = socket.gethostbyname(host)
                            lines.append(f"  Tab {i+1}: {host} → {ip}")
                        except Exception as e:
                            lines.append(f"  Tab {i+1}: error: {e}")
                    def show(lines=lines):
                        self.print_to_terminal("\n".join(lines))
                        self.print_to_terminal("")
                        self.print_prompt()
                    GLib.idle_add(show)
                threading.Thread(target=resolve_all, daemon=True).start()
                return  # no imprimir prompt doble

        elif command == "historyten":
            history = self.app.url_history
            if not history:
                self.print_to_terminal("El historial está vacío.")
            else:
                last10 = history[-10:]
                lines = ["Últimas páginas visitadas:"]
                for i, url in enumerate(reversed(last10), 1):
                    lines.append(f"  {i:2}. {url}")
                self.print_to_terminal("\n".join(lines))

        elif command == "home":
            self._wv().load_uri(self.app.home_uri)

        elif command == "google":
            if args:
                query = urllib.parse.quote(args)
                url = f"https://www.google.com/search?q={query}"
                self._wv().load_uri(url)
            else:
                self._wv().load_uri("https://www.google.com")

        elif command == "yt":
            if args:
                query = urllib.parse.quote(args)
                url = f"https://www.youtube.com/results?search_query={query}"
                self._wv().load_uri(url)
            else:
                self._wv().load_uri("https://www.youtube.com")

        elif command == "wiki":
            if args:
                query = urllib.parse.quote(args)
                url = f"https://es.wikipedia.org/wiki/{query}"
                self._wv().load_uri(url)
            else:
                self._wv().load_uri("https://es.wikipedia.org")

        elif command == "cat":
            self._wv().load_uri("https://www.google.com/search?q=gatos+graciosos&tbm=isch")

        elif command == "calc":
            if args:
                result = self.safe_eval(args)
                self.print_to_terminal(f"{args} = {result}")

        elif command == "time":
            now = datetime.datetime.now().strftime("%H:%M:%S")
            self.print_to_terminal(f"{now}")

        elif command == "date":
            today = datetime.date.today().strftime("%Y-%m-%d")
            self.print_to_terminal(f"{today}")

        elif command == "duckduckgo":
            if args:
                query = urllib.parse.quote(args)
                url = f"https://duckduckgo.com/?q={query}"
                self._wv().load_uri(url)
            else:
                self._wv().load_uri("https://duckduckgo.com")

        elif command == "new":
            if args:
                if not args.startswith(('http://', 'https://', 'file://')):
                    args = 'https://' + args
                self._wv().load_uri(args)

        elif command == "dark":
            self.app.dark_mode = not self.app.dark_mode
            if self.app.dark_mode:
                self.apply_dark_css()

        elif command == "say":
            if args:
                dialog = Gtk.AlertDialog()
                dialog.set_message(args)
                dialog.set_detail("Mensaje de PrekT-BR")
                dialog.set_buttons(["OK"])
                dialog.show(self)

        elif command == "arburarbustribiet":
            dialog = Gtk.AlertDialog()
            dialog.set_message("Arbur Arbustribiet")
            dialog.set_detail("")
            dialog.set_buttons(["OK"])
            dialog.show(self)
            self.print_to_terminal("Arbur Arbustribiet")

        elif command == "about":
            self.print_to_terminal("PrekT-BR\nNavegador casero con WebKitGTK + terminal\nv1.0.1")

        elif command in ("clear", "clean"):
            self.clear_terminal()

        elif command == "reload":
            self._wv().reload()

        elif command == "back":
            if self._wv().can_go_back():
                self._wv().go_back()

        elif command == "forward":
            if self._wv().can_go_forward():
                self._wv().go_forward()

        elif command == "echo":
            if args:
                self.print_to_terminal(args)

        elif command in ("quit", "exit"):
            self.app.quit()

        else:
            self.print_to_terminal(f"Comando desconocido: {cmd}\nPrueba 'help'")

    def on_home_clicked(self, button):
        self._wv().load_uri(self.app.home_uri)

    def on_url_activate(self, entry):
        url = entry.get_text().strip()
        if not url:
            return
        if not url.startswith(('http://', 'https://', 'file://', 'about:')):
            url = 'https://' + url
        self._wv().load_uri(url)

    def on_go_clicked(self, button):
        self.on_url_activate(self.url_entry)

    def on_uri_changed(self, webview, param):
        # Puede dispararse durante __init__ antes de que tabs/tab_buttons estén listos
        if not hasattr(self, 'tabs') or not self.tabs or not hasattr(self, 'url_entry'):
            return
        uri = webview.get_uri()
        if uri and uri != "about:blank":
            if webview == self._wv():
                self.url_entry.set_text(uri)
            if not self.app.url_history or self.app.url_history[-1] != uri:
                self.app.url_history.append(uri)

    def on_title_changed(self, webview, param):
        if not hasattr(self, 'tabs') or not self.tabs or not hasattr(self, 'tab_buttons'):
            return
        title = webview.get_title()
        for i, tab in enumerate(self.tabs):
            if tab["webview"] == webview:
                short = (title[:12] + "…") if title and len(title) > 12 else (title or f"Tab {i+1}")
                self.tab_buttons[i].set_label(f" {short} ")
                break
        if webview == self._wv():
            self.set_title(title if title else "PrekT-BR :3")


def main():
    app = PrekTBR()
    signal.signal(signal.SIGINT, sigint_handler(app))
    app.run(sys.argv)


if __name__ == "__main__":
    main()
