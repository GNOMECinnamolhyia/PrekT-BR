#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import gi
import urllib.parse
import datetime
import math
import signal

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

        # WebView inicial (sesión normal)
        self.webview = self._create_webview(tor=False)

        self.settings = self.webview.get_settings()

        # Barra superior
        self.url_entry = Gtk.Entry()
        self.url_entry.set_text(self.app.initial_url)
        self.url_entry.set_hexpand(True)
        self.url_entry.connect('activate', self.on_url_activate)

        go_button = Gtk.Button(label="Ir")
        go_button.connect('clicked', self.on_go_clicked)

        back_button = Gtk.Button(label=" ← ")
        back_button.connect('clicked', lambda b: self.webview.go_back() if self.webview.can_go_back() else None)

        forward_button = Gtk.Button(label=" → ")
        forward_button.connect('clicked', lambda b: self.webview.go_forward() if self.webview.can_go_forward() else None)

        reload_button = Gtk.Button(label=" ↻ ")
        reload_button.connect('clicked', lambda b: self.webview.reload())

        home_button = Gtk.Button(label="Home")
        home_button.connect('clicked', self.on_home_clicked)

        self.terminal_button = Gtk.Button(label="Terminal")
        self.terminal_button.connect('clicked', self.on_toggle_terminal)

        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        header.set_margin_top(10)
        header.set_margin_bottom(10)
        header.set_margin_start(12)
        header.set_margin_end(12)

        header.append(back_button)
        header.append(forward_button)
        header.append(reload_button)
        header.append(home_button)
        header.append(self.terminal_button)
        header.append(self.url_entry)
        header.append(go_button)

        # Terminal
        self.terminal_buffer = Gtk.TextBuffer()
        self.terminal_view = Gtk.TextView(buffer=self.terminal_buffer)
        self.terminal_view.set_editable(True)
        self.terminal_view.set_cursor_visible(True)
        self.terminal_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self.terminal_view.set_monospace(True)
        self.terminal_view.add_css_class("matrix-terminal")

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
        """
        provider.load_from_data(css)
        display = self.get_display()
        Gtk.StyleContext.add_provider_for_display(display, provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)

        self.scroll_terminal = Gtk.ScrolledWindow()
        self.scroll_terminal.set_vexpand(True)
        self.scroll_terminal.set_hexpand(True)
        self.scroll_terminal.set_min_content_width(300)
        self.scroll_terminal.set_child(self.terminal_view)

        key_controller = Gtk.EventControllerKey()
        key_controller.connect('key-pressed', self.on_terminal_key_pressed)
        self.terminal_view.add_controller(key_controller)

        self.content_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        self.content_box.append(self.webview)

        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        main_box.append(header)
        main_box.append(self.content_box)

        self.set_child(main_box)

        self.webview.load_uri(self.app.home_uri)

        self.print_to_terminal("PrekT-BR terminal\nNUEVA FUNCIONALIDAD: 'tormode' PARA ACCEDER A TOR\n")
        self.print_prompt()

        self.terminal_visible = False

    def _create_webview(self, tor=False):
        """Crea un WebView nuevo, con o sin proxy Tor."""
        if tor:
            # WebKitGTK 6.0: el proxy se configura en NetworkSession
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
                # Fallback: variable de entorno (menos elegante pero funciona)
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

        # Conectar señales
        webview.connect('notify::uri', self.on_uri_changed)
        webview.connect('notify::title', self.on_title_changed)
        webview.connect('load-changed', self.on_load_changed)

        return webview

    def _swap_webview(self, new_webview, load_uri=None):
        """Reemplaza el WebView actual por uno nuevo en el layout."""
        current_uri = self.webview.get_uri()
        self.content_box.remove(self.webview)
        self.webview = new_webview
        # Insertar antes del terminal si está visible
        self.content_box.prepend(self.webview)

        uri_to_load = load_uri or current_uri
        if uri_to_load and uri_to_load != "about:blank":
            self.webview.load_uri(uri_to_load)
        else:
            self.webview.load_uri(self.app.home_uri)

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
        self.webview.evaluate_javascript(js, -1, None, None, None, None)
        return False

    def enable_tor_mode(self):
        if self.tor_active:
            self.print_to_terminal("El modo Tor ya está activo.")
            return

        try:
            os.environ["SOCKS5_SERVER"] = "127.0.0.1:9050"
            os.environ["SOCKS_PROXY"] = "socks5://127.0.0.1:9050"
            new_webview = self._create_webview(tor=True)
            self._swap_webview(new_webview)
            self.tor_active = True
            self.print_to_terminal("  MODO TOR ACTIVADO")
            self.print_to_terminal("  WebRTC DESACTIVADO.")
            self.print_to_terminal("  TEN CUIDADO.")
            self.print_to_terminal("  QUITA LA S DE TODOS LOS HTTPS:// AUTOMATICOS CUANDO VISITES SITIOS ONION.")
        except Exception as e:
            self.print_to_terminal(f"Error al activar Tor: {str(e)}")

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
                "  tormode                   → activa modo Tor\n"
            )

        elif command == "tormode":
            self.enable_tor_mode()

        elif command == "home":
            self.webview.load_uri(self.app.home_uri)

        elif command == "google":
            if args:
                query = urllib.parse.quote(args)
                url = f"https://www.google.com/search?q={query}"
                self.webview.load_uri(url)
            else:
                self.webview.load_uri("https://www.google.com")

        elif command == "yt":
            if args:
                query = urllib.parse.quote(args)
                url = f"https://www.youtube.com/results?search_query={query}"
                self.webview.load_uri(url)
            else:
                self.webview.load_uri("https://www.youtube.com")

        elif command == "wiki":
            if args:
                query = urllib.parse.quote(args)
                url = f"https://es.wikipedia.org/wiki/{query}"
                self.webview.load_uri(url)
            else:
                self.webview.load_uri("https://es.wikipedia.org")

        elif command == "cat":
            self.webview.load_uri("https://www.google.com/search?q=gatos+graciosos&tbm=isch")

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
                self.webview.load_uri(url)
            else:
                self.webview.load_uri("https://duckduckgo.com")

        elif command == "new":
            if args:
                if not args.startswith(('http://', 'https://', 'file://')):
                    args = 'https://' + args
                self.webview.load_uri(args)

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
            self.print_to_terminal("PrekT-BR\nNavegador casero con WebKitGTK + terminal\nv1.0")

        elif command in ("clear", "clean"):
            self.clear_terminal()

        elif command == "reload":
            self.webview.reload()

        elif command == "back":
            if self.webview.can_go_back():
                self.webview.go_back()

        elif command == "forward":
            if self.webview.can_go_forward():
                self.webview.go_forward()

        elif command == "echo":
            if args:
                self.print_to_terminal(args)

        elif command in ("quit", "exit"):
            self.app.quit()

        else:
            self.print_to_terminal(f"Comando desconocido: {cmd}\nPrueba 'help'")

    def on_home_clicked(self, button):
        self.webview.load_uri(self.app.home_uri)

    def on_url_activate(self, entry):
        url = entry.get_text().strip()
        if not url:
            return
        if not url.startswith(('http://', 'https://', 'file://', 'about:')):
            url = 'https://' + url
        self.webview.load_uri(url)

    def on_go_clicked(self, button):
        self.on_url_activate(self.url_entry)

    def on_uri_changed(self, webview, param):
        uri = webview.get_uri()
        if uri and uri != "about:blank":
            self.url_entry.set_text(uri)

    def on_title_changed(self, webview, param):
        title = webview.get_title()
        self.set_title(title if title else "PrekT-BR")


def main():
    app = PrekTBR()
    signal.signal(signal.SIGINT, sigint_handler(app))
    app.run(sys.argv)


if __name__ == "__main__":
    main()
