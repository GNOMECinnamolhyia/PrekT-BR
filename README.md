# PrekT-BR 

Un navegador con terminal personalizada hecho con **Python/C + GTK4 + WebKitGTK 6.0**.

Tiene barra de navegación, pestaña lateral con terminal de comandos personalizados, modo oscuro, y algunos mas

## Características

- Interfaz GTK4
- Motor WebKitGTK 6.0 (rápido y ligero, creo)
- Terminal lateral con comandos custom (presiona Terminal para abrirla)

## Requisitos (Arch Linux)

Necesitas instalar estos paquetes:

gtk4
webkitgtk-6.0
python
python-gobject
xdg-desktop-portal
xdg-desktop-portal-gtk
gobject-introspection
tor
torsocks

## Funcionalidad de Tor

Este navegador tiene la funcion tormode para poder acceder a sitios onion, TEN CUIDADO, este navegador no esta hecho para reemplazar al Tor Browser.
Siempre usa el Tor Browser antes que la funcion tormode de este navegador.

Ademas de que siempre que quieras usar la funcionalidad de Tor tienes que hacer sudo systemctl start tor (para distros que usan systemd)

## Funcionalidad de I2P (beta de la version 2.0)

El archivo de beta.py contiene la beta de la version 2.0 con pestañas que se pueden abrir y cerrar (no solo 3 fijas), ademas de tener el modo I2P que puede acceder a sitios .i2p, osea que tecnicamente aunque no sea oficial, este seria el primer I2P Browser del mundo!!!!, jaja

Ademas de que siempre que quieras usar la funcionalidad de I2P tienes que hacer sudo systemctl start i2pd (para distros que usan systemd)

## Requisitos (Arch Linux, beta PrekT-BR 2.0)

Necesitas instalar estos paquetes:

gtk4
webkitgtk-6.0
python
python-gobject
xdg-desktop-portal
xdg-desktop-portal-gtk
gobject-introspection
tor
torsocks
i2pd
