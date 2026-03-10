# PrekT-BR 

Un navegador con terminal personalizada hecho con **Python/C++ + GTK4 + WebKitGTK 6.0**.

Tiene barra de navegación, pestaña lateral con terminal de comandos personalizados, modo oscuro, y algunos mas

## Características

- Interfaz GTK4
- Motor WebKitGTK 6.0 (rápido y ligero, creo)
- Terminal lateral con comandos custom (presiona Terminal para abrirla)

## Funcionalidad de Tor

Este navegador tiene la funcion tormode para poder acceder a sitios onion, TEN CUIDADO, este navegador no esta hecho para reemplazar al Tor Browser.
Siempre usa el Tor Browser antes que la funcion tormode de este navegador.

Ademas de que siempre que quieras usar la funcionalidad de Tor tienes que hacer sudo systemctl start tor (para distros que usan systemd)

## Funcionalidad de I2P 

Este navegador tiene la funcion i2pmode para poder acceder a sitios onion, aunque no es tan "TEN CUIDADO" como en la funcion de tormode (porque no existe un I2P Browser oficial, solo un Firefox I2P Profile), sigue teniendo cuidado

Ademas de que siempre que quieras usar la funcionalidad de I2P tienes que hacer sudo systemctl start i2pd (para distros que usan systemd)

## Requisitos

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
Ademas de una herramienta para compilar C++ 
