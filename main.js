#!/usr/bin/env gjs
// -*- mode: javascript; indent-tabs-mode: nil -*-
//
//  PrekT-BR — Navegador personal basado en WebKitGTK 6
//  Versión 2.1 - SECURE ENHaNCED
//  Traducido a GJS (GNOME JavaScript)
//

import GLib from 'gi://GLib';
import Gio from 'gi://Gio';
import Gdk from 'gi://Gdk?version=4.0';
import Gtk from 'gi://Gtk?version=4.0';
import WebKit from 'gi://WebKit?version=6.0';
import GObject from 'gi://GObject';
import { programArgs } from 'system';

// ─── Rutas de datos ───────────────────────────────────────────────────────────

const DATA_DIR      = GLib.build_filenamev([GLib.get_home_dir(), '.local', 'share', 'prektbr']);
const HISTORY_FILE  = GLib.build_filenamev([DATA_DIR, 'history.json']);
const BOOKMARKS_FILE= GLib.build_filenamev([DATA_DIR, 'bookmarks.json']);
const _SALT_FILE    = GLib.build_filenamev([DATA_DIR, '.salt']);

GLib.mkdir_with_parents(DATA_DIR, 0o700);

// ─── Cifrado de datos en disco ────────────────────────────────────────────────

function _getOrCreateSalt() {
    try {
        if (GLib.file_test(_SALT_FILE, GLib.FileTest.EXISTS)) {
            const [ok, data] = GLib.file_get_contents(_SALT_FILE);
            if (ok && data.length === 32) return data;
        }
    } catch(e) {}
    // Generar 32 bytes aleatorios
    const salt = new Uint8Array(32);
    for (let i = 0; i < 32; i++) salt[i] = Math.floor(Math.random() * 256);
    try {
        GLib.file_set_contents(_SALT_FILE, salt);
        // chmod 600
        const f = Gio.File.new_for_path(_SALT_FILE);
        f.set_attribute_uint32('unix::mode', 0o600, Gio.FileQueryInfoFlags.NONE, null);
    } catch(e) {}
    return salt;
}

// PBKDF2-HMAC-SHA256 implementado con GLib/GChecksum
// GJS no expone PBKDF2 nativo, usamos una implementación manual simplificada
// compatible con la versión Python (mismos parámetros: 200000 iteraciones, dklen=64)
function _pbkdf2HmacSha256(password, salt, iterations, dklen) {
    // HMAC-SHA256 usando GLib.compute_hmac_for_data
    function hmac(key, data) {
        // GLib.compute_hmac_for_data espera key como string o bytes
        return GLib.compute_hmac_for_data(GLib.ChecksumType.SHA256, key, data);
    }
    function hmacBytes(key, data) {
        const hex = hmac(key, data);
        const result = new Uint8Array(32);
        for (let i = 0; i < 32; i++)
            result[i] = parseInt(hex.substr(i * 2, 2), 16);
        return result;
    }
    function xorArrays(a, b) {
        const r = new Uint8Array(a.length);
        for (let i = 0; i < a.length; i++) r[i] = a[i] ^ b[i];
        return r;
    }
    function intToBytes(n) {
        return new Uint8Array([n >> 24 & 0xff, n >> 16 & 0xff, n >> 8 & 0xff, n & 0xff]);
    }

    const blocks = Math.ceil(dklen / 32);
    let dk = new Uint8Array(0);

    for (let b = 1; b <= blocks; b++) {
        const saltBlock = new Uint8Array(salt.length + 4);
        saltBlock.set(salt);
        saltBlock.set(intToBytes(b), salt.length);

        let U = hmacBytes(password, saltBlock);
        let T = new Uint8Array(U);

        for (let i = 1; i < iterations; i++) {
            U = hmacBytes(password, U);
            T = xorArrays(T, U);
        }

        const prev = dk;
        dk = new Uint8Array(prev.length + T.length);
        dk.set(prev);
        dk.set(T, prev.length);
    }

    return dk.slice(0, dklen);
}

function _deriveKey(length = 64) {
    const user = GLib.get_user_name() || 'prektbr';
    const encoder = new TextEncoder();
    const password = new Uint8Array([...encoder.encode(user), ...encoder.encode('prektbr-v3')]);
    const salt = _getOrCreateSalt();
    return _pbkdf2HmacSha256(password, salt, 200000, length);
}

const _KEY = _deriveKey();

function _xorBytes(data) {
    const result = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i++)
        result[i] = data[i] ^ _KEY[i % _KEY.length];
    return result;
}

function loadJson(path, def) {
    try {
        const [ok, raw] = GLib.file_get_contents(path);
        if (!ok) return def;
        // Intentar descifrar (base64 + XOR)
        try {
            const b64str = new TextDecoder().decode(raw);
            const decoded = GLib.base64_decode(b64str);
            const plain = _xorBytes(decoded);
            return JSON.parse(new TextDecoder().decode(plain));
        } catch(e) {
            // Compatibilidad hacia atrás: JSON plano
            return JSON.parse(new TextDecoder().decode(raw));
        }
    } catch(e) {
        return def;
    }
}

function saveJson(path, data) {
    try {
        const raw = new TextEncoder().encode(JSON.stringify(data, null, 2));
        const encrypted = GLib.base64_encode(_xorBytes(raw));
        GLib.file_set_contents(path, new TextEncoder().encode(encrypted));
    } catch(e) {
        print(`[prektbr] Error guardando ${path}: ${e}`);
    }
}

// ─── CSS global ───────────────────────────────────────────────────────────────

const GLOBAL_CSS = `
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
`;

// ─── Anti-fingerprinting JS ───────────────────────────────────────────────────

const FP_PROTECTION_JS = `
(function() {
    'use strict';

    // ═══════════════════════════════════════════════════════════════════════
    // 1. LETTERBOXING — viewport redondeado a múltiplos de 100x100 (Tor-style)
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
    // ═══════════════════════════════════════════════════════════════════════
    (function() {
        const GRANULARITY = 2;
        const origNow = performance.now.bind(performance);
        performance.now = function() {
            return Math.round(origNow() / GRANULARITY) * GRANULARITY;
        };
        const origDateNow = Date.now;
        Date.now = function() {
            return Math.round(origDateNow() / GRANULARITY) * GRANULARITY;
        };
        try { delete window.SharedArrayBuffer; } catch(e) {}
        try { delete window.Atomics; } catch(e) {}
    })();

    // ═══════════════════════════════════════════════════════════════════════
    // 3. CANVAS FINGERPRINTING — ruido por sesión
    // ═══════════════════════════════════════════════════════════════════════
    (function() {
        const NOISE_SEED = (Math.random() * 0xFFFFFFFF) | 0;
        function noiseByte(index) {
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
            vendor:              'Google Inc.',
            vendorSub:           '',
            productSub:          '20030107',
            appName:             'Netscape',
            appVersion:          '5.0 (Windows)',
        };
        for (const [k, v] of Object.entries(overrides)) {
            try { Object.defineProperty(navigator, k, { get: () => v, configurable: true }); } catch(e) {}
        }
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
        const origLoad = document.fonts.load.bind(document.fonts);
        document.fonts.load = (font, txt) =>
            generic.some(g => font.toLowerCase().includes(g)) ? origLoad(font, txt) : Promise.resolve([]);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 11. WINDOW.NAME — limpiar
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
    // 15. SPEECH SYNTHESIS / RECOGNITION — bloquear
    // ═══════════════════════════════════════════════════════════════════════
    try {
        if (window.speechSynthesis) {
            window.speechSynthesis.getVoices = () => [];
        }
        delete window.SpeechRecognition;
        delete window.webkitSpeechRecognition;
    } catch(e) {}

})();
`;

// ─── Helpers ──────────────────────────────────────────────────────────────────

function encodeURIComponentQ(str) {
    return encodeURIComponent(str);
}

function resolveInput(text) {
    const dangerous = ['javascript:', 'data:', 'vbscript:', 'blob:'];
    const lower = text.trim().toLowerCase();
    for (const scheme of dangerous) {
        if (lower.startsWith(scheme))
            return 'about:blank';
    }
    if (text.startsWith('http://') || text.startsWith('https://') ||
        text.startsWith('about:') || text.startsWith('file://'))
        return text;
    if (text.includes('.') && !text.includes(' '))
        return 'https://' + text;
    return `https://duckduckgo.com/?q=${encodeURIComponentQ(text)}`;
}

function nowIso() {
    return new Date().toISOString();
}

// HTML formatter (para el inspector)
function formatHtml(html) {
    const INLINE_TAGS = new Set(['a','abbr','acronym','b','bdo','big','br','button','cite',
        'code','dfn','em','i','img','input','kbd','label','map','object','output','q',
        'samp','select','small','span','strong','sub','sup','textarea','time','tt','u','var']);
    const VOID_TAGS = new Set(['area','base','br','col','embed','hr','img','input','link',
        'meta','param','source','track','wbr']);
    const RAW_TAGS = new Set(['script','style']);

    let out = [];
    let indent = 0;
    let inRaw = false;

    function pad() { return '  '.repeat(indent); }

    // Parser manual simple
    let i = 0;
    while (i < html.length) {
        if (html[i] === '<') {
            // Comentario
            if (html.startsWith('<!--', i)) {
                const end = html.indexOf('-->', i);
                if (end === -1) break;
                out.push(`${pad()}${html.slice(i, end + 3)}`);
                i = end + 3;
                continue;
            }
            // DOCTYPE
            if (html.startsWith('<!', i)) {
                const end = html.indexOf('>', i);
                out.push(html.slice(i, end + 1));
                i = end + 1;
                continue;
            }
            // Cierre
            if (html[i + 1] === '/') {
                const end = html.indexOf('>', i);
                const tag = html.slice(i + 2, end).trim().toLowerCase().split(/\s/)[0];
                if (RAW_TAGS.has(tag)) inRaw = false;
                if (!VOID_TAGS.has(tag) && !INLINE_TAGS.has(tag)) indent = Math.max(0, indent - 1);
                out.push(`${inRaw ? '' : pad()}</${tag}>`);
                i = end + 1;
                continue;
            }
            // Apertura
            const end = html.indexOf('>', i);
            if (end === -1) break;
            const tagContent = html.slice(i + 1, end);
            const tagName = tagContent.trim().toLowerCase().split(/[\s\/]/)[0];
            const line = `${inRaw ? '' : pad()}<${tagContent}>`;
            out.push(line);
            if (RAW_TAGS.has(tagName)) { inRaw = true; }
            if (!VOID_TAGS.has(tagName) && !INLINE_TAGS.has(tagName) && !tagContent.endsWith('/'))
                indent++;
            i = end + 1;
        } else {
            // Texto
            const end = html.indexOf('<', i);
            const text = (end === -1 ? html.slice(i) : html.slice(i, end)).trim();
            if (text) out.push(`${inRaw ? '' : pad()}${text}`);
            i = end === -1 ? html.length : end;
        }
    }
    return out.filter(l => l.trim() !== '').join('\n');
}

// Evaluador seguro de expresiones matemáticas
function safeEval(expr) {
    const allowed = /^[\d\s\+\-\*\/\(\)\.\^%,a-z_]+$/;
    const clean = expr.trim().toLowerCase().replace(/\^/g, '**');
    if (!allowed.test(clean)) return 'Error: expresión no permitida';

    const mathFuncs = {};
    for (const name of Object.getOwnPropertyNames(Math)) {
        if (typeof Math[name] === 'function' || typeof Math[name] === 'number')
            mathFuncs[name] = Math[name];
    }

    // Lista blanca de identificadores
    const identRe = /[a-z_][a-z0-9_]*/g;
    let m;
    while ((m = identRe.exec(clean)) !== null) {
        if (!(m[0] in mathFuncs))
            return `Error: nombre no permitido '${m[0]}'`;
    }

    try {
        // Construir función con solo Math en scope
        const fn = new Function(...Object.keys(mathFuncs), `return (${clean})`);
        const result = fn(...Object.values(mathFuncs));
        return String(result);
    } catch(e) {
        return `Error: ${e.message}`;
    }
}

// ─── TabData ──────────────────────────────────────────────────────────────────

class TabData {
    constructor(webview, mode = 'normal') {
        this.webview = webview;
        this.mode = mode; // 'normal' | 'tor' | 'i2p'
    }
}

// ─── Ventana principal ────────────────────────────────────────────────────────

class BrowserWindow extends Gtk.ApplicationWindow {
    static { GObject.registerClass(this); }

    constructor(app) {
        super({ application: app, title: 'PrekT-BR' });
        this._app = app;
        this._tabs = [];
        this._currentTab = -1;
        this._sidebarMode = null;
        this._sidebarWidget = null;
        this._inspectorMode = false;
        this._findbarVisible = false;
        this._terminalVisible = false;
        this._promptEndOffset = 0;

        this._buildUi();
        this._openTab({ uri: app.homeUri });
    }

    // ── UI ────────────────────────────────────────────────────────────────

    _buildUi() {
        const root = new Gtk.Box({ orientation: Gtk.Orientation.VERTICAL, spacing: 0 });

        // Barra de pestañas
        this._tabbarBox = new Gtk.Box({ orientation: Gtk.Orientation.HORIZONTAL, spacing: 2 });
        this._tabbarBox.add_css_class('tabbar');

        const newTabBtn = new Gtk.Button({ label: '+' });
        newTabBtn.add_css_class('new-tab-btn');
        newTabBtn.set_tooltip_text('Nueva pestaña');
        newTabBtn.connect('clicked', () => this._openTab({}));

        const tabbarScroll = new Gtk.ScrolledWindow();
        tabbarScroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.NEVER);
        tabbarScroll.set_hexpand(true);
        tabbarScroll.set_child(this._tabbarBox);
        tabbarScroll.set_min_content_height(38);

        const tabbarRow = new Gtk.Box({ orientation: Gtk.Orientation.HORIZONTAL, spacing: 0 });
        tabbarRow.add_css_class('tabbar');
        tabbarRow.append(tabbarScroll);
        tabbarRow.append(newTabBtn);

        // Botones de navegación
        this._backBtn    = this._navBtn('←',   'Atrás (Alt+Izq)',                   () => this._onBack());
        this._forwardBtn = this._navBtn('→',   'Adelante (Alt+Der)',                () => this._onForward());
        this._reloadBtn  = this._navBtn('↻',   'Recargar (Ctrl+R) / Shift: sin caché', () => this._onReload());
        this._homeBtn    = this._navBtn('⌂',   'Ir al inicio',                      () => this._onHome());
        this._bookmarkStar = this._navBtn('★', 'Guardar marcador',                  () => this._onToggleBookmark());

        this._urlEntry = new Gtk.Entry();
        this._urlEntry.set_hexpand(true);
        this._urlEntry.add_css_class('url-entry');
        this._urlEntry.set_placeholder_text('Ingresa una URL o busca en DuckDuckGo...');
        this._urlEntry.connect('activate', () => this._onUrlActivate());

        this._badge = new Gtk.Label({ label: '' });
        this._badge.add_css_class('badge-normal');
        this._badge.set_tooltip_text('Modo de red actual');
        this._badge.set_visible(false);

        this._secBadge = new Gtk.Label({ label: '' });
        this._secBadge.set_tooltip_text('Estado de seguridad de la página');
        this._secBadge.set_visible(false);

        const bmarksBtn   = this._navBtn('\u2318',       'Marcadores',                    () => this._toggleSidebar('bookmarks'));
        const historyBtn  = this._navBtn('\u{1F552}\uFE0E', 'Historial',                  () => this._toggleSidebar('history'));
        const terminalBtn = this._navBtn('>_',           'Terminal (Ctrl+Alt+T)',          () => this._onToggleTerminal());
        const findBtn     = this._navBtn('⌕',            'Buscar en página (Ctrl+F)',      () => this._toggleFindbar());
        const inspectorBtn= this._navBtn('</>',          'Inspector HTML (Ctrl+AltGr+D)', () => this._toggleInspector());

        const navBox = new Gtk.Box({ orientation: Gtk.Orientation.HORIZONTAL, spacing: 4 });
        navBox.add_css_class('toolbar');
        for (const w of [this._backBtn, this._forwardBtn, this._reloadBtn, this._homeBtn,
                         this._secBadge, this._urlEntry, this._bookmarkStar, this._badge,
                         bmarksBtn, historyBtn, findBtn, inspectorBtn, terminalBtn])
            navBox.append(w);

        // Área de contenido
        this._contentArea = new Gtk.Box({ orientation: Gtk.Orientation.HORIZONTAL, spacing: 0 });
        this._contentArea.set_vexpand(true);
        this._contentArea.set_hexpand(true);

        // Stack de pestañas
        this._tabStack = new Gtk.Stack();
        this._tabStack.set_vexpand(true);
        this._tabStack.set_hexpand(true);
        this._contentArea.append(this._tabStack);

        // Terminal
        this._termBuf = new Gtk.TextBuffer();
        this._termTv  = new Gtk.TextView({ buffer: this._termBuf });
        this._termTv.set_editable(true);
        this._termTv.set_cursor_visible(true);
        this._termTv.set_wrap_mode(Gtk.WrapMode.WORD_CHAR);
        this._termTv.set_monospace(true);
        this._termTv.add_css_class('terminal');
        this._termTv.set_size_request(340, 200);

        const termScroll = new Gtk.ScrolledWindow();
        termScroll.set_vexpand(true);
        termScroll.set_hexpand(false);
        termScroll.set_min_content_width(340);
        termScroll.set_min_content_height(200);
        termScroll.set_child(this._termTv);
        this._termScroll = termScroll;

        const keyCtrl = new Gtk.EventControllerKey();
        keyCtrl.connect('key-pressed', (ctrl, keyval, keycode, state) =>
            this._onTerminalKey(keyval, keycode, state));
        this._termTv.add_controller(keyCtrl);

        // Inspector de HTML
        this._inspBuf = new Gtk.TextBuffer();
        this._inspTv  = new Gtk.TextView({ buffer: this._inspBuf });
        this._inspTv.set_editable(true);
        this._inspTv.set_cursor_visible(true);
        this._inspTv.set_wrap_mode(Gtk.WrapMode.WORD_CHAR);
        this._inspTv.set_monospace(true);
        this._inspTv.add_css_class('inspector-tv');
        this._inspTv.set_size_request(400, 200);

        const inspScroll = new Gtk.ScrolledWindow();
        inspScroll.set_vexpand(true);
        inspScroll.set_hexpand(false);
        inspScroll.set_min_content_width(400);
        inspScroll.set_min_content_height(200);
        inspScroll.set_child(this._inspTv);
        this._inspScroll = inspScroll;

        const inspBtnBox = new Gtk.Box({ orientation: Gtk.Orientation.HORIZONTAL, spacing: 4 });
        inspBtnBox.add_css_class('toolbar');
        const inspReloadBtn = this._navBtn('Cargar HTML', 'Obtener HTML actual de la página', () => this._inspectorLoad());
        const inspApplyBtn  = this._navBtn('Aplicar',     'Aplicar HTML editado a la página',  () => this._inspectorApply());
        const inspCloseBtn  = this._navBtn('Cerrar',      'Cerrar inspector',                  () => this._closeInspector());
        for (const b of [inspReloadBtn, inspApplyBtn, inspCloseBtn]) inspBtnBox.append(b);

        this._inspPanel = new Gtk.Box({ orientation: Gtk.Orientation.VERTICAL, spacing: 0 });
        this._inspPanel.append(inspBtnBox);
        this._inspPanel.append(inspScroll);

        const inspKeyCtrl = new Gtk.EventControllerKey();
        inspKeyCtrl.connect('key-pressed', (ctrl, keyval, keycode, state) =>
            this._onInspectorKey(keyval, state));
        this._inspTv.add_controller(inspKeyCtrl);

        // Barra de búsqueda
        this._findbarBox = new Gtk.Box({ orientation: Gtk.Orientation.HORIZONTAL, spacing: 6 });
        this._findbarBox.add_css_class('findbar');
        this._findEntry = new Gtk.Entry();
        this._findEntry.add_css_class('findbar-entry');
        this._findEntry.set_placeholder_text('Buscar en página…');
        this._findEntry.connect('activate', () => this._findNext());
        this._findEntry.connect('changed',  () => this._findChanged());
        const findPrevBtn  = this._navBtn('↑', 'Anterior (Shift+Enter)', () => this._findPrev());
        const findNextBtn  = this._navBtn('↓', 'Siguiente (Enter)',      () => this._findNext());
        const findCloseBtn = this._navBtn('✕', 'Cerrar (Esc)',           () => this._closeFindbar());
        this._findLabel = new Gtk.Label({ label: '' });
        this._findLabel.add_css_class('findbar-label');
        for (const w of [this._findEntry, findPrevBtn, findNextBtn, this._findLabel, findCloseBtn])
            this._findbarBox.append(w);

        // Barra de estado
        this._statusbar = new Gtk.Label({ label: '' });
        this._statusbar.add_css_class('statusbar');
        this._statusbar.set_halign(Gtk.Align.START);
        this._statusbar.set_hexpand(true);
        this._statusbar.set_ellipsize(3);

        this._dlProgress = new Gtk.ProgressBar();
        this._dlProgress.add_css_class('dl-progress');
        this._dlProgress.set_visible(false);
        this._dlProgress.set_valign(Gtk.Align.CENTER);
        this._dlProgress.set_size_request(150, -1);

        const statusbarBox = new Gtk.Box({ orientation: Gtk.Orientation.HORIZONTAL, spacing: 8 });
        statusbarBox.add_css_class('statusbar');
        statusbarBox.append(this._statusbar);
        statusbarBox.append(this._dlProgress);

        root.append(tabbarRow);
        root.append(navBox);
        root.append(this._contentArea);
        root.append(this._findbarBox);
        root.append(statusbarBox);
        this.set_child(root);
        this._findbarBox.set_visible(false);

        // Atajos globales
        const keyGlobal = new Gtk.EventControllerKey();
        keyGlobal.connect('key-pressed', (ctrl, keyval, keycode, state) =>
            this._onGlobalKey(keyval, keycode, state));
        this.add_controller(keyGlobal);

        this._termPrint('PrekT-BR v2.1  —  escribe \'help\' para ver los comandos');
        this._termPrompt();
    }

    _navBtn(label, tooltip, callback) {
        const b = new Gtk.Button({ label });
        b.add_css_class('nav-button');
        b.set_tooltip_text(tooltip);
        b.connect('clicked', (_btn) => callback());
        return b;
    }

    // ── Pestañas ──────────────────────────────────────────────────────────

    _makeTabWidget(idx) {
        const tabBox = new Gtk.Box({ orientation: Gtk.Orientation.HORIZONTAL, spacing: 0 });
        tabBox.add_css_class('tab-btn');

        const titleBtn = new Gtk.Button({ label: `Tab ${idx + 1}` });
        titleBtn.add_css_class('tab-title-btn');
        titleBtn.set_hexpand(true);
        titleBtn.connect('clicked', () => this._onTabClick(idx));

        const closeBtn = new Gtk.Button({ label: 'x' });
        closeBtn.add_css_class('close-tab-btn');
        closeBtn.connect('clicked', () => this._onCloseTab(idx));

        tabBox.append(titleBtn);
        tabBox.append(closeBtn);
        tabBox._titleBtn = titleBtn;
        return tabBox;
    }

    _openTab({ uri = null, mode = 'normal' } = {}) {
        const wv = this._makeWebview(mode);
        const td = new TabData(wv, mode);
        this._tabs.push(td);
        const idx = this._tabs.length - 1;

        this._tabStack.add_named(wv, `tab${idx}`);
        const tabWidget = this._makeTabWidget(idx);
        this._tabbarBox.append(tabWidget);

        this._setupDownloadHandler(wv);
        this._switchTab(idx);
        wv.load_uri(uri || this._app.homeUri);
    }

    _onCloseTab(idx) {
        if (this._tabs.length === 1) {
            this._tabs[0].webview.load_uri(this._app.homeUri);
            return;
        }
        const td = this._tabs[idx];
        this._clearTabData(td);
        this._tabStack.remove(td.webview);
        this._tabs.splice(idx, 1);
        this._rebuildTabbar();
        const newIdx = Math.min(idx, this._tabs.length - 1);
        this._switchTab(newIdx);
    }

    _clearTabData(td) {
        try {
            const ns = td.webview.get_network_session();
            if (ns) {
                const wds = ns.get_website_data_store();
                if (wds) {
                    wds.clear(
                        WebKit.WebsiteDataTypes.COOKIES |
                        WebKit.WebsiteDataTypes.DISK_CACHE |
                        WebKit.WebsiteDataTypes.MEMORY_CACHE |
                        WebKit.WebsiteDataTypes.SESSION_STORAGE |
                        WebKit.WebsiteDataTypes.LOCAL_STORAGE |
                        WebKit.WebsiteDataTypes.INDEXED_DB_DATABASES |
                        WebKit.WebsiteDataTypes.OFFLINE_APPLICATION_CACHE,
                        0, null, null
                    );
                }
            }
        } catch(e) {
            print(`[prektbr] Error limpiando datos de pestaña: ${e}`);
        }
    }

    _rebuildTabbar() {
        let child = this._tabbarBox.get_first_child();
        while (child) {
            const nxt = child.get_next_sibling();
            this._tabbarBox.remove(child);
            child = nxt;
        }
        for (let i = 0; i < this._tabs.length; i++) {
            const td = this._tabs[i];
            const tw = this._makeTabWidget(i);
            const title = td.webview.get_title();
            if (title) {
                const short = title.length > 14 ? title.slice(0, 14) + '...' : title;
                tw._titleBtn.set_label(short);
            }
            this._tabbarBox.append(tw);
        }
    }

    _onTabClick(idx) { this._switchTab(idx); }

    _switchTab(idx) {
        if (idx < 0 || idx >= this._tabs.length) return;

        let child = this._tabbarBox.get_first_child();
        let i = 0;
        while (child) {
            child.remove_css_class('tab-active');
            if (i === idx) child.add_css_class('tab-active');
            child = child.get_next_sibling();
            i++;
        }

        this._currentTab = idx;
        this._tabStack.set_visible_child_name(`tab${idx}`);

        const td = this._tabs[idx];
        const uri = td.webview.get_uri();
        this._urlEntry.set_text(uri && uri !== 'about:blank' ? uri : '');
        this._updateBadge(td.mode);
        this._updateNavButtons();
        this._updateBookmarkStar();
        this._updateSecurityBadge(td.webview.get_uri() || '');
    }

    _wv() { return this._tabs[this._currentTab].webview; }
    _td() { return this._tabs[this._currentTab]; }

    // ── WebView ───────────────────────────────────────────────────────────

    _makeWebview(mode = 'normal') {
        let wv;
        if (mode === 'tor') {
            const ns = WebKit.NetworkSession.new_ephemeral();
            const ps = WebKit.NetworkProxySettings.new('socks5://127.0.0.1:9050', null);
            ns.set_proxy_settings(WebKit.NetworkProxyMode.CUSTOM, ps);
            wv = new WebKit.WebView({ network_session: ns });
        } else if (mode === 'i2p') {
            const ns = WebKit.NetworkSession.new_ephemeral();
            const ps = WebKit.NetworkProxySettings.new('http://127.0.0.1:4444', null);
            ns.set_proxy_settings(WebKit.NetworkProxyMode.CUSTOM, ps);
            wv = new WebKit.WebView({ network_session: ns });
        } else {
            wv = new WebKit.WebView();
        }

        const s = WebKit.Settings.new();
        s.set_enable_developer_extras(false);
        s.set_javascript_can_access_clipboard(false);
        s.set_enable_webrtc(false);
        s.set_enable_mediasource(false);
        s.set_enable_encrypted_media(false);
        s.set_enable_back_forward_navigation_gestures(false);
        s.set_media_playback_requires_user_gesture(true);
        s.set_javascript_can_open_windows_automatically(false);
        s.set_allow_modal_dialogs(false);
        s.set_enable_page_cache(false);
        s.set_user_agent('Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0');
        wv.set_settings(s);
        wv.set_vexpand(true);
        wv.set_hexpand(true);

        wv.connect('notify::uri',   () => this._onUriChanged(wv));
        wv.connect('notify::title', () => this._onTitleChanged(wv));
        wv.connect('load-changed',  (w, event) => this._onLoadChanged(w, event));
        wv.connect('notify::estimated-load-progress', () => this._onProgress(wv));

        // Inyección anti-fingerprinting
        const ucm = wv.get_user_content_manager();
        try {
            const fpScript = new WebKit.UserScript(
                FP_PROTECTION_JS,
                WebKit.UserContentInjectedFrames.TOP_FRAME,
                WebKit.UserScriptInjectionTime.START,
                null, null
            );
            ucm.add_script(fpScript);
        } catch(e) {
            print(`[prektbr] UserContentManager fallback: ${e}`);
            wv.connect('load-changed', (w, event) => {
                if (event === WebKit.LoadEvent.STARTED)
                    w.evaluate_javascript(FP_PROTECTION_JS, -1, null, null, null, null);
            });
        }

        return wv;
    }

    // ── Señales ───────────────────────────────────────────────────────────

    _onUriChanged(wv) {
        if (!this._tabs.length) return;
        const uri = wv.get_uri();
        if (!uri || uri === 'about:blank') return;
        if (wv === this._wv()) {
            this._urlEntry.set_text(uri);
            this._updateBookmarkStar();
            this._updateNavButtons();
            this._updateSecurityBadge(uri);
        }
        const title = wv.get_title() || uri;
        this._app.addHistory(uri, title);
    }

    _onTitleChanged(wv) {
        if (!this._tabs.length) return;
        const title = wv.get_title() || '';
        let child = this._tabbarBox.get_first_child();
        let i = 0;
        while (child) {
            if (i < this._tabs.length && this._tabs[i].webview === wv) {
                if (child._titleBtn) {
                    const short = title.length > 14 ? title.slice(0, 14) + '...' : (title || `Tab ${i + 1}`);
                    child._titleBtn.set_label(short);
                }
                break;
            }
            child = child.get_next_sibling();
            i++;
        }
        if (wv === this._wv())
            this.set_title(title ? `PrekT-BR — ${title}` : 'PrekT-BR');
    }

    _onLoadChanged(wv, event) {
        if (event === WebKit.LoadEvent.STARTED) {
            this._reloadBtn.set_label('✕');
            this._reloadBtn.set_tooltip_text('Detener carga');
        } else if (event === WebKit.LoadEvent.FINISHED) {
            this._reloadBtn.set_label('↻');
            this._reloadBtn.set_tooltip_text('Recargar (Ctrl+R)');
            this._statusbar.set_label('');
            if (this._app.darkMode && wv === this._wv())
                GLib.timeout_add(GLib.PRIORITY_DEFAULT, 400, () => { this._applyDarkCss(); return false; });
        }
    }

    _onProgress(wv) {
        if (wv !== this._wv()) return;
        const p = wv.get_estimated_load_progress();
        if (p > 0 && p < 1)
            this._statusbar.set_label(`Cargando… ${Math.floor(p * 100)}%`);
        else
            this._statusbar.set_label('');
    }

    // ── Navegación ────────────────────────────────────────────────────────

    _onBack() {
        try { const wv = this._wv(); if (wv.can_go_back) wv.go_back(); } catch(e) { print(`[prektbr] back: ${e}`); }
    }
    _onForward() {
        try { const wv = this._wv(); if (wv.can_go_forward) wv.go_forward(); } catch(e) { print(`[prektbr] forward: ${e}`); }
    }
    _onHome() {
        try { this._wv().load_uri(this._app.homeUri); } catch(e) { print(`[prektbr] home: ${e}`); }
    }

    _onUrlActivate() {
        try {
            const text = this._urlEntry.get_text().trim();
            if (!text) return;
            this._wv().load_uri(resolveInput(text));
        } catch(e) { print(`[prektbr] url: ${e}`); }
    }

    _onReload() {
        try {
            const wv = this._wv();
            if (wv.is_loading) wv.stop_loading();
            else wv.reload();
        } catch(e) { print(`[prektbr] reload: ${e}`); }
    }

    _updateNavButtons() {
        if (!this._tabs.length) return;
        this._backBtn.set_sensitive(this._wv().can_go_back);
        this._forwardBtn.set_sensitive(this._wv().can_go_forward);
    }

    // ── Marcadores ────────────────────────────────────────────────────────

    _onToggleBookmark() {
        const wv = this._wv();
        const uri = wv.get_uri();
        if (!uri || uri === 'about:blank') return;
        if (this._app.isBookmarked(uri)) {
            this._app.removeBookmark(uri);
            this._bookmarkStar.set_label('★');
            this._statusbar.set_label('Marcador eliminado');
        } else {
            const title = wv.get_title() || uri;
            this._app.addBookmark(uri, title);
            this._bookmarkStar.set_label('★');
            this._statusbar.set_label('Marcador guardado');
        }
        GLib.timeout_add(GLib.PRIORITY_DEFAULT, 2000, () => { this._statusbar.set_label(''); return false; });
        if (this._sidebarMode === 'bookmarks') this._showSidebar('bookmarks');
    }

    _updateBookmarkStar() {
        if (!this._tabs.length) return;
        this._bookmarkStar.set_label('★');
    }

    // ── Sidebar ───────────────────────────────────────────────────────────

    _toggleSidebar(mode) {
        if (this._sidebarMode === mode) this._closeSidebar();
        else this._showSidebar(mode);
    }

    _closeSidebar() {
        if (this._sidebarWidget) {
            this._contentArea.remove(this._sidebarWidget);
            this._sidebarWidget = null;
        }
        this._sidebarMode = null;
    }

    _showSidebar(mode) {
        this._closeSidebar();
        this._sidebarMode = mode;

        const outer = new Gtk.Box({ orientation: Gtk.Orientation.VERTICAL, spacing: 0 });
        outer.add_css_class('sidebar');

        const titleBox = new Gtk.Box({ orientation: Gtk.Orientation.HORIZONTAL, spacing: 0 });
        titleBox.add_css_class('sidebar-title');
        const lbl = new Gtk.Label({ label: mode === 'bookmarks' ? 'Marcadores' : 'Historial' });
        lbl.set_hexpand(true);
        lbl.set_halign(Gtk.Align.START);
        const closeBtn = new Gtk.Button({ label: 'Cerrar' });
        closeBtn.add_css_class('nav-button');
        closeBtn.connect('clicked', () => this._closeSidebar());
        titleBox.append(lbl);
        titleBox.append(closeBtn);

        const scroll = new Gtk.ScrolledWindow();
        scroll.set_vexpand(true);
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC);

        const listBox = new Gtk.Box({ orientation: Gtk.Orientation.VERTICAL, spacing: 1 });
        listBox.set_margin_top(4); listBox.set_margin_bottom(4);
        listBox.set_margin_start(4); listBox.set_margin_end(4);

        if (mode === 'bookmarks') {
            const items = [...this._app.bookmarks];
            if (!items.length) {
                const empty = new Gtk.Label({ label: 'Sin marcadores aún' });
                empty.set_margin_top(20);
                empty.add_css_class('sidebar-item');
                listBox.append(empty);
            }
            for (const b of items)
                this._sidebarItem(listBox, b.title, b.url, true);
        } else {
            const items = [...this._app.history.slice(-200)].reverse();
            if (!items.length) {
                const empty = new Gtk.Label({ label: 'El historial está vacío' });
                empty.set_margin_top(20);
                empty.add_css_class('sidebar-item');
                listBox.append(empty);
            }
            for (const h of items) {
                const ts = (h.ts || '').slice(0, 10);
                const label = `[${ts}] ${h.title || h.url}`;
                this._sidebarItem(listBox, label, h.url, false);
            }
        }

        scroll.set_child(listBox);
        outer.append(titleBox);
        outer.append(scroll);
        this._contentArea.prepend(outer);
        this._sidebarWidget = outer;
    }

    _sidebarItem(box, label, url, removable) {
        const row = new Gtk.Box({ orientation: Gtk.Orientation.HORIZONTAL, spacing: 2 });
        const btn = new Gtk.Button({ label });
        btn.add_css_class('sidebar-item');
        btn.set_hexpand(true);
        btn.set_halign(Gtk.Align.FILL);
        btn.connect('clicked', () => this._wv().load_uri(url));
        row.append(btn);
        if (removable) {
            const delBtn = new Gtk.Button({ label: 'Quitar' });
            delBtn.add_css_class('close-tab-btn');
            delBtn.connect('clicked', () => {
                this._app.removeBookmark(url);
                this._showSidebar('bookmarks');
            });
            row.append(delBtn);
        }
        box.append(row);
    }

    // ── Badge de red ──────────────────────────────────────────────────────

    _updateBadge(mode) {
        this._badge.remove_css_class('badge-normal');
        this._badge.remove_css_class('badge-tor');
        this._badge.remove_css_class('badge-i2p');
        this._badge.remove_css_class('badge-clear');
        if (mode === 'tor') {
            this._badge.set_label('TOR');
            this._badge.add_css_class('badge-tor');
        } else if (mode === 'i2p') {
            this._badge.set_label('I2P');
            this._badge.add_css_class('badge-i2p');
        } else {
            this._badge.set_label('Clear');
            this._badge.add_css_class('badge-clear');
        }
        this._badge.set_visible(true);
    }

    // ── Modo oscuro ───────────────────────────────────────────────────────

    _applyDarkCss() {
        const css = `:root { color-scheme: dark !important; }
* { background-color: #111 !important; color: #eee !important;
    border-color: #333 !important; }
a { color: #8ab4f8 !important; }
img { filter: brightness(0.85); }`;
        const js = `(function(){
    let el = document.getElementById('prektbr-dark');
    if(!el){el=document.createElement('style');el.id='prektbr-dark';
    document.head.appendChild(el);} el.textContent=\`${css}\`;
})();`;
        this._wv().evaluate_javascript(js, -1, null, null, null, null);
    }

    // ── Atajos de teclado ─────────────────────────────────────────────────

    _onGlobalKey(keyval, keycode, state) {
        const ctrlHeld  = !!(state & Gdk.ModifierType.CONTROL_MASK);
        const altHeld   = !!(state & Gdk.ModifierType.ALT_MASK);
        const shiftHeld = !!(state & Gdk.ModifierType.SHIFT_MASK);
        const altgrHeld = !!(state & Gdk.ModifierType.MOD5_MASK);

        if (ctrlHeld && !altHeld && !altgrHeld) {
            if (keyval === Gdk.KEY_t)                          { this._openTab({}); return true; }
            if (keyval === Gdk.KEY_w)                          { this._onCloseTab(this._currentTab); return true; }
            if (keyval === Gdk.KEY_l)                          { this._urlEntry.grab_focus(); this._urlEntry.select_region(0, -1); return true; }
            if (keyval === Gdk.KEY_r && !shiftHeld)            { this._wv().reload(); return true; }
            if (keyval === Gdk.KEY_r && shiftHeld)             { this._wv().reload_bypass_cache(); return true; }
            if (keyval === Gdk.KEY_f)                          { this._toggleFindbar(); return true; }
            if (keyval === Gdk.KEY_plus || keyval === Gdk.KEY_equal) {
                const wv = this._wv(); wv.set_zoom_level(Math.min(wv.get_zoom_level() + 0.1, 5.0)); return true;
            }
            if (keyval === Gdk.KEY_minus)                      { const wv = this._wv(); wv.set_zoom_level(Math.max(wv.get_zoom_level() - 0.1, 0.1)); return true; }
            if (keyval === Gdk.KEY_0)                          { this._wv().set_zoom_level(1.0); return true; }
        }

        if (ctrlHeld && altHeld && !altgrHeld) {
            if (keyval === Gdk.KEY_t || keyval === Gdk.KEY_Return) { this._onToggleTerminal(); return true; }
        }

        if (ctrlHeld && altgrHeld) {
            if (keyval === Gdk.KEY_d) { this._toggleInspector(); return true; }
        }

        if (!ctrlHeld && !altHeld) {
            if (keyval === Gdk.KEY_Escape) {
                if (this._findbarVisible) { this._closeFindbar(); return true; }
                if (this._inspectorMode) { this._closeInspector(); return true; }
            }
        }

        if (altHeld && !ctrlHeld) {
            if (keyval === Gdk.KEY_Left)  { if (this._wv().can_go_back)    this._wv().go_back();    return true; }
            if (keyval === Gdk.KEY_Right) { if (this._wv().can_go_forward) this._wv().go_forward(); return true; }
        }

        return false;
    }

    // ── Badge de seguridad ────────────────────────────────────────────────

    _updateSecurityBadge(uri) {
        if (!uri || uri.startsWith('about:')) { this._secBadge.set_visible(false); return; }

        let scheme = '', host = '';
        try {
            const u = new URL(uri);
            scheme = u.protocol.replace(':', '');
            host = u.hostname;
        } catch(e) { this._secBadge.set_visible(false); return; }

        for (const cls of ['badge-secure','badge-insecure','badge-onion','badge-eepsite','badge-file'])
            this._secBadge.remove_css_class(cls);

        if (scheme === 'file') {
            this._secBadge.set_label('F');
            this._secBadge.add_css_class('badge-file');
            this._secBadge.set_tooltip_text('Archivo local');
        } else if (host.endsWith('.onion')) {
            this._secBadge.set_label('O');
            this._secBadge.add_css_class('badge-onion');
            this._secBadge.set_tooltip_text('Onion — servicio oculto Tor');
        } else if (host.endsWith('.i2p') || host.endsWith('.loki')) {
            this._secBadge.set_label('E');
            this._secBadge.add_css_class('badge-eepsite');
            this._secBadge.set_tooltip_text('Eepsite — servicio I2P/Lokinet');
        } else if (scheme === 'https') {
            this._secBadge.set_label('S');
            this._secBadge.add_css_class('badge-secure');
            this._secBadge.set_tooltip_text('Seguro — conexión HTTPS');
        } else {
            this._secBadge.set_label('I');
            this._secBadge.add_css_class('badge-insecure');
            this._secBadge.set_tooltip_text('Inseguro — conexión HTTP sin cifrar');
        }
        this._secBadge.set_visible(true);
    }

    // ── Buscar en página ──────────────────────────────────────────────────

    _toggleFindbar() {
        if (this._findbarVisible) this._closeFindbar();
        else { this._findbarBox.set_visible(true); this._findbarVisible = true; this._findEntry.grab_focus(); }
    }

    _closeFindbar() {
        this._findbarBox.set_visible(false);
        this._findbarVisible = false;
        this._wv().get_find_controller().search_finish();
        this._findLabel.set_label('');
    }

    _findChanged() {
        const text = this._findEntry.get_text();
        const fc = this._wv().get_find_controller();
        if (text)
            fc.search(text, WebKit.FindOptions.CASE_INSENSITIVE | WebKit.FindOptions.WRAP_AROUND, 1000);
        else { fc.search_finish(); this._findLabel.set_label(''); }
    }

    _findNext() { const text = this._findEntry.get_text(); if (text) this._wv().get_find_controller().search_next(); }
    _findPrev() { const text = this._findEntry.get_text(); if (text) this._wv().get_find_controller().search_previous(); }

    // ── Inspector ─────────────────────────────────────────────────────────

    _toggleInspector() {
        if (this._inspectorMode) this._closeInspector();
        else this._openInspector();
    }

    _openInspector() {
        if (this._inspectorMode) return;
        if (this._terminalVisible) {
            this._statusbar.set_label('Cierra la terminal primero (Ctrl+Alt+T)');
            GLib.timeout_add(GLib.PRIORITY_DEFAULT, 2000, () => { this._statusbar.set_label(''); return false; });
            return;
        }
        this._inspectorMode = true;
        this._contentArea.append(this._inspPanel);
        this._inspectorLoad();
    }

    _closeInspector() {
        if (!this._inspectorMode) return;
        this._contentArea.remove(this._inspPanel);
        this._inspectorMode = false;
    }

    _inspectorLoad() {
        this._inspBuf.set_text('Cargando HTML…', -1);
        const wv = this._wv();

        // Estrategia: evaluate_javascript con callback asíncrono (WebKit 6.0 GJS)
        const js = 'document.documentElement.outerHTML';
        try {
            wv.evaluate_javascript(js, -1, null, null, null, (wv_, result) => {
                try {
                    const jsVal = wv_.evaluate_javascript_finish(result);
                    const html = jsVal ? jsVal.to_string() : '';
                    const formatted = (html && html !== 'undefined' && html !== 'null')
                        ? formatHtml(html) : '[HTML vacío]';
                    GLib.idle_add(GLib.PRIORITY_DEFAULT_IDLE, () => {
                        this._inspBuf.set_text(formatted, -1);
                        return false;
                    });
                } catch(e) {
                    // Fallback: usar script_message_handler
                    this._inspectorLoadViaMessageHandler(wv);
                }
            });
        } catch(e) {
            // evaluate_javascript no acepta callback en esta build — usar message handler
            this._inspectorLoadViaMessageHandler(wv);
        }
    }

    _inspectorLoadViaMessageHandler(wv) {
        const ucm = wv.get_user_content_manager();
        const handlerName = 'prektbrInspector';

        // Desregistrar por si quedó uno anterior
        try { ucm.unregister_script_message_handler(handlerName); } catch(e) {}

        let handlerId = null;
        const onMsg = (ucm_, msg) => {
            let html = '';
            try {
                const jsc = msg.get_js_value();
                html = jsc ? jsc.to_string() : '';
            } catch(e) {
                try { html = msg.to_string(); } catch(e2) { html = '[No se pudo convertir el resultado]'; }
            }
            // Desconectar handler para no acumular
            if (handlerId !== null) {
                try { ucm_.disconnect(handlerId); } catch(e) {}
                handlerId = null;
            }
            try { ucm_.unregister_script_message_handler(handlerName); } catch(e) {}

            const formatted = (html && html !== 'undefined' && html !== 'null')
                ? formatHtml(html) : '[HTML vacío]';
            GLib.idle_add(GLib.PRIORITY_DEFAULT_IDLE, () => {
                this._inspBuf.set_text(formatted, -1);
                return false;
            });
        };

        try {
            ucm.register_script_message_handler(handlerName);
            handlerId = ucm.connect(`script-message-received::${handlerName}`, onMsg);
            const js = `window.webkit.messageHandlers.${handlerName}.postMessage(document.documentElement.outerHTML);`;
            // Llamar evaluate_javascript sin callback (solo disparar el JS)
            wv.evaluate_javascript(js, -1, null, null, null, null);
        } catch(e) {
            GLib.idle_add(GLib.PRIORITY_DEFAULT_IDLE, () => {
                this._inspBuf.set_text(`[Error cargando HTML: ${e}]`, -1);
                return false;
            });
        }
    }

    _inspectorApply() {
        const start = this._inspBuf.get_start_iter();
        const end   = this._inspBuf.get_end_iter();
        const html  = this._inspBuf.get_text(start, end, false);
        const escaped = html.replace(/\\/g, '\\\\').replace(/`/g, '\\`');
        const js = `document.open(); document.write(\`${escaped}\`); document.close();`;
        this._wv().evaluate_javascript(js, -1, null, null, null, null);
    }

    _onInspectorKey(keyval, state) {
        const ctrlHeld = !!(state & Gdk.ModifierType.CONTROL_MASK);
        if (ctrlHeld && keyval === Gdk.KEY_Return) { this._inspectorApply(); return true; }
        if (keyval === Gdk.KEY_Escape) { this._closeInspector(); return true; }
        return false;
    }

    // ── Descargas ─────────────────────────────────────────────────────────

    _setupDownloadHandler(wv) {
        const ns = wv.get_network_session();
        if (ns) ns.connect('download-started', (session, download) => this._onDownloadStarted(download));
    }

    _onDownloadStarted(download) {
        download.connect('decide-destination', (dl, suggestedFilename) =>
            this._onDecideDestination(dl, suggestedFilename));
        download.connect('failed', (dl, error) => this._onDownloadFailed(error));
    }

    _onDecideDestination(download, suggestedFilename) {
        let fname = suggestedFilename;
        if (!fname) {
            try {
                const req = download.get_request();
                const uri = req ? req.get_uri() : '';
                fname = GLib.path_get_basename(new URL(uri).pathname) || 'descarga';
            } catch(e) { fname = 'descarga'; }
        }

        const dialog = new Gtk.FileDialog();
        dialog.set_title('Guardar archivo');
        dialog.set_initial_name(fname);
        dialog.save(this, null, (dlg, result) => this._onSaveDialogDone(dlg, result, download));
        return true;
    }

    _onSaveDialogDone(dialog, result, download) {
        try {
            const gfile = dialog.save_finish(result);
            const dest = gfile.get_path();
            const fname = GLib.path_get_basename(dest);

            download.set_destination(dest);
            this._statusbar.set_label(`Descargando: ${fname}  0%`);
            this._dlProgress.set_fraction(0.0);
            this._dlProgress.set_visible(true);

            download.connect('notify::estimated-progress', (d) => {
                const p = d.get_estimated_progress();
                GLib.idle_add(GLib.PRIORITY_DEFAULT_IDLE, () => {
                    this._dlProgress.set_fraction(p);
                    this._statusbar.set_label(`Descargando: ${fname}  ${Math.floor(p * 100)}%`);
                    return false;
                });
            });

            download.connect('finished', () => {
                GLib.idle_add(GLib.PRIORITY_DEFAULT_IDLE, () => {
                    this._dlProgress.set_fraction(1.0);
                    this._statusbar.set_label(`Descarga completa: ${fname}`);
                    GLib.timeout_add(GLib.PRIORITY_DEFAULT, 3500, () => {
                        this._dlProgress.set_visible(false);
                        this._dlProgress.set_fraction(0.0);
                        this._statusbar.set_label('');
                        return false;
                    });
                    return false;
                });
            });
        } catch(e) {
            download.cancel();
        }
    }

    _onDownloadFailed(error) {
        GLib.idle_add(GLib.PRIORITY_DEFAULT_IDLE, () => {
            this._dlProgress.set_visible(false);
            this._dlProgress.set_fraction(0.0);
            this._statusbar.set_label(`Error de descarga: ${error}`);
            GLib.timeout_add(GLib.PRIORITY_DEFAULT, 4000, () => { this._statusbar.set_label(''); return false; });
            return false;
        });
    }

    // ── Terminal ──────────────────────────────────────────────────────────

    _onToggleTerminal() {
        if (this._inspectorMode) {
            this._statusbar.set_label('Cierra el inspector primero (Esc)');
            GLib.timeout_add(GLib.PRIORITY_DEFAULT, 2000, () => { this._statusbar.set_label(''); return false; });
            return;
        }
        if (this._terminalVisible) {
            this._contentArea.remove(this._termScroll);
            this._terminalVisible = false;
        } else {
            this._contentArea.append(this._termScroll);
            this._terminalVisible = true;
            this._termTv.grab_focus();
        }
    }

    _termPrint(text, noNl = false) {
        const end = this._termBuf.get_end_iter();
        this._termBuf.insert(end, noNl ? text : text + '\n', -1);
        const end2 = this._termBuf.get_end_iter();
        this._termTv.scroll_to_iter(end2, 0.0, true, 0.0, 1.0);
    }

    _termPrompt() {
        const end = this._termBuf.get_end_iter();
        this._termBuf.insert(end, '> ', -1);
        const end2 = this._termBuf.get_end_iter();
        this._promptEndMark = this._termBuf.create_mark('prompt_end', end2, true);
    }

    _onTerminalKey(keyval, keycode, state) {
        if (keyval === Gdk.KEY_Return || keyval === Gdk.KEY_KP_Enter) {
            const start = this._termBuf.get_start_iter();
            const end   = this._termBuf.get_end_iter();
            const full  = this._termBuf.get_text(start, end, false).trimEnd();
            const lines = full.split('\n');
            if (lines.length) {
                const last = lines[lines.length - 1].trim();
                if (last.startsWith('> ')) {
                    const cmd = last.slice(2).trim();
                    if (cmd) {
                        this._termPrint('');
                        this._runCommand(cmd);
                        return true;
                    }
                }
            }
            this._termPrint('');
            this._termPrompt();
            return true;
        }

        // Proteger el prompt
        if ([Gdk.KEY_BackSpace, Gdk.KEY_Delete, Gdk.KEY_Left, Gdk.KEY_Home,
             Gdk.KEY_KP_Left, Gdk.KEY_KP_Home].includes(keyval)) {
            if (this._promptEndMark) {
                const insertMark = this._termBuf.get_insert();
                const cursor = this._termBuf.get_iter_at_mark(insertMark);
                const limit  = this._termBuf.get_iter_at_mark(this._promptEndMark);
                if (cursor.compare(limit) <= 0) return true;
            }
        }
        return false;
    }

    // ── Modo red ──────────────────────────────────────────────────────────

    _enableNetworkMode(mode) {
        const td = this._td();
        if (td.mode === mode) {
            this._termPrint(`La pestaña ya está en modo ${mode.toUpperCase()}.`);
            this._termPrompt();
            return;
        }
        const oldUri = td.webview.get_uri() || this._app.homeUri;
        const newWv = this._makeWebview(mode);
        const idx = this._currentTab;

        this._tabStack.remove(td.webview);
        td.webview = newWv;
        td.mode = mode;
        this._tabStack.add_named(newWv, `tab${idx}`);
        this._tabStack.set_visible_child_name(`tab${idx}`);
        newWv.load_uri(oldUri !== 'about:blank' ? oldUri : this._app.homeUri);
        this._updateBadge(mode);

        if (mode === 'tor') {
            this._termPrint('  MODO TOR ACTIVADO — WebRTC deshabilitado');
            this._termPrint('  Usa http:// (sin s) para sitios .onion');
        } else if (mode === 'i2p') {
            this._termPrint('  MODO I2P ACTIVADO — Proxy HTTP 127.0.0.1:4444');
            this._termPrint('  Navega a sitios .i2p normalmente');
        }
        this._termPrompt();
    }

    _disableNetworkMode() {
        const td = this._td();
        if (td.mode === 'normal') {
            this._termPrint('La pestaña ya está en modo normal.');
            this._termPrompt();
            return;
        }
        const oldUri = td.webview.get_uri() || this._app.homeUri;
        const newWv = this._makeWebview('normal');
        const idx = this._currentTab;

        this._tabStack.remove(td.webview);
        td.webview = newWv;
        td.mode = 'normal';
        this._tabStack.add_named(newWv, `tab${idx}`);
        this._tabStack.set_visible_child_name(`tab${idx}`);
        newWv.load_uri(oldUri !== 'about:blank' ? oldUri : this._app.homeUri);
        this._updateBadge('normal');
        this._termPrint('  Modo normal restaurado.');
        this._termPrompt();
    }

    // ── Comandos de terminal ──────────────────────────────────────────────

    _runCommand(raw) {
        const parts = raw.split(/\s+(.+)?/, 2);
        const cmd  = (parts[0] || '').toLowerCase();
        const args = (parts[1] || '').trim();

        const nav = (url) => this._wv().load_uri(url);

        if (cmd === 'help') {
            this._termPrint(
                '─── Navegación ───────────────────────────────\n' +
                '  open <url>            → abre URL en pestaña actual\n' +
                '  newtab [url]          → abre nueva pestaña\n' +
                '  closetab              → cierra pestaña actual\n' +
                '  tab <n>               → cambia a pestaña n (1-based)\n' +
                '  back / forward        → historial del navegador\n' +
                '  reload                → recarga normal\n' +
                '  reloadhard            → recarga sin caché\n' +
                '  home                  → página de inicio\n' +
                '  zoom <n>              → nivel de zoom (0.1–5.0, 1.0=normal)\n' +
                '─── Búsqueda ─────────────────────────────────\n' +
                '  ddg <consulta>        → DuckDuckGo\n' +
                '  google <consulta>     → Google\n' +
                '  yt <consulta>         → YouTube\n' +
                '  wiki <consulta>       → Wikipedia (es)\n' +
                '─── Redes alternativas ───────────────────────\n' +
                '  tormode               → activa Tor en esta pestaña\n' +
                '  i2pmode               → activa I2P en esta pestaña\n' +
                '  clearnet              → vuelve a modo normal\n' +
                '  loki <direccion>      → abre direccion.loki\n' +
                '  whoami                → tu IP pública\n' +
                '  serverip              → IP del servidor actual\n' +
                '─── Marcadores e historial ───────────────────\n' +
                '  bookmark              → guarda/quita marcador actual\n' +
                '  bookmarks             → lista marcadores\n' +
                '  history [n]           → últimas n URLs (def. 10)\n' +
                '─── Utilidades ───────────────────────────────\n' +
                '  dark                  → toggle modo oscuro\n' +
                '  calc <expr>           → calculadora\n' +
                '  time / date           → hora / fecha\n' +
                '  echo <texto>          → repite texto\n' +
                '  clear                 → limpia terminal\n' +
                '  clearcookies          → borra cookies/datos de pestaña actual\n' +
                '  clearall              → borra datos de todas las pestañas\n' +
                '  about                 → info del navegador\n' +
                '  quit                  → cierra el navegador\n' +
                '─── Atajos de teclado ────────────────────────\n' +
                '  Ctrl+T                → nueva pestaña\n' +
                '  Ctrl+W                → cerrar pestaña\n' +
                '  Ctrl+L                → foco en barra de URL\n' +
                '  Ctrl+R                → recargar\n' +
                '  Ctrl+Shift+R          → recargar sin caché\n' +
                '  Ctrl+F                → buscar en página\n' +
                '  Ctrl++ / Ctrl+-       → zoom in/out\n' +
                '  Ctrl+0                → zoom reset\n' +
                '  Ctrl+Alt+T            → abrir/cerrar terminal\n' +
                '  Ctrl+AltGr+D          → abrir/cerrar inspector HTML\n' +
                '  Alt+Izq / Alt+Der     → atrás / adelante\n'
            );

        } else if (cmd === 'open' || cmd === 'new') {
            if (args) nav(resolveInput(args));
            else this._termPrint('Uso: open <url>');

        } else if (cmd === 'newtab') {
            this._openTab({ uri: args ? resolveInput(args) : null });

        } else if (cmd === 'closetab') {
            this._onCloseTab(this._currentTab);

        } else if (cmd === 'tab') {
            const n = parseInt(args, 10);
            if (!isNaN(n)) this._switchTab(n - 1);
            else this._termPrint('Uso: tab <número>');

        } else if (cmd === 'back') {
            if (this._wv().can_go_back) this._wv().go_back();

        } else if (cmd === 'forward') {
            if (this._wv().can_go_forward) this._wv().go_forward();

        } else if (cmd === 'reload')     { this._wv().reload();
        } else if (cmd === 'reloadhard') { this._wv().reload_bypass_cache();
        } else if (cmd === 'home')       { nav(this._app.homeUri);

        } else if (cmd === 'zoom') {
            if (args) {
                const level = parseFloat(args);
                if (!isNaN(level) && level >= 0.1 && level <= 5.0) {
                    this._wv().set_zoom_level(level);
                    this._termPrint(`Zoom: ${level.toFixed(1)}x`);
                } else {
                    this._termPrint('Zoom válido: 0.1 – 5.0 (1.0 = normal)');
                }
            } else {
                this._termPrint(`Zoom actual: ${this._wv().get_zoom_level().toFixed(1)}x  — uso: zoom <número>`);
            }

        } else if (cmd === 'ddg') {
            const q = args ? encodeURIComponentQ(args) : '';
            nav(q ? `https://duckduckgo.com/?q=${q}` : 'https://duckduckgo.com');

        } else if (cmd === 'google') {
            const q = args ? encodeURIComponentQ(args) : '';
            nav(q ? `https://www.google.com/search?q=${q}` : 'https://www.google.com');

        } else if (cmd === 'yt') {
            const q = args ? encodeURIComponentQ(args) : '';
            nav(q ? `https://www.youtube.com/results?search_query=${q}` : 'https://www.youtube.com');

        } else if (cmd === 'wiki') {
            const q = args ? encodeURIComponentQ(args) : '';
            nav(q ? `https://es.wikipedia.org/wiki/${q}` : 'https://es.wikipedia.org');

        } else if (cmd === 'loki') {
            if (args) {
                let addr = args.replace(/^https?:\/\//, '');
                if (!addr.endsWith('.loki')) addr += '.loki';
                nav(`http://${addr}`);
            } else {
                this._termPrint('Uso: loki <direccion>  (ejemplo: loki stats.i2p.rocks)');
            }

        } else if (cmd === 'tormode') {
            this._enableNetworkMode('tor'); return;

        } else if (cmd === 'i2pmode') {
            this._enableNetworkMode('i2p'); return;

        } else if (cmd === 'clearnet') {
            this._disableNetworkMode(); return;

        } else if (cmd === 'whoami') {
            this._termPrint('Consultando IP pública...');
            // GJS no tiene threading nativo — usamos Gio.Subprocess
            try {
                const proc = Gio.Subprocess.new(
                    ['curl', '-s', '--max-time', '7', 'https://api.ipify.org'],
                    Gio.SubprocessFlags.STDOUT_PIPE | Gio.SubprocessFlags.STDERR_SILENCE
                );
                proc.communicate_utf8_async(null, null, (p, res) => {
                    try {
                        const [, stdout] = p.communicate_utf8_finish(res);
                        const ip = (stdout || '').trim();
                        GLib.idle_add(GLib.PRIORITY_DEFAULT_IDLE, () => {
                            this._termPrint(`IP pública: ${ip || '[sin respuesta]'}`);
                            this._termPrint('');
                            this._termPrompt();
                            return false;
                        });
                    } catch(e) {
                        GLib.idle_add(GLib.PRIORITY_DEFAULT_IDLE, () => {
                            this._termPrint(`Error: ${e}`);
                            this._termPrint('');
                            this._termPrompt();
                            return false;
                        });
                    }
                });
            } catch(e) {
                this._termPrint(`Error lanzando curl: ${e}`);
            }
            return;

        } else if (cmd === 'serverip') {
            const td = this._td();
            if (td.mode === 'tor' || td.mode === 'i2p') {
                this._termPrint(`serverip no disponible en modo ${td.mode.toUpperCase()}.`);
            } else {
                const uri = this._wv().get_uri();
                if (!uri || uri.startsWith('file://')) {
                    this._termPrint('Sin página cargada.');
                } else {
                    let host = '';
                    try { host = new URL(uri).hostname; } catch(e) {}
                    if (host) {
                        try {
                            const proc = Gio.Subprocess.new(
                                ['getent', 'hosts', host],
                                Gio.SubprocessFlags.STDOUT_PIPE | Gio.SubprocessFlags.STDERR_SILENCE
                            );
                            proc.communicate_utf8_async(null, null, (p, res) => {
                                try {
                                    const [, stdout] = p.communicate_utf8_finish(res);
                                    const ip = (stdout || '').trim().split(/\s+/)[0];
                                    GLib.idle_add(GLib.PRIORITY_DEFAULT_IDLE, () => {
                                        this._termPrint(ip ? `${host} → ${ip}` : `${host} → [sin respuesta]`);
                                        this._termPrint('');
                                        this._termPrompt();
                                        return false;
                                    });
                                } catch(e) {
                                    GLib.idle_add(GLib.PRIORITY_DEFAULT_IDLE, () => {
                                        this._termPrint(`Error: ${e}`);
                                        this._termPrint('');
                                        this._termPrompt();
                                        return false;
                                    });
                                }
                            });
                        } catch(e) {
                            this._termPrint(`Error: ${e}`);
                        }
                        return;
                    }
                }
            }

        } else if (cmd === 'bookmark') {
            const wv = this._wv();
            const uri = wv.get_uri();
            if (!uri || uri === 'about:blank') {
                this._termPrint('Sin página activa.');
            } else {
                const title = wv.get_title() || uri;
                if (this._app.isBookmarked(uri)) {
                    this._app.removeBookmark(uri);
                    this._termPrint(`Marcador eliminado: ${uri}`);
                    this._bookmarkStar.set_label('★');
                } else {
                    this._app.addBookmark(uri, title);
                    this._termPrint(`Marcador guardado: ${title}`);
                    this._bookmarkStar.set_label('★');
                }
            }

        } else if (cmd === 'bookmarks') {
            if (!this._app.bookmarks.length) {
                this._termPrint('Sin marcadores guardados.');
            } else {
                const lines = ['Marcadores guardados:'];
                this._app.bookmarks.forEach((b, i) => {
                    lines.push(`  ${String(i + 1).padStart(3)}. ${b.title}\n       ${b.url}`);
                });
                this._termPrint(lines.join('\n'));
            }

        } else if (cmd === 'history') {
            const n = parseInt(args, 10) || 10;
            const hist = this._app.history;
            if (!hist.length) {
                this._termPrint('El historial está vacío.');
            } else {
                const slice = hist.slice(-n).reverse();
                const lines = [`Últimas ${n} páginas:`];
                slice.forEach((h, i) => {
                    const ts = (h.ts || '').slice(0, 19).replace('T', ' ');
                    lines.push(`  ${String(i + 1).padStart(3)}. [${ts}] ${h.title}\n       ${h.url}`);
                });
                this._termPrint(lines.join('\n'));
            }

        } else if (cmd === 'dark') {
            this._app.darkMode = !this._app.darkMode;
            this._termPrint(`Modo oscuro ${this._app.darkMode ? 'activado' : 'desactivado'}.`);
            if (this._app.darkMode) GLib.idle_add(GLib.PRIORITY_DEFAULT_IDLE, () => { this._applyDarkCss(); return false; });

        } else if (cmd === 'calc') {
            if (args) this._termPrint(`${args} = ${safeEval(args)}`);
            else this._termPrint('Uso: calc <expresión>');

        } else if (cmd === 'time') {
            const now = new Date();
            this._termPrint(`${String(now.getHours()).padStart(2,'0')}:${String(now.getMinutes()).padStart(2,'0')}:${String(now.getSeconds()).padStart(2,'0')}`);

        } else if (cmd === 'date') {
            const now = new Date();
            this._termPrint(`${now.getFullYear()}-${String(now.getMonth()+1).padStart(2,'0')}-${String(now.getDate()).padStart(2,'0')}`);

        } else if (cmd === 'echo') {
            if (args) this._termPrint(args);

        } else if (cmd === 'clear' || cmd === 'clean') {
            this._termBuf.set_text('', -1);

        } else if (cmd === 'about') {
            this._termPrint(
                'PrekT-BR v2.1 — Hardened Edition\n' +
                'WebKitGTK 6 + GTK 4 + GJS\n' +
                'Redes: Tor (SOCKS5 :9050), I2P (HTTP :4444)\n' +
                '─── Protecciones activas ──────────────────────\n' +
                '  [*] WebRTC deshabilitado (sin IP leak)\n' +
                '  [*] User-Agent: Firefox/Windows normalizado\n' +
                '  [*] Letterboxing: viewport redondeado a 100x100\n' +
                '  [*] performance.now() degradado a 2ms (anti timing-attack)\n' +
                '  [*] SharedArrayBuffer/Atomics: eliminados\n' +
                '  [*] Canvas: ruido por semilla de sesión\n' +
                '  [*] AudioContext: ruido en análisis de frecuencia\n' +
                '  [*] WebGL: vendor/renderer normalizado, debug bloqueado\n' +
                '  [*] Navigator: platform/plugins/idioma/memoria fijos\n' +
                '  [*] Screen: resolución normalizada a 1920x1080\n' +
                '  [*] Timezone: forzado a UTC\n' +
                '  [*] Battery API: datos fijos\n' +
                '  [*] Font enumeration: bloqueada\n' +
                '  [*] Geolocation: bloqueada silenciosamente\n' +
                '  [*] MediaDevices: cámaras/micrófonos ocultos\n' +
                '  [*] SpeechSynthesis/Recognition: bloqueados\n' +
                '  [*] Cookies: limpieza automática al cerrar pestaña\n' +
                '  [*] JS popups y autoplay: bloqueados\n' +
                '  [*] Esquemas peligrosos bloqueados (js:, data:, blob:)\n' +
                '  [*] calc: evaluador seguro sin eval()\n' +
                '  [*] DevTools: deshabilitadas\n' +
                '  [*] Historial/marcadores: cifrados en disco\n' +
                'Comandos: clearcookies | clearall\n'
            );

        } else if (cmd === 'clearcookies') {
            this._clearTabData(this._td());
            this._termPrint('Cookies y datos de sesión de la pestaña actual eliminados.');

        } else if (cmd === 'clearall') {
            for (const td of this._tabs) this._clearTabData(td);
            this._termPrint('Datos de todas las pestañas eliminados.');

        } else if (cmd === 'quit' || cmd === 'exit') {
            this._app.quit();
            return;

        } else {
            this._termPrint(`Comando desconocido: '${cmd}'  —  escribe 'help'`);
        }

        this._termPrint('');
        this._termPrompt();
    }
}

// ─── Aplicación ───────────────────────────────────────────────────────────────

class PrekTBR extends Gtk.Application {
    static { GObject.registerClass(this); }

    constructor() {
        super({
            application_id: 'com.cinnamolhyia.prektbr',
            flags: Gio.ApplicationFlags.HANDLES_OPEN,
        });

        const newtabPath = GLib.build_filenamev([GLib.get_current_dir(), 'newtab.html']);
        this.homeUri = `file://${newtabPath}`;
        this.initialUrl = this.homeUri;
        this.darkMode = false;

        this.history   = loadJson(HISTORY_FILE,   []);
        this.bookmarks = loadJson(BOOKMARKS_FILE, []);
    }

    vfunc_startup() {
        super.vfunc_startup();
        // Suprimir warnings GTK en entornos sin sandbox
        GLib.setenv('GDK_DEBUG', 'portals', true);
        GLib.setenv('GTK_A11Y', 'none', true);

        const provider = new Gtk.CssProvider();
        provider.load_from_data(GLOBAL_CSS, -1);
        Gtk.StyleContext.add_provider_for_display(
            Gdk.Display.get_default(), provider,
            Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
        );
    }

    vfunc_activate() {
        let win = this.active_window;
        if (!win) {
            win = new BrowserWindow(this);
            win.set_default_size(1280, 800);
        }
        win.present();
    }

    vfunc_open(files, hint) {
        let win = this.active_window;
        if (!win) {
            win = new BrowserWindow(this);
            win.set_default_size(1280, 800);
        }
        if (files && files.length > 0)
            win._openTab({ uri: files[0].get_uri() });
        win.present();
    }

    addHistory(url, title = '') {
        if (!url || url.startsWith('file://') || url === 'about:blank') return;
        const entry = { url, title: title || url, ts: nowIso() };
        if (this.history.length && this.history[this.history.length - 1].url === url) return;
        this.history.push(entry);
        if (this.history.length > 2000) this.history = this.history.slice(-2000);
        saveJson(HISTORY_FILE, this.history);
    }

    addBookmark(url, title = '') {
        if (!url || url === 'about:blank') return false;
        if (this.bookmarks.some(b => b.url === url)) return false;
        this.bookmarks.push({ url, title: title || url });
        saveJson(BOOKMARKS_FILE, this.bookmarks);
        return true;
    }

    removeBookmark(url) {
        this.bookmarks = this.bookmarks.filter(b => b.url !== url);
        saveJson(BOOKMARKS_FILE, this.bookmarks);
    }

    isBookmarked(url) {
        return this.bookmarks.some(b => b.url === url);
    }
}

// ─── Punto de entrada ─────────────────────────────────────────────────────────

const app = new PrekTBR();
app.run([imports.system.programInvocationName, ...programArgs]);
