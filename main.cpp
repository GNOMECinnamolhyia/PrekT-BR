/*
 * PrekT-BR — Navegador personal basado en WebKitGTK 6
 * Versión 2.1 - SECURE ENHANCED
 */

#include <gtk/gtk.h>
#include <webkit/webkit.h>

#include <algorithm>
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <regex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

// JSON (header-only nlohmann/json — instalar: apt install nlohmann-json3-dev)
#include <nlohmann/json.hpp>
using json = nlohmann::json;

// OpenSSL para PBKDF2
#include <openssl/evp.h>
#include <openssl/rand.h>

// POSIX
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

namespace fs = std::filesystem;

// ─── Rutas de datos ───────────────────────────────────────────────────────────

static std::string g_data_dir;
static std::string g_history_file;
static std::string g_bookmarks_file;
static std::string g_salt_file;

static void init_data_paths() {
    const char* home = getenv("HOME");
    if (!home) home = "/tmp";
    g_data_dir      = std::string(home) + "/.local/share/prektbr";
    g_history_file  = g_data_dir + "/history.json";
    g_bookmarks_file= g_data_dir + "/bookmarks.json";
    g_salt_file     = g_data_dir + "/.salt";
    fs::create_directories(g_data_dir);
}

// ─── Cifrado XOR + PBKDF2 ─────────────────────────────────────────────────────

static std::vector<uint8_t> g_key;

static std::vector<uint8_t> get_or_create_salt() {
    std::vector<uint8_t> salt(32);
    std::ifstream fin(g_salt_file, std::ios::binary);
    if (fin && fin.read(reinterpret_cast<char*>(salt.data()), 32) && fin.gcount() == 32) {
        return salt;
    }
    RAND_bytes(salt.data(), 32);
    {
        std::ofstream fout(g_salt_file, std::ios::binary);
        fout.write(reinterpret_cast<const char*>(salt.data()), 32);
    }
    chmod(g_salt_file.c_str(), 0600);
    return salt;
}

static std::vector<uint8_t> derive_key(int length = 64) {
    const char* user_env = getenv("USER");
    if (!user_env) user_env = getenv("USERNAME");
    if (!user_env) user_env = "prektbr";
    std::string user_str = std::string(user_env) + "prektbr-v3";
    auto salt = get_or_create_salt();
    std::vector<uint8_t> dk(length);
    PKCS5_PBKDF2_HMAC(
        user_str.c_str(), (int)user_str.size(),
        salt.data(), (int)salt.size(),
        200000, EVP_sha256(),
        length, dk.data()
    );
    return dk;
}

static std::vector<uint8_t> xor_bytes(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> result(data.size());
    for (size_t i = 0; i < data.size(); i++) {
        result[i] = data[i] ^ g_key[i % g_key.size()];
    }
    return result;
}

// ─── Base64 simple ────────────────────────────────────────────────────────────

static const std::string B64_CHARS =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static std::string base64_encode(const std::vector<uint8_t>& data) {
    std::string out;
    int i = 0, j = 0;
    uint8_t buf3[3], buf4[4];
    size_t len = data.size();
    size_t pos = 0;
    while (pos < len) {
        i = 0;
        while (i < 3 && pos < len) buf3[i++] = data[pos++];
        for (j = i; j < 3; j++) buf3[j] = 0;
        buf4[0] = (buf3[0] & 0xfc) >> 2;
        buf4[1] = ((buf3[0] & 0x03) << 4) + ((buf3[1] & 0xf0) >> 4);
        buf4[2] = ((buf3[1] & 0x0f) << 2) + ((buf3[2] & 0xc0) >> 6);
        buf4[3] = buf3[2] & 0x3f;
        for (j = 0; j < i + 1; j++) out += B64_CHARS[buf4[j]];
        while (i++ < 3) out += '=';
    }
    return out;
}

static std::vector<uint8_t> base64_decode(const std::string& s) {
    std::vector<uint8_t> out;
    int i = 0, j = 0;
    uint8_t buf4[4], buf3[3];
    size_t pos = 0;
    auto is_b64 = [](uint8_t c) {
        return (isalnum(c) || c == '+' || c == '/');
    };
    while (pos < s.size() && s[pos] != '=' && is_b64((uint8_t)s[pos])) {
        buf4[i++] = (uint8_t)s[pos++];
        if (i == 4) {
            for (int k = 0; k < 4; k++) buf4[k] = (uint8_t)B64_CHARS.find(buf4[k]);
            buf3[0] = (buf4[0] << 2) + ((buf4[1] & 0x30) >> 4);
            buf3[1] = ((buf4[1] & 0xf) << 4) + ((buf4[2] & 0x3c) >> 2);
            buf3[2] = ((buf4[2] & 0x3) << 6) + buf4[3];
            for (int k = 0; k < 3; k++) out.push_back(buf3[k]);
            i = 0;
        }
    }
    if (i) {
        for (j = i; j < 4; j++) buf4[j] = 0;
        for (j = 0; j < 4; j++) buf4[j] = (uint8_t)B64_CHARS.find(buf4[j]);
        buf3[0] = (buf4[0] << 2) + ((buf4[1] & 0x30) >> 4);
        buf3[1] = ((buf4[1] & 0xf) << 4) + ((buf4[2] & 0x3c) >> 2);
        buf3[2] = ((buf4[2] & 0x3) << 6) + buf4[3];
        for (j = 0; j < i - 1; j++) out.push_back(buf3[j]);
    }
    return out;
}

// ─── Carga / guardado JSON cifrado ────────────────────────────────────────────

static json load_json_file(const std::string& path, const json& defval) {
    try {
        std::ifstream fin(path, std::ios::binary);
        if (!fin) return defval;
        std::vector<uint8_t> raw((std::istreambuf_iterator<char>(fin)),
                                  std::istreambuf_iterator<char>());
        // Intentar descifrado XOR+base64
        try {
            auto decoded = base64_decode(std::string(raw.begin(), raw.end()));
            auto plain   = xor_bytes(decoded);
            return json::parse(std::string(plain.begin(), plain.end()));
        } catch (...) {}
        // Fallback: JSON plano
        return json::parse(std::string(raw.begin(), raw.end()));
    } catch (...) {
        return defval;
    }
}

static void save_json_file(const std::string& path, const json& data) {
    try {
        std::string s = data.dump(2);
        std::vector<uint8_t> raw(s.begin(), s.end());
        auto encrypted = base64_encode(xor_bytes(raw));
        std::ofstream fout(path, std::ios::binary);
        fout.write(encrypted.data(), encrypted.size());
    } catch (const std::exception& e) {
        std::cerr << "[prektbr] Error guardando " << path << ": " << e.what() << "\n";
    }
}

// ─── CSS global ───────────────────────────────────────────────────────────────

static const char* GLOBAL_CSS = R"css(
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
)css";

// ─── JavaScript de anti-fingerprinting ───────────────────────────────────────

static const char* FP_PROTECTION_JS = R"js(
(function() {
    'use strict';

    // 1. LETTERBOXING
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

    // 2. TIMING ATTACKS
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

    // 3. CANVAS FINGERPRINTING
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

    // 4. AUDIOCONTEXT
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

    // 5. NAVIGATOR
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

    // 6. SCREEN
    (function() {
        const s = { width: 1920, height: 1080, availWidth: 1920, availHeight: 1080,
                    colorDepth: 24, pixelDepth: 24, orientation: { type: 'landscape-primary', angle: 0 } };
        for (const [k, v] of Object.entries(s)) {
            try { Object.defineProperty(screen, k, { get: () => v, configurable: true }); } catch(e) {}
        }
        try { Object.defineProperty(window, 'devicePixelRatio', { get: () => 1, configurable: true }); } catch(e) {}
    })();

    // 7. WEBGL
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

    // 8. BATTERY API
    if (navigator.getBattery) {
        navigator.getBattery = () => Promise.resolve({
            charging: true, chargingTime: 0,
            dischargingTime: Infinity, level: 1.0,
            addEventListener: () => {}, removeEventListener: () => {}
        });
    }

    // 9. TIMEZONE
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

    // 10. FUENTES
    if (document.fonts && document.fonts.check) {
        const generic = ['serif','sans-serif','monospace','cursive','fantasy','system-ui'];
        const origCheck = document.fonts.check.bind(document.fonts);
        document.fonts.check = (font, txt) =>
            generic.some(g => font.toLowerCase().includes(g)) ? origCheck(font, txt) : false;
        const origLoad = document.fonts.load.bind(document.fonts);
        document.fonts.load = (font, txt) =>
            generic.some(g => font.toLowerCase().includes(g)) ? origLoad(font, txt) : Promise.resolve([]);
    }

    // 11. WINDOW.NAME
    window.name = '';

    // 12. NETWORK INFORMATION API
    try {
        Object.defineProperty(navigator, 'onLine', { get: () => true, configurable: true });
    } catch(e) {}

    // 13. GEOLOCATION
    if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition = (ok, err) => {
            if (err) err({ code: 1, message: 'Permission denied' });
        };
        navigator.geolocation.watchPosition = (ok, err) => {
            if (err) err({ code: 1, message: 'Permission denied' });
            return 0;
        };
    }

    // 14. MEDIA DEVICES
    if (navigator.mediaDevices) {
        navigator.mediaDevices.enumerateDevices = () => Promise.resolve([]);
        navigator.mediaDevices.getUserMedia    = () => Promise.reject(new DOMException('NotAllowedError'));
        navigator.mediaDevices.getDisplayMedia = () => Promise.reject(new DOMException('NotAllowedError'));
    }

    // 15. SPEECH
    try {
        if (window.speechSynthesis) {
            window.speechSynthesis.getVoices = () => [];
        }
        delete window.SpeechRecognition;
        delete window.webkitSpeechRecognition;
    } catch(e) {}

})();
)js";

// ─── Utilidades de cadena ─────────────────────────────────────────────────────

static std::string str_tolower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}

static std::string str_trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

static std::string url_encode(const std::string& s) {
    std::ostringstream o;
    for (unsigned char c : s) {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            o << c;
        } else {
            o << '%' << std::uppercase << std::hex << (int)c;
        }
    }
    return o.str();
}

// Parsear host y scheme de una URI
static void parse_uri(const std::string& uri, std::string& scheme, std::string& host) {
    size_t cs = uri.find("://");
    if (cs == std::string::npos) { scheme = ""; host = uri; return; }
    scheme = uri.substr(0, cs);
    size_t hs = cs + 3;
    size_t he = uri.find_first_of("/?#", hs);
    host = (he == std::string::npos) ? uri.substr(hs) : uri.substr(hs, he - hs);
    // Quitar puerto
    size_t cp = host.rfind(':');
    if (cp != std::string::npos) host = host.substr(0, cp);
}

// ─── Timestamp ISO ────────────────────────────────────────────────────────────

static std::string now_iso() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", localtime(&t));
    return buf;
}

// ─── Evaluador de expresiones matemáticas (safe_eval) ─────────────────────────

// Evaluador AST simple: números, +, -, *, /, **, (, ), pow, sqrt, sin, cos, tan, etc.
struct CalcParser {
    std::string expr;
    size_t pos;
    std::string error;

    double parse_number() {
        size_t start = pos;
        while (pos < expr.size() && (isdigit(expr[pos]) || expr[pos] == '.')) pos++;
        if (pos == start) { error = "número esperado"; return 0; }
        return std::stod(expr.substr(start, pos - start));
    }

    double parse_primary();
    double parse_unary();
    double parse_pow();
    double parse_mul();
    double parse_add();
    double parse();
};

double CalcParser::parse_primary() {
    while (pos < expr.size() && expr[pos] == ' ') pos++;
    if (pos >= expr.size()) { error = "expresión incompleta"; return 0; }

    if (expr[pos] == '(') {
        pos++;
        double v = parse_add();
        while (pos < expr.size() && expr[pos] == ' ') pos++;
        if (pos < expr.size() && expr[pos] == ')') pos++;
        else error = "')' esperado";
        return v;
    }

    // Función o nombre
    if (isalpha(expr[pos]) || expr[pos] == '_') {
        size_t start = pos;
        while (pos < expr.size() && (isalnum(expr[pos]) || expr[pos] == '_')) pos++;
        std::string name = expr.substr(start, pos - start);
        while (pos < expr.size() && expr[pos] == ' ') pos++;
        if (pos < expr.size() && expr[pos] == '(') {
            pos++;
            double a = parse_add();
            double b = 0;
            bool has_b = false;
            while (pos < expr.size() && expr[pos] == ' ') pos++;
            if (pos < expr.size() && expr[pos] == ',') {
                pos++;
                b = parse_add();
                has_b = true;
            }
            while (pos < expr.size() && expr[pos] == ' ') pos++;
            if (pos < expr.size() && expr[pos] == ')') pos++;
            else error = "')' esperado";

            if (name == "sqrt")  return std::sqrt(a);
            if (name == "sin")   return std::sin(a);
            if (name == "cos")   return std::cos(a);
            if (name == "tan")   return std::tan(a);
            if (name == "asin")  return std::asin(a);
            if (name == "acos")  return std::acos(a);
            if (name == "atan")  return std::atan(a);
            if (name == "atan2") return std::atan2(a, b);
            if (name == "log")   return std::log(a);
            if (name == "log2")  return std::log2(a);
            if (name == "log10") return std::log10(a);
            if (name == "exp")   return std::exp(a);
            if (name == "abs")   return std::abs(a);
            if (name == "ceil")  return std::ceil(a);
            if (name == "floor") return std::floor(a);
            if (name == "round") return std::round(a);
            if (name == "pow")   return std::pow(a, b);
            if (name == "fmod")  return std::fmod(a, b);
            if (name == "hypot") return std::hypot(a, b);
            if (name == "max")   return has_b ? std::max(a, b) : a;
            if (name == "min")   return has_b ? std::min(a, b) : a;
            error = "función desconocida: " + name;
            return 0;
        }
        // Constantes
        if (name == "pi" || name == "PI") return M_PI;
        if (name == "e"  || name == "E")  return M_E;
        if (name == "inf" || name == "inf") return INFINITY;
        error = "nombre no permitido: " + name;
        return 0;
    }

    return parse_number();
}

double CalcParser::parse_unary() {
    while (pos < expr.size() && expr[pos] == ' ') pos++;
    if (pos < expr.size() && expr[pos] == '-') { pos++; return -parse_unary(); }
    if (pos < expr.size() && expr[pos] == '+') { pos++; return  parse_unary(); }
    return parse_primary();
}

double CalcParser::parse_pow() {
    double base = parse_unary();
    while (pos < expr.size()) {
        while (pos < expr.size() && expr[pos] == ' ') pos++;
        if (pos < expr.size() && expr[pos] == '*' &&
            pos+1 < expr.size() && expr[pos+1] == '*') {
            pos += 2;
            double exp = parse_unary();
            base = std::pow(base, exp);
        } else if (pos < expr.size() && expr[pos] == '^') {
            pos++;
            double exp = parse_unary();
            base = std::pow(base, exp);
        } else break;
    }
    return base;
}

double CalcParser::parse_mul() {
    double result = parse_pow();
    while (pos < expr.size()) {
        while (pos < expr.size() && expr[pos] == ' ') pos++;
        if (pos >= expr.size()) break;
        char op = expr[pos];
        if (op == '*' && !(pos+1 < expr.size() && expr[pos+1] == '*')) {
            pos++;
            result *= parse_pow();
        } else if (op == '/') {
            pos++;
            double d = parse_pow();
            if (d == 0) { error = "división por cero"; return 0; }
            result /= d;
        } else if (op == '%') {
            pos++;
            double d = parse_pow();
            result = std::fmod(result, d);
        } else break;
    }
    return result;
}

double CalcParser::parse_add() {
    double result = parse_mul();
    while (pos < expr.size()) {
        while (pos < expr.size() && expr[pos] == ' ') pos++;
        if (pos >= expr.size()) break;
        char op = expr[pos];
        if (op == '+') { pos++; result += parse_mul(); }
        else if (op == '-') { pos++; result -= parse_mul(); }
        else break;
    }
    return result;
}

double CalcParser::parse() {
    pos = 0; error = "";
    double v = parse_add();
    return v;
}

static std::string safe_eval(const std::string& expr_raw) {
    // Solo caracteres seguros
    static const std::regex allowed("^[\\d\\s\\+\\-\\*/\\(\\)\\.\\^%,a-z_A-Z]+$");
    std::string expr = str_trim(expr_raw);
    if (!std::regex_match(expr, allowed))
        return "Error: expresión no permitida";
    CalcParser p;
    p.expr = expr;
    double v = p.parse();
    if (!p.error.empty()) return "Error: " + p.error;
    // Formatear resultado
    if (v == (long long)v && std::abs(v) < 1e15) {
        std::ostringstream os;
        os << (long long)v;
        return os.str();
    }
    std::ostringstream os;
    os << v;
    return os.str();
}

// ─── Formateador simple de HTML ───────────────────────────────────────────────

static std::string format_html(const std::string& html) {
    // Formateador básico de indentación para el inspector
    static const std::vector<std::string> inline_tags = {
        "a","abbr","acronym","b","bdo","big","br","button","cite",
        "code","dfn","em","i","img","input","kbd","label","map",
        "object","output","q","samp","select","small","span","strong",
        "sub","sup","textarea","time","tt","u","var"
    };
    static const std::vector<std::string> void_tags = {
        "area","base","br","col","embed","hr","img","input","link",
        "meta","param","source","track","wbr"
    };
    static const std::vector<std::string> raw_tags = {"script","style"};

    auto is_in = [](const std::vector<std::string>& v, const std::string& s) {
        return std::find(v.begin(), v.end(), s) != v.end();
    };

    std::string out;
    int indent = 0;
    bool in_raw = false;
    size_t i = 0;
    size_t n = html.size();

    while (i < n) {
        if (html[i] == '<') {
            // Comentario
            if (i+3 < n && html.substr(i,4) == "<!--") {
                size_t e = html.find("-->", i+4);
                if (e == std::string::npos) e = n - 3;
                out += std::string(indent*2, ' ') + html.substr(i, e-i+3) + "\n";
                i = e + 3;
                continue;
            }
            // DOCTYPE
            if (i+1 < n && html[i+1] == '!') {
                size_t e = html.find('>', i);
                if (e == std::string::npos) e = n-1;
                out += html.substr(i, e-i+1) + "\n";
                i = e + 1;
                continue;
            }
            // Closing tag
            if (i+1 < n && html[i+1] == '/') {
                size_t e = html.find('>', i);
                if (e == std::string::npos) e = n-1;
                std::string tag_full = html.substr(i+2, e-i-2);
                // trim
                while (!tag_full.empty() && tag_full.back() == ' ') tag_full.pop_back();
                std::string tag = str_tolower(tag_full);
                if (is_in(raw_tags, tag)) in_raw = false;
                if (!is_in(void_tags, tag) && !is_in(inline_tags, tag)) {
                    indent = std::max(0, indent-1);
                }
                if (in_raw)
                    out += "</" + tag_full + ">\n";
                else
                    out += std::string(indent*2, ' ') + "</" + tag_full + ">\n";
                i = e + 1;
                continue;
            }
            // Opening tag
            size_t e = html.find('>', i);
            if (e == std::string::npos) e = n-1;
            std::string tag_content = html.substr(i+1, e-i-1);
            // Extract tag name
            size_t sp = tag_content.find_first_of(" \t\r\n/");
            std::string tag = str_tolower(sp == std::string::npos ? tag_content : tag_content.substr(0, sp));
            if (in_raw) {
                out += html.substr(i, e-i+1) + "\n";
            } else {
                out += std::string(indent*2, ' ') + html.substr(i, e-i+1) + "\n";
            }
            bool self_closing = (!tag_content.empty() && tag_content.back() == '/');
            if (!self_closing && !is_in(void_tags, tag) && !is_in(inline_tags, tag)) {
                if (!in_raw) indent++;
            }
            if (is_in(raw_tags, tag)) in_raw = true;
            i = e + 1;
        } else {
            // Text
            size_t e = html.find('<', i);
            if (e == std::string::npos) e = n;
            std::string text = html.substr(i, e-i);
            std::string stripped = str_trim(text);
            if (!stripped.empty()) {
                if (in_raw)
                    out += text + "\n";
                else
                    out += std::string(indent*2, ' ') + stripped + "\n";
            }
            i = e;
        }
    }
    return out;
}

// ─── Datos de pestaña ─────────────────────────────────────────────────────────

struct TabData {
    WebKitWebView* webview;
    std::string    mode; // "normal" | "tor" | "i2p"
    GtkWidget*     tab_widget;  // el Box de pestaña en la barra
    GtkButton*     title_btn;   // botón de título dentro del tab_widget
};

// ─── Aplicación principal ─────────────────────────────────────────────────────

struct PrekTBR;
struct BrowserWindow;

struct PrekTBR {
    GtkApplication* app;
    std::string     home_uri;
    std::string     initial_url;
    bool            dark_mode = false;
    json            history;
    json            bookmarks;

    PrekTBR() {
        char cwd[4096] = {};
        getcwd(cwd, sizeof(cwd));
        home_uri    = "file://" + std::string(cwd) + "/newtab.html";
        initial_url = home_uri;
        history     = load_json_file(g_history_file,   json::array());
        bookmarks   = load_json_file(g_bookmarks_file, json::array());
    }

    void add_history(const std::string& url, const std::string& title_in = "") {
        if (url.empty() || url.substr(0,7) == "file://" || url == "about:blank") return;
        std::string title = title_in.empty() ? url : title_in;
        if (!history.empty() && history.back()["url"] == url) return;
        json entry;
        entry["url"]   = url;
        entry["title"] = title;
        entry["ts"]    = now_iso();
        history.push_back(entry);
        if ((int)history.size() > 2000)
            history = json(history.begin() + (history.size() - 2000), history.end());
        save_json_file(g_history_file, history);
    }

    bool add_bookmark(const std::string& url, const std::string& title_in = "") {
        if (url.empty() || url == "about:blank") return false;
        for (auto& b : bookmarks)
            if (b["url"] == url) return false;
        json entry;
        entry["url"]   = url;
        entry["title"] = title_in.empty() ? url : title_in;
        bookmarks.push_back(entry);
        save_json_file(g_bookmarks_file, bookmarks);
        return true;
    }

    void remove_bookmark(const std::string& url) {
        bookmarks.erase(
            std::remove_if(bookmarks.begin(), bookmarks.end(),
                [&](const json& b){ return b["url"] == url; }),
            bookmarks.end()
        );
        save_json_file(g_bookmarks_file, bookmarks);
    }

    bool is_bookmarked(const std::string& url) {
        for (auto& b : bookmarks)
            if (b["url"] == url) return true;
        return false;
    }
};

// ─── Ventana del navegador ────────────────────────────────────────────────────

struct BrowserWindow {
    GtkApplicationWindow* window;
    PrekTBR*   app;
    std::vector<TabData> tabs;
    int        current_tab = -1;
    std::string sidebar_mode; // "" | "bookmarks" | "history"
    bool       inspector_mode              = false;
    bool       findbar_visible             = false;
    bool       terminal_visible            = false;
    bool       inspector_handler_registered = false;

    // Widgets
    GtkWidget* tabbar_box;
    GtkWidget* back_btn;
    GtkWidget* forward_btn;
    GtkWidget* reload_btn;
    GtkWidget* home_btn;
    GtkWidget* bookmark_star;
    GtkWidget* url_entry;
    GtkWidget* badge;
    GtkWidget* sec_badge;
    GtkWidget* content_area;
    GtkWidget* sidebar_widget;
    GtkWidget* tab_stack;

    // Terminal
    GtkTextBuffer* terminal_buf;
    GtkWidget*     terminal_tv;
    GtkWidget*     term_scroll;
    GtkTextMark*   prompt_end_mark;

    // Inspector
    GtkTextBuffer* inspector_buf;
    GtkWidget*     inspector_tv;
    GtkWidget*     insp_scroll;
    GtkWidget*     insp_panel;

    // Findbar
    GtkWidget* findbar_box;
    GtkWidget* find_entry;
    GtkWidget* find_label;

    // Statusbar
    GtkWidget* statusbar;
    GtkWidget* dl_progress;

    // ── Ayudantes ────────────────────────────────────────────────────────────

    WebKitWebView* wv() {
        return tabs[current_tab].webview;
    }
    TabData& td() {
        return tabs[current_tab];
    }

    // ── Botón de navegación ──────────────────────────────────────────────────

    GtkWidget* nav_btn(const char* label, const char* tooltip,
                       GCallback cb, gpointer udata = nullptr) {
        GtkWidget* b = gtk_button_new_with_label(label);
        gtk_widget_add_css_class(b, "nav-button");
        gtk_widget_set_tooltip_text(b, tooltip);
        if (cb) g_signal_connect(b, "clicked", cb, udata ? udata : this);
        return b;
    }

    // ── Construcción de la UI ─────────────────────────────────────────────────

    void build_ui() {
        GtkWidget* root = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);

        // ── Barra de pestañas
        tabbar_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 2);
        gtk_widget_add_css_class(tabbar_box, "tabbar");

        GtkWidget* new_tab_btn = gtk_button_new_with_label("+");
        gtk_widget_add_css_class(new_tab_btn, "new-tab-btn");
        gtk_widget_set_tooltip_text(new_tab_btn, "Nueva pestaña");
        g_signal_connect(new_tab_btn, "clicked", G_CALLBACK(+[](GtkButton*, gpointer d){
            static_cast<BrowserWindow*>(d)->open_tab();
        }), this);

        GtkWidget* tabbar_scroll = gtk_scrolled_window_new();
        gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(tabbar_scroll),
                                       GTK_POLICY_AUTOMATIC, GTK_POLICY_NEVER);
        gtk_widget_set_hexpand(tabbar_scroll, TRUE);
        gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(tabbar_scroll), tabbar_box);
        gtk_widget_set_size_request(tabbar_scroll, -1, 38);

        GtkWidget* tabbar_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
        gtk_widget_add_css_class(tabbar_row, "tabbar");
        gtk_box_append(GTK_BOX(tabbar_row), tabbar_scroll);
        gtk_box_append(GTK_BOX(tabbar_row), new_tab_btn);

        // ── Barra de navegación
        back_btn    = nav_btn("←", "Atrás (Alt+Izq)",           G_CALLBACK(+[](GtkButton*, gpointer d){ static_cast<BrowserWindow*>(d)->on_back(); }));
        forward_btn = nav_btn("→", "Adelante (Alt+Der)",         G_CALLBACK(+[](GtkButton*, gpointer d){ static_cast<BrowserWindow*>(d)->on_forward(); }));
        reload_btn  = nav_btn("↻", "Recargar (Ctrl+R)",          G_CALLBACK(+[](GtkButton*, gpointer d){ static_cast<BrowserWindow*>(d)->on_reload(); }));
        home_btn    = nav_btn("⌂", "Ir al inicio",               G_CALLBACK(+[](GtkButton*, gpointer d){ webkit_web_view_load_uri(static_cast<BrowserWindow*>(d)->wv(), static_cast<BrowserWindow*>(d)->app->home_uri.c_str()); }));
        bookmark_star = nav_btn("★", "Guardar marcador",         G_CALLBACK(+[](GtkButton*, gpointer d){ static_cast<BrowserWindow*>(d)->on_toggle_bookmark(); }));

        url_entry = gtk_entry_new();
        gtk_widget_set_hexpand(url_entry, TRUE);
        gtk_widget_add_css_class(url_entry, "url-entry");
        gtk_entry_set_placeholder_text(GTK_ENTRY(url_entry), "Ingresa una URL o busca en DuckDuckGo...");
        g_signal_connect(url_entry, "activate", G_CALLBACK(+[](GtkEntry*, gpointer d){
            static_cast<BrowserWindow*>(d)->on_url_activate();
        }), this);

        badge = gtk_label_new("");
        gtk_widget_add_css_class(badge, "badge-normal");
        gtk_widget_set_tooltip_text(badge, "Modo de red actual");
        gtk_widget_set_visible(badge, FALSE);

        sec_badge = gtk_label_new("");
        gtk_widget_set_tooltip_text(sec_badge, "Estado de seguridad de la página");
        gtk_widget_set_visible(sec_badge, FALSE);

        GtkWidget* bmarks_btn    = nav_btn("⌘",  "Marcadores",            G_CALLBACK(+[](GtkButton*, gpointer d){ static_cast<BrowserWindow*>(d)->toggle_sidebar("bookmarks"); }));
        GtkWidget* history_btn   = nav_btn("⏲", "Historial",             G_CALLBACK(+[](GtkButton*, gpointer d){ static_cast<BrowserWindow*>(d)->toggle_sidebar("history"); }));
        GtkWidget* terminal_btn  = nav_btn(">_", "Terminal (Ctrl+Alt+T)", G_CALLBACK(+[](GtkButton*, gpointer d){ static_cast<BrowserWindow*>(d)->on_toggle_terminal(); }));
        GtkWidget* find_btn      = nav_btn("⌕",  "Buscar en página (Ctrl+F)", G_CALLBACK(+[](GtkButton*, gpointer d){ static_cast<BrowserWindow*>(d)->toggle_findbar(); }));
        GtkWidget* inspector_btn = nav_btn("</>", "Inspector HTML (Ctrl+AltGr+D)", G_CALLBACK(+[](GtkButton*, gpointer d){ static_cast<BrowserWindow*>(d)->toggle_inspector(); }));

        GtkWidget* nav_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);
        gtk_widget_add_css_class(nav_box, "toolbar");
        for (GtkWidget* w : {back_btn, forward_btn, reload_btn, home_btn,
                              sec_badge, url_entry, bookmark_star, badge,
                              bmarks_btn, history_btn, find_btn, inspector_btn, terminal_btn}) {
            gtk_box_append(GTK_BOX(nav_box), w);
        }

        // ── Área de contenido
        content_area = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
        gtk_widget_set_vexpand(content_area, TRUE);
        gtk_widget_set_hexpand(content_area, TRUE);
        sidebar_widget = nullptr;

        tab_stack = gtk_stack_new();
        gtk_widget_set_vexpand(tab_stack, TRUE);
        gtk_widget_set_hexpand(tab_stack, TRUE);
        gtk_box_append(GTK_BOX(content_area), tab_stack);

        // ── Terminal
        terminal_buf = gtk_text_buffer_new(nullptr);
        terminal_tv  = gtk_text_view_new_with_buffer(terminal_buf);
        gtk_text_view_set_editable(GTK_TEXT_VIEW(terminal_tv), TRUE);
        gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(terminal_tv), TRUE);
        gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(terminal_tv), GTK_WRAP_WORD_CHAR);
        gtk_text_view_set_monospace(GTK_TEXT_VIEW(terminal_tv), TRUE);
        gtk_widget_add_css_class(terminal_tv, "terminal");
        gtk_widget_set_size_request(terminal_tv, 340, 200);

        term_scroll = gtk_scrolled_window_new();
        gtk_widget_set_vexpand(term_scroll, TRUE);
        gtk_widget_set_hexpand(term_scroll, FALSE);
        gtk_widget_set_size_request(term_scroll, 340, 200);
        gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(term_scroll), terminal_tv);
        g_object_ref(term_scroll); // Mantener referencia para poder re-añadir al box

        GtkEventController* key_ctrl = gtk_event_controller_key_new();
        g_signal_connect(key_ctrl, "key-pressed", G_CALLBACK(+[](
            GtkEventControllerKey*, guint kv, guint kc, GdkModifierType state, gpointer d) -> gboolean {
            return static_cast<BrowserWindow*>(d)->on_terminal_key(kv, kc, state);
        }), this);
        gtk_widget_add_controller(terminal_tv, key_ctrl);

        // ── Inspector
        inspector_buf = gtk_text_buffer_new(nullptr);
        inspector_tv  = gtk_text_view_new_with_buffer(inspector_buf);
        gtk_text_view_set_editable(GTK_TEXT_VIEW(inspector_tv), TRUE);
        gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(inspector_tv), TRUE);
        gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(inspector_tv), GTK_WRAP_WORD_CHAR);
        gtk_text_view_set_monospace(GTK_TEXT_VIEW(inspector_tv), TRUE);
        gtk_widget_add_css_class(inspector_tv, "inspector-tv");
        gtk_widget_set_size_request(inspector_tv, 400, 200);

        insp_scroll = gtk_scrolled_window_new();
        gtk_widget_set_vexpand(insp_scroll, TRUE);
        gtk_widget_set_hexpand(insp_scroll, FALSE);
        gtk_widget_set_size_request(insp_scroll, 400, 200);
        gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(insp_scroll), inspector_tv);

        GtkWidget* insp_btn_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);
        gtk_widget_add_css_class(insp_btn_box, "toolbar");
        GtkWidget* insp_reload_btn = nav_btn("Cargar HTML", "Obtener HTML actual de la página",
            G_CALLBACK(+[](GtkButton*, gpointer d){ static_cast<BrowserWindow*>(d)->inspector_load(); }));
        GtkWidget* insp_apply_btn  = nav_btn("Aplicar",     "Aplicar HTML editado a la página",
            G_CALLBACK(+[](GtkButton*, gpointer d){ static_cast<BrowserWindow*>(d)->inspector_apply(); }));
        GtkWidget* insp_close_btn  = nav_btn("Cerrar",      "Cerrar inspector",
            G_CALLBACK(+[](GtkButton*, gpointer d){ static_cast<BrowserWindow*>(d)->close_inspector(); }));
        gtk_box_append(GTK_BOX(insp_btn_box), insp_reload_btn);
        gtk_box_append(GTK_BOX(insp_btn_box), insp_apply_btn);
        gtk_box_append(GTK_BOX(insp_btn_box), insp_close_btn);

        insp_panel = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
        gtk_box_append(GTK_BOX(insp_panel), insp_btn_box);
        gtk_box_append(GTK_BOX(insp_panel), insp_scroll);
        g_object_ref(insp_panel); // Mantener referencia para poder re-añadir al box

        GtkEventController* insp_key = gtk_event_controller_key_new();
        g_signal_connect(insp_key, "key-pressed", G_CALLBACK(+[](
            GtkEventControllerKey*, guint kv, guint kc, GdkModifierType state, gpointer d) -> gboolean {
            return static_cast<BrowserWindow*>(d)->on_inspector_key(kv, kc, state);
        }), this);
        gtk_widget_add_controller(inspector_tv, insp_key);

        // ── Findbar
        findbar_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
        gtk_widget_add_css_class(findbar_box, "findbar");
        find_entry = gtk_entry_new();
        gtk_widget_add_css_class(find_entry, "findbar-entry");
        gtk_entry_set_placeholder_text(GTK_ENTRY(find_entry), "Buscar en página…");
        g_signal_connect(find_entry, "activate", G_CALLBACK(+[](GtkEntry*, gpointer d){
            static_cast<BrowserWindow*>(d)->find_next();
        }), this);
        g_signal_connect(find_entry, "changed", G_CALLBACK(+[](GtkEditable*, gpointer d){
            static_cast<BrowserWindow*>(d)->find_changed();
        }), this);
        GtkWidget* fp_btn = nav_btn("↑", "Anterior", G_CALLBACK(+[](GtkButton*, gpointer d){ static_cast<BrowserWindow*>(d)->find_prev(); }));
        GtkWidget* fn_btn = nav_btn("↓", "Siguiente", G_CALLBACK(+[](GtkButton*, gpointer d){ static_cast<BrowserWindow*>(d)->find_next(); }));
        GtkWidget* fc_btn = nav_btn("✕", "Cerrar (Esc)", G_CALLBACK(+[](GtkButton*, gpointer d){ static_cast<BrowserWindow*>(d)->close_findbar(); }));
        find_label = gtk_label_new("");
        gtk_widget_add_css_class(find_label, "findbar-label");
        gtk_box_append(GTK_BOX(findbar_box), find_entry);
        gtk_box_append(GTK_BOX(findbar_box), fp_btn);
        gtk_box_append(GTK_BOX(findbar_box), fn_btn);
        gtk_box_append(GTK_BOX(findbar_box), find_label);
        gtk_box_append(GTK_BOX(findbar_box), fc_btn);

        // ── Statusbar + barra de progreso
        statusbar = gtk_label_new("");
        gtk_widget_add_css_class(statusbar, "statusbar");
        gtk_label_set_xalign(GTK_LABEL(statusbar), 0.0f);
        gtk_widget_set_hexpand(statusbar, TRUE);
        gtk_label_set_ellipsize(GTK_LABEL(statusbar), PANGO_ELLIPSIZE_END);

        dl_progress = gtk_progress_bar_new();
        gtk_widget_add_css_class(dl_progress, "dl-progress");
        gtk_widget_set_visible(dl_progress, FALSE);
        gtk_widget_set_valign(dl_progress, GTK_ALIGN_CENTER);
        gtk_widget_set_size_request(dl_progress, 150, -1);

        GtkWidget* statusbar_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
        gtk_widget_add_css_class(statusbar_box, "statusbar");
        gtk_box_append(GTK_BOX(statusbar_box), statusbar);
        gtk_box_append(GTK_BOX(statusbar_box), dl_progress);

        gtk_box_append(GTK_BOX(root), tabbar_row);
        gtk_box_append(GTK_BOX(root), nav_box);
        gtk_box_append(GTK_BOX(root), content_area);
        gtk_box_append(GTK_BOX(root), findbar_box);
        gtk_box_append(GTK_BOX(root), statusbar_box);
        gtk_window_set_child(GTK_WINDOW(window), root);
        gtk_widget_set_visible(findbar_box, FALSE);

        // ── Atajos de teclado globales
        GtkEventController* key_global = gtk_event_controller_key_new();
        g_signal_connect(key_global, "key-pressed", G_CALLBACK(+[](
            GtkEventControllerKey*, guint kv, guint kc, GdkModifierType state, gpointer d) -> gboolean {
            return static_cast<BrowserWindow*>(d)->on_global_key(kv, kc, state);
        }), this);
        gtk_widget_add_controller(GTK_WIDGET(window), key_global);

        term_print("PrekT-BR v2.1  —  escribe 'help' para ver los comandos");
        term_prompt();
    }

    // ── Pestaña: crear widget ────────────────────────────────────────────────

    void make_tab_widget(int idx) {
        GtkWidget* tab_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
        gtk_widget_add_css_class(tab_box, "tab-btn");

        char lbl[32];
        snprintf(lbl, sizeof(lbl), "Tab %d", idx+1);
        GtkWidget* title_btn = gtk_button_new_with_label(lbl);
        gtk_widget_add_css_class(title_btn, "tab-title-btn");
        gtk_widget_set_hexpand(title_btn, TRUE);

        // Usar índice capturado
        using TabPair = std::pair<BrowserWindow*,int>;
        static auto tab_cb      = +[](GtkButton*, gpointer d){ auto* p = static_cast<TabPair*>(d); p->first->switch_tab(p->second); };
        static auto tab_close_cb= +[](GtkButton*, gpointer d){ auto* p = static_cast<TabPair*>(d); p->first->on_close_tab(p->second); };
        static GClosureNotify tab_destroy = [](gpointer p, GClosure*){ delete static_cast<TabPair*>(p); };

        g_signal_connect_data(title_btn, "clicked",
            G_CALLBACK(tab_cb),
            new TabPair(this, idx),
            tab_destroy,
            G_CONNECT_DEFAULT);

        GtkWidget* close_btn = gtk_button_new_with_label("x");
        gtk_widget_add_css_class(close_btn, "close-tab-btn");
        g_signal_connect_data(close_btn, "clicked",
            G_CALLBACK(tab_close_cb),
            new TabPair(this, idx),
            tab_destroy,
            G_CONNECT_DEFAULT);

        gtk_box_append(GTK_BOX(tab_box), title_btn);
        gtk_box_append(GTK_BOX(tab_box), close_btn);

        // Guardar referencias en TabData
        tabs[idx].tab_widget = tab_box;
        tabs[idx].title_btn  = GTK_BUTTON(title_btn);
        gtk_box_append(GTK_BOX(tabbar_box), tab_box);
    }

    // ── Abrir pestaña ────────────────────────────────────────────────────────

    void open_tab(const std::string& uri = "", const std::string& mode = "normal") {
        WebKitWebView* wview = make_webview(mode);
        TabData new_td;
        new_td.webview    = wview;
        new_td.mode       = mode;
        new_td.tab_widget = nullptr;
        new_td.title_btn  = nullptr;
        tabs.push_back(new_td);
        int idx = (int)tabs.size() - 1;

        char name[32];
        snprintf(name, sizeof(name), "tab%d", idx);
        gtk_stack_add_named(GTK_STACK(tab_stack), GTK_WIDGET(wview), name);

        make_tab_widget(idx);
        setup_download_handler(wview);
        switch_tab(idx);
        webkit_web_view_load_uri(wview, uri.empty() ? app->home_uri.c_str() : uri.c_str());
    }

    // ── Cerrar pestaña ───────────────────────────────────────────────────────

    void on_close_tab(int idx) {
        if ((int)tabs.size() == 1) {
            webkit_web_view_load_uri(tabs[0].webview, app->home_uri.c_str());
            return;
        }
        clear_tab_data(tabs[idx]);
        char name[32];
        snprintf(name, sizeof(name), "tab%d", idx);
        gtk_stack_remove(GTK_STACK(tab_stack), GTK_WIDGET(tabs[idx].webview));
        tabs.erase(tabs.begin() + idx);
        rebuild_tabbar();
        int new_idx = std::min(idx, (int)tabs.size() - 1);
        switch_tab(new_idx);
    }

    void clear_tab_data(TabData& t) {
        WebKitNetworkSession* ns = webkit_web_view_get_network_session(t.webview);
        if (!ns) return;
        WebKitWebsiteDataManager* wdm = webkit_network_session_get_website_data_manager(ns);
        if (!wdm) return;
        webkit_website_data_manager_clear(wdm,
            (WebKitWebsiteDataTypes)(
                WEBKIT_WEBSITE_DATA_COOKIES |
                WEBKIT_WEBSITE_DATA_DISK_CACHE |
                WEBKIT_WEBSITE_DATA_MEMORY_CACHE |
                WEBKIT_WEBSITE_DATA_SESSION_STORAGE |
                WEBKIT_WEBSITE_DATA_LOCAL_STORAGE |
                WEBKIT_WEBSITE_DATA_INDEXEDDB_DATABASES |
                WEBKIT_WEBSITE_DATA_OFFLINE_APPLICATION_CACHE
            ),
            0, nullptr, nullptr, nullptr
        );
    }

    void rebuild_tabbar() {
        // Quitar todos los hijos del tabbar_box
        GtkWidget* child = gtk_widget_get_first_child(tabbar_box);
        while (child) {
            GtkWidget* nxt = gtk_widget_get_next_sibling(child);
            gtk_box_remove(GTK_BOX(tabbar_box), child);
            child = nxt;
        }
        for (int i = 0; i < (int)tabs.size(); i++) {
            make_tab_widget(i);
            // Restaurar título
            const char* title = webkit_web_view_get_title(tabs[i].webview);
            if (title && *title && tabs[i].title_btn) {
                std::string t = title;
                if (t.size() > 14) t = t.substr(0,14) + "...";
                gtk_button_set_label(tabs[i].title_btn, t.c_str());
            }
        }
    }

    void switch_tab(int idx) {
        if (idx < 0 || idx >= (int)tabs.size()) return;

        // Actualizar estilos
        GtkWidget* child = gtk_widget_get_first_child(tabbar_box);
        int i = 0;
        while (child) {
            gtk_widget_remove_css_class(child, "tab-active");
            if (i == idx) gtk_widget_add_css_class(child, "tab-active");
            child = gtk_widget_get_next_sibling(child);
            i++;
        }

        current_tab = idx;
        char name[32];
        snprintf(name, sizeof(name), "tab%d", idx);
        gtk_stack_set_visible_child_name(GTK_STACK(tab_stack), name);

        const char* uri = webkit_web_view_get_uri(tabs[idx].webview);
        if (uri && strcmp(uri, "about:blank") != 0)
            gtk_editable_set_text(GTK_EDITABLE(url_entry), uri);
        else
            gtk_editable_set_text(GTK_EDITABLE(url_entry), "");

        update_badge(tabs[idx].mode);
        update_nav_buttons();
        update_bookmark_star();
        update_security_badge(uri ? uri : "");
    }

    // ── Crear WebView ────────────────────────────────────────────────────────

    WebKitWebView* make_webview(const std::string& mode) {
        WebKitWebView* wview = nullptr;

        if (mode == "tor") {
            WebKitNetworkSession* ns = webkit_network_session_new_ephemeral();
            WebKitNetworkProxySettings* ps = webkit_network_proxy_settings_new("socks5://127.0.0.1:9050", nullptr);
            webkit_network_session_set_proxy_settings(ns, WEBKIT_NETWORK_PROXY_MODE_CUSTOM, ps);
            webkit_network_proxy_settings_free(ps);
            wview = WEBKIT_WEB_VIEW(g_object_new(WEBKIT_TYPE_WEB_VIEW, "network-session", ns, nullptr));
            g_object_unref(ns);
        } else if (mode == "i2p") {
            WebKitNetworkSession* ns = webkit_network_session_new_ephemeral();
            WebKitNetworkProxySettings* ps = webkit_network_proxy_settings_new("http://127.0.0.1:4444", nullptr);
            webkit_network_session_set_proxy_settings(ns, WEBKIT_NETWORK_PROXY_MODE_CUSTOM, ps);
            webkit_network_proxy_settings_free(ps);
            wview = WEBKIT_WEB_VIEW(g_object_new(WEBKIT_TYPE_WEB_VIEW, "network-session", ns, nullptr));
            g_object_unref(ns);
        } else {
            wview = WEBKIT_WEB_VIEW(webkit_web_view_new());
        }

        WebKitSettings* s = webkit_settings_new();
        webkit_settings_set_enable_developer_extras(s, FALSE);
        webkit_settings_set_javascript_can_access_clipboard(s, FALSE);
        webkit_settings_set_enable_webrtc(s, FALSE);
        webkit_settings_set_enable_mediasource(s, FALSE);
        webkit_settings_set_enable_encrypted_media(s, FALSE);
        webkit_settings_set_enable_back_forward_navigation_gestures(s, FALSE);
        webkit_settings_set_media_playback_requires_user_gesture(s, TRUE);
        webkit_settings_set_javascript_can_open_windows_automatically(s, FALSE);
        webkit_settings_set_allow_modal_dialogs(s, FALSE);
        webkit_settings_set_enable_page_cache(s, FALSE);
        webkit_settings_set_user_agent(s,
            "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0");
        webkit_web_view_set_settings(wview, s);
        g_object_unref(s);

        gtk_widget_set_vexpand(GTK_WIDGET(wview), TRUE);
        gtk_widget_set_hexpand(GTK_WIDGET(wview), TRUE);

        g_signal_connect(wview, "notify::uri",   G_CALLBACK(+[](WebKitWebView* wv, GParamSpec*, gpointer d){
            static_cast<BrowserWindow*>(d)->on_uri_changed(wv);
        }), this);
        g_signal_connect(wview, "notify::title", G_CALLBACK(+[](WebKitWebView* wv, GParamSpec*, gpointer d){
            static_cast<BrowserWindow*>(d)->on_title_changed(wv);
        }), this);
        g_signal_connect(wview, "load-changed", G_CALLBACK(+[](WebKitWebView* wv, WebKitLoadEvent ev, gpointer d){
            static_cast<BrowserWindow*>(d)->on_load_changed(wv, ev);
        }), this);
        g_signal_connect(wview, "notify::estimated-load-progress", G_CALLBACK(+[](WebKitWebView* wv, GParamSpec*, gpointer d){
            static_cast<BrowserWindow*>(d)->on_progress(wv);
        }), this);

        // Inyectar script anti-fingerprinting
        WebKitUserContentManager* ucm = webkit_web_view_get_user_content_manager(wview);
        WebKitUserScript* fp_script = webkit_user_script_new(
            FP_PROTECTION_JS,
            WEBKIT_USER_CONTENT_INJECT_TOP_FRAME,
            WEBKIT_USER_SCRIPT_INJECT_AT_DOCUMENT_START,
            nullptr, nullptr
        );
        webkit_user_content_manager_add_script(ucm, fp_script);
        webkit_user_script_unref(fp_script);

        return wview;
    }

    // ── Señales del WebView ──────────────────────────────────────────────────

    void on_uri_changed(WebKitWebView* wview) {
        if (tabs.empty()) return;
        const char* uri = webkit_web_view_get_uri(wview);
        if (!uri || strcmp(uri, "about:blank") == 0) return;
        if (wview == wv()) {
            gtk_editable_set_text(GTK_EDITABLE(url_entry), uri);
            update_bookmark_star();
            update_nav_buttons();
            update_security_badge(uri);
        }
        const char* title = webkit_web_view_get_title(wview);
        app->add_history(uri, title ? title : uri);
    }

    void on_title_changed(WebKitWebView* wview) {
        if (tabs.empty()) return;
        const char* title = webkit_web_view_get_title(wview);
        if (!title) title = "";
        // Actualizar pestaña
        for (int i = 0; i < (int)tabs.size(); i++) {
            if (tabs[i].webview == wview && tabs[i].title_btn) {
                std::string t = title;
                if (t.empty()) { char buf[16]; snprintf(buf,sizeof(buf),"Tab %d",i+1); t = buf; }
                if (t.size() > 14) t = t.substr(0,14) + "...";
                gtk_button_set_label(tabs[i].title_btn, t.c_str());
                break;
            }
        }
        if (wview == wv()) {
            std::string wtitle = *title ? std::string("PrekT-BR — ") + title : "PrekT-BR";
            gtk_window_set_title(GTK_WINDOW(window), wtitle.c_str());
        }
    }

    void on_load_changed(WebKitWebView* wview, WebKitLoadEvent event) {
        if (event == WEBKIT_LOAD_STARTED) {
            gtk_button_set_label(GTK_BUTTON(reload_btn), "✕");
            gtk_widget_set_tooltip_text(reload_btn, "Detener carga");
        } else if (event == WEBKIT_LOAD_FINISHED) {
            gtk_button_set_label(GTK_BUTTON(reload_btn), "↻");
            gtk_widget_set_tooltip_text(reload_btn, "Recargar (Ctrl+R)");
            gtk_label_set_text(GTK_LABEL(statusbar), "");
            if (app->dark_mode && wview == wv()) {
                g_timeout_add(400, [](gpointer d) -> gboolean {
                    static_cast<BrowserWindow*>(d)->apply_dark_css();
                    return G_SOURCE_REMOVE;
                }, this);
            }
        }
    }

    void on_progress(WebKitWebView* wview) {
        if (wview != wv()) return;
        double p = webkit_web_view_get_estimated_load_progress(wview);
        if (p > 0 && p < 1) {
            char buf[64];
            snprintf(buf, sizeof(buf), "Cargando… %d%%", (int)(p*100));
            gtk_label_set_text(GTK_LABEL(statusbar), buf);
        } else {
            gtk_label_set_text(GTK_LABEL(statusbar), "");
        }
    }

    // ── Navegación ───────────────────────────────────────────────────────────

    void on_back()    { if (webkit_web_view_can_go_back(wv()))    webkit_web_view_go_back(wv()); }
    void on_forward() { if (webkit_web_view_can_go_forward(wv())) webkit_web_view_go_forward(wv()); }

    void on_url_activate() {
        const char* text_c = gtk_editable_get_text(GTK_EDITABLE(url_entry));
        std::string text = str_trim(text_c ? text_c : "");
        if (text.empty()) return;
        std::string url = resolve_input(text);
        webkit_web_view_load_uri(wv(), url.c_str());
    }

    std::string resolve_input(const std::string& text) {
        std::string lower = str_tolower(text);
        for (auto& scheme : {"javascript:", "data:", "vbscript:", "blob:"}) {
            if (lower.substr(0, strlen(scheme)) == scheme) {
                gtk_label_set_text(GTK_LABEL(statusbar),
                    (std::string("Esquema bloqueado: ") + scheme).c_str());
                return "about:blank";
            }
        }
        if (text.substr(0,7)=="http://" || text.substr(0,8)=="https://" ||
            text.substr(0,6)=="about:" || text.substr(0,7)=="file://") {
            return text;
        }
        if (text.find('.') != std::string::npos && text.find(' ') == std::string::npos) {
            return "https://" + text;
        }
        return "https://duckduckgo.com/?q=" + url_encode(text);
    }

    void update_nav_buttons() {
        if (tabs.empty()) return;
        gtk_widget_set_sensitive(back_btn,    webkit_web_view_can_go_back(wv()));
        gtk_widget_set_sensitive(forward_btn, webkit_web_view_can_go_forward(wv()));
    }

    void on_reload() {
        if (webkit_web_view_is_loading(wv()))
            webkit_web_view_stop_loading(wv());
        else
            webkit_web_view_reload(wv());
    }

    // ── Marcadores ───────────────────────────────────────────────────────────

    void on_toggle_bookmark() {
        const char* uri_c = webkit_web_view_get_uri(wv());
        if (!uri_c || strcmp(uri_c, "about:blank") == 0) return;
        std::string uri = uri_c;
        if (app->is_bookmarked(uri)) {
            app->remove_bookmark(uri);
            gtk_button_set_label(GTK_BUTTON(bookmark_star), "★");
            gtk_label_set_text(GTK_LABEL(statusbar), "Marcador eliminado");
        } else {
            const char* title = webkit_web_view_get_title(wv());
            app->add_bookmark(uri, title ? title : uri);
            gtk_button_set_label(GTK_BUTTON(bookmark_star), "★");
            gtk_label_set_text(GTK_LABEL(statusbar), "Marcador guardado");
        }
        g_timeout_add(2000, [](gpointer d) -> gboolean {
            gtk_label_set_text(GTK_LABEL(static_cast<BrowserWindow*>(d)->statusbar), "");
            return G_SOURCE_REMOVE;
        }, this);
        if (sidebar_mode == "bookmarks") show_sidebar("bookmarks");
    }

    void update_bookmark_star() {
        if (tabs.empty()) return;
        gtk_button_set_label(GTK_BUTTON(bookmark_star), "★");
    }

    // ── Sidebar ──────────────────────────────────────────────────────────────

    void toggle_sidebar(const std::string& mode) {
        if (sidebar_mode == mode) close_sidebar();
        else show_sidebar(mode);
    }

    void close_sidebar() {
        if (sidebar_widget) {
            gtk_box_remove(GTK_BOX(content_area), sidebar_widget);
            sidebar_widget = nullptr;
        }
        sidebar_mode = "";
    }

    void show_sidebar(const std::string& mode) {
        close_sidebar();
        sidebar_mode = mode;

        GtkWidget* outer = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
        gtk_widget_add_css_class(outer, "sidebar");

        GtkWidget* title_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
        gtk_widget_add_css_class(title_box, "sidebar-title");
        GtkWidget* lbl = gtk_label_new(mode == "bookmarks" ? "Marcadores" : "Historial");
        gtk_widget_set_hexpand(lbl, TRUE);
        gtk_label_set_xalign(GTK_LABEL(lbl), 0.0f);
        GtkWidget* close_btn = gtk_button_new_with_label("Cerrar");
        gtk_widget_add_css_class(close_btn, "nav-button");
        g_signal_connect(close_btn, "clicked", G_CALLBACK(+[](GtkButton*, gpointer d){
            static_cast<BrowserWindow*>(d)->close_sidebar();
        }), this);
        gtk_box_append(GTK_BOX(title_box), lbl);
        gtk_box_append(GTK_BOX(title_box), close_btn);

        GtkWidget* scroll = gtk_scrolled_window_new();
        gtk_widget_set_vexpand(scroll, TRUE);
        gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
                                       GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);

        GtkWidget* list_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 1);
        gtk_widget_set_margin_top(list_box, 4);
        gtk_widget_set_margin_bottom(list_box, 4);
        gtk_widget_set_margin_start(list_box, 4);
        gtk_widget_set_margin_end(list_box, 4);

        if (mode == "bookmarks") {
            if (app->bookmarks.empty()) {
                GtkWidget* empty = gtk_label_new("Sin marcadores aún");
                gtk_widget_set_margin_top(empty, 20);
                gtk_widget_add_css_class(empty, "sidebar-item");
                gtk_box_append(GTK_BOX(list_box), empty);
            }
            for (auto& b : app->bookmarks) {
                sidebar_item(list_box, b["title"].get<std::string>(),
                             b["url"].get<std::string>(), true);
            }
        } else {
            int start = std::max(0, (int)app->history.size() - 200);
            std::vector<json> items(app->history.begin() + start, app->history.end());
            std::reverse(items.begin(), items.end());
            if (items.empty()) {
                GtkWidget* empty = gtk_label_new("El historial está vacío");
                gtk_widget_set_margin_top(empty, 20);
                gtk_widget_add_css_class(empty, "sidebar-item");
                gtk_box_append(GTK_BOX(list_box), empty);
            }
            for (auto& h : items) {
                std::string ts = h.value("ts", "").substr(0, 10);
                std::string label = "[" + ts + "] " + h.value("title", h.value("url",""));
                sidebar_item(list_box, label, h["url"].get<std::string>(), false);
            }
        }

        gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), list_box);
        gtk_box_append(GTK_BOX(outer), title_box);
        gtk_box_append(GTK_BOX(outer), scroll);
        gtk_box_prepend(GTK_BOX(content_area), outer);
        sidebar_widget = outer;
    }

    void sidebar_item(GtkWidget* box, const std::string& label,
                      const std::string& url, bool removable) {
        GtkWidget* row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 2);
        GtkWidget* btn = gtk_button_new_with_label(label.c_str());
        gtk_widget_add_css_class(btn, "sidebar-item");
        gtk_widget_set_hexpand(btn, TRUE);

        using StrPair = std::pair<BrowserWindow*,std::string>;
        static auto load_cb    = +[](GtkButton*, gpointer d){ auto* p = static_cast<StrPair*>(d); webkit_web_view_load_uri(p->first->wv(), p->second.c_str()); };
        static auto remove_cb  = +[](GtkButton*, gpointer d){ auto* p = static_cast<StrPair*>(d); p->first->app->remove_bookmark(p->second); p->first->show_sidebar("bookmarks"); };
        static GClosureNotify str_destroy = [](gpointer p, GClosure*){ delete static_cast<StrPair*>(p); };

        g_signal_connect_data(btn, "clicked",
            G_CALLBACK(load_cb),
            new StrPair(this, url),
            str_destroy,
            G_CONNECT_DEFAULT);

        gtk_box_append(GTK_BOX(row), btn);
        if (removable) {
            GtkWidget* del_btn = gtk_button_new_with_label("Quitar");
            gtk_widget_add_css_class(del_btn, "close-tab-btn");
            g_signal_connect_data(del_btn, "clicked",
                G_CALLBACK(remove_cb),
                new StrPair(this, url),
                str_destroy,
                G_CONNECT_DEFAULT);
            gtk_box_append(GTK_BOX(row), del_btn);
        }
        gtk_box_append(GTK_BOX(box), row);
    }

    // ── Badge de modo de red ─────────────────────────────────────────────────

    void update_badge(const std::string& mode) {
        gtk_widget_remove_css_class(badge, "badge-normal");
        gtk_widget_remove_css_class(badge, "badge-tor");
        gtk_widget_remove_css_class(badge, "badge-i2p");
        gtk_widget_remove_css_class(badge, "badge-clear");
        if (mode == "tor") {
            gtk_label_set_text(GTK_LABEL(badge), "TOR");
            gtk_widget_add_css_class(badge, "badge-tor");
            gtk_widget_set_visible(badge, TRUE);
        } else if (mode == "i2p") {
            gtk_label_set_text(GTK_LABEL(badge), "I2P");
            gtk_widget_add_css_class(badge, "badge-i2p");
            gtk_widget_set_visible(badge, TRUE);
        } else {
            gtk_label_set_text(GTK_LABEL(badge), "Clear");
            gtk_widget_add_css_class(badge, "badge-clear");
            gtk_widget_set_visible(badge, TRUE);
        }
    }

    // ── Modo oscuro ──────────────────────────────────────────────────────────

    void apply_dark_css() {
        const char* css =
            ":root { color-scheme: dark !important; }"
            "* { background-color: #111 !important; color: #eee !important;"
            "    border-color: #333 !important; }"
            "a { color: #8ab4f8 !important; }"
            "img { filter: brightness(0.85); }";
        // Escapar backticks
        std::string css_str = css;
        std::string js = "(function(){let el=document.getElementById('prektbr-dark');"
            "if(!el){el=document.createElement('style');el.id='prektbr-dark';"
            "document.head.appendChild(el);}el.textContent=`" + css_str + "`;})();";
        webkit_web_view_evaluate_javascript(wv(), js.c_str(), -1, nullptr, nullptr, nullptr, nullptr, nullptr);
    }

    // ── Atajos de teclado globales ───────────────────────────────────────────

    gboolean on_global_key(guint keyval, guint /*keycode*/, GdkModifierType state) {
        bool ctrl_held  = state & GDK_CONTROL_MASK;
        bool alt_held   = state & GDK_ALT_MASK;
        bool shift_held = state & GDK_SHIFT_MASK;
        // AltGr en GTK4 aparece como SUPER o HYPER según el teclado/entorno
        bool altgr_held = (state & GDK_SUPER_MASK) || (state & GDK_HYPER_MASK);

        if (ctrl_held && !alt_held && !altgr_held) {
            if (keyval == GDK_KEY_t)     { open_tab(); return TRUE; }
            if (keyval == GDK_KEY_w)     { on_close_tab(current_tab); return TRUE; }
            if (keyval == GDK_KEY_l)     {
                gtk_widget_grab_focus(url_entry);
                gtk_editable_select_region(GTK_EDITABLE(url_entry), 0, -1);
                return TRUE;
            }
            if (keyval == GDK_KEY_r && !shift_held) { webkit_web_view_reload(wv()); return TRUE; }
            if (keyval == GDK_KEY_r &&  shift_held) { webkit_web_view_reload_bypass_cache(wv()); return TRUE; }
            if (keyval == GDK_KEY_f)     { toggle_findbar(); return TRUE; }
            if (keyval == GDK_KEY_plus || keyval == GDK_KEY_equal) {
                webkit_web_view_set_zoom_level(wv(),
                    std::min(webkit_web_view_get_zoom_level(wv()) + 0.1, 5.0));
                return TRUE;
            }
            if (keyval == GDK_KEY_minus) {
                webkit_web_view_set_zoom_level(wv(),
                    std::max(webkit_web_view_get_zoom_level(wv()) - 0.1, 0.1));
                return TRUE;
            }
            if (keyval == GDK_KEY_0) { webkit_web_view_set_zoom_level(wv(), 1.0); return TRUE; }
        }

        if (ctrl_held && alt_held && !altgr_held) {
            if (keyval == GDK_KEY_t || keyval == GDK_KEY_Return) {
                on_toggle_terminal(); return TRUE;
            }
        }

        if (ctrl_held && altgr_held) {
            if (keyval == GDK_KEY_d) { toggle_inspector(); return TRUE; }
        }

        if (!ctrl_held && !alt_held) {
            if (keyval == GDK_KEY_Escape) {
                if (findbar_visible)  { close_findbar(); return TRUE; }
                if (inspector_mode)   { close_inspector(); return TRUE; }
            }
        }

        if (alt_held && !ctrl_held) {
            if (keyval == GDK_KEY_Left)  { on_back(); return TRUE; }
            if (keyval == GDK_KEY_Right) { on_forward(); return TRUE; }
        }

        return FALSE;
    }

    // ── Badge de seguridad ───────────────────────────────────────────────────

    void update_security_badge(const std::string& uri) {
        if (uri.empty() || uri.substr(0,6) == "about:") {
            gtk_widget_set_visible(sec_badge, FALSE);
            return;
        }
        std::string scheme, host;
        parse_uri(uri, scheme, host);

        gtk_widget_remove_css_class(sec_badge, "badge-secure");
        gtk_widget_remove_css_class(sec_badge, "badge-insecure");
        gtk_widget_remove_css_class(sec_badge, "badge-onion");
        gtk_widget_remove_css_class(sec_badge, "badge-eepsite");
        gtk_widget_remove_css_class(sec_badge, "badge-file");

        auto ends_with = [](const std::string& s, const std::string& suf) {
            return s.size() >= suf.size() &&
                   s.compare(s.size()-suf.size(), suf.size(), suf) == 0;
        };

        if (scheme == "file") {
            gtk_label_set_text(GTK_LABEL(sec_badge), "F");
            gtk_widget_add_css_class(sec_badge, "badge-file");
            gtk_widget_set_tooltip_text(sec_badge, "Archivo local");
        } else if (ends_with(host, ".onion")) {
            gtk_label_set_text(GTK_LABEL(sec_badge), "O");
            gtk_widget_add_css_class(sec_badge, "badge-onion");
            gtk_widget_set_tooltip_text(sec_badge, "Onion — servicio oculto Tor");
        } else if (ends_with(host, ".i2p") || ends_with(host, ".loki")) {
            gtk_label_set_text(GTK_LABEL(sec_badge), "E");
            gtk_widget_add_css_class(sec_badge, "badge-eepsite");
            gtk_widget_set_tooltip_text(sec_badge, "Eepsite — servicio I2P/Lokinet");
        } else if (scheme == "https") {
            gtk_label_set_text(GTK_LABEL(sec_badge), "S");
            gtk_widget_add_css_class(sec_badge, "badge-secure");
            gtk_widget_set_tooltip_text(sec_badge, "Seguro — conexión HTTPS");
        } else {
            gtk_label_set_text(GTK_LABEL(sec_badge), "I");
            gtk_widget_add_css_class(sec_badge, "badge-insecure");
            gtk_widget_set_tooltip_text(sec_badge, "Inseguro — conexión HTTP sin cifrar");
        }
        gtk_widget_set_visible(sec_badge, TRUE);
    }

    // ── Findbar ──────────────────────────────────────────────────────────────

    void toggle_findbar() {
        if (findbar_visible) close_findbar();
        else {
            gtk_widget_set_visible(findbar_box, TRUE);
            findbar_visible = true;
            gtk_widget_grab_focus(find_entry);
        }
    }

    void close_findbar() {
        gtk_widget_set_visible(findbar_box, FALSE);
        findbar_visible = false;
        webkit_find_controller_search_finish(webkit_web_view_get_find_controller(wv()));
        gtk_label_set_text(GTK_LABEL(find_label), "");
    }

    void find_changed() {
        const char* text = gtk_editable_get_text(GTK_EDITABLE(find_entry));
        WebKitFindController* fc = webkit_web_view_get_find_controller(wv());
        if (text && *text) {
            webkit_find_controller_search(fc, text,
                WEBKIT_FIND_OPTIONS_CASE_INSENSITIVE | WEBKIT_FIND_OPTIONS_WRAP_AROUND, 1000);
        } else {
            webkit_find_controller_search_finish(fc);
            gtk_label_set_text(GTK_LABEL(find_label), "");
        }
    }

    void find_next() {
        const char* text = gtk_editable_get_text(GTK_EDITABLE(find_entry));
        if (text && *text)
            webkit_find_controller_search_next(webkit_web_view_get_find_controller(wv()));
    }

    void find_prev() {
        const char* text = gtk_editable_get_text(GTK_EDITABLE(find_entry));
        if (text && *text)
            webkit_find_controller_search_previous(webkit_web_view_get_find_controller(wv()));
    }

    // ── Inspector de HTML ─────────────────────────────────────────────────────

    void toggle_inspector() {
        if (inspector_mode) close_inspector();
        else open_inspector();
    }

    void open_inspector() {
        if (inspector_mode) return;
        if (terminal_visible) {
            gtk_label_set_text(GTK_LABEL(statusbar), "Cierra la terminal primero (Ctrl+Alt+T)");
            g_timeout_add(2000, [](gpointer d) -> gboolean {
                gtk_label_set_text(GTK_LABEL(static_cast<BrowserWindow*>(d)->statusbar), "");
                return G_SOURCE_REMOVE;
            }, this);
            return;
        }
        inspector_mode = true;
        gtk_box_append(GTK_BOX(content_area), insp_panel);
        inspector_load();
    }

    void close_inspector() {
        if (!inspector_mode) return;
        gtk_box_remove(GTK_BOX(content_area), insp_panel);
        inspector_mode = false;
    }

    void inspector_load() {
        gtk_text_buffer_set_text(inspector_buf, "Cargando HTML…", -1);
        WebKitWebView* wview = wv();

        // Usar script_message_handler — se registra UNA SOLA VEZ y se reutiliza
        WebKitUserContentManager* ucm = webkit_web_view_get_user_content_manager(wview);
        const char* handler_name = "prektbrInspector";

        if (!inspector_handler_registered) {
            webkit_user_content_manager_register_script_message_handler(ucm, handler_name, nullptr);
            inspector_handler_registered = true;
        }

        // Desconectar señal anterior si existe, luego reconectar
        g_signal_handlers_disconnect_by_func(ucm,
            (gpointer)(void(*)(WebKitUserContentManager*, JSCValue*, gpointer))[](
                WebKitUserContentManager*, JSCValue*, gpointer){},
            this);

        using InspCB = void(*)(WebKitUserContentManager*, JSCValue*, gpointer);
        InspCB insp_cb = [](WebKitUserContentManager*, JSCValue* msg, gpointer d) {
            auto* win = static_cast<BrowserWindow*>(d);
            char* html = jsc_value_to_string(msg);
            std::string fmt;
            if (html && *html && strcmp(html,"undefined") != 0 && strcmp(html,"null") != 0)
                fmt = format_html(html);
            else
                fmt = "[HTML vacío]";
            g_free(html);
            using BufPair = std::pair<BrowserWindow*,std::string>;
            auto* pair = new BufPair(win, fmt);
            g_idle_add([](gpointer d2) -> gboolean {
                auto* p = static_cast<BufPair*>(d2);
                gtk_text_buffer_set_text(p->first->inspector_buf, p->second.c_str(), -1);
                delete p;
                return G_SOURCE_REMOVE;
            }, pair);
        };

        // Usar g_signal_connect con una sola conexión activa a la vez
        // Primero desconectamos cualquier handler previo para esta señal
        guint sig_id = g_signal_lookup("script-message-received", WEBKIT_TYPE_USER_CONTENT_MANAGER);
        guint detail  = g_quark_from_string("prektbrInspector");
        g_signal_handlers_disconnect_matched(ucm,
            GSignalMatchType(G_SIGNAL_MATCH_ID | G_SIGNAL_MATCH_DETAIL | G_SIGNAL_MATCH_DATA),
            sig_id, detail, nullptr, nullptr, this);

        g_signal_connect(ucm,
            "script-message-received::prektbrInspector",
            G_CALLBACK(insp_cb),
            this);

        std::string js = std::string("window.webkit.messageHandlers.") + handler_name +
                         ".postMessage(document.documentElement.outerHTML);";
        webkit_web_view_evaluate_javascript(wview, js.c_str(), -1, nullptr, nullptr, nullptr, nullptr, nullptr);
    }

    void inspector_apply() {
        GtkTextIter start, end;
        gtk_text_buffer_get_start_iter(inspector_buf, &start);
        gtk_text_buffer_get_end_iter(inspector_buf, &end);
        gchar* html = gtk_text_buffer_get_text(inspector_buf, &start, &end, FALSE);
        std::string html_str = html ? html : "";
        g_free(html);

        // Escapar backticks y backslashes
        std::string escaped;
        for (char c : html_str) {
            if (c == '\\') escaped += "\\\\";
            else if (c == '`') escaped += "\\`";
            else escaped += c;
        }
        std::string js = "document.open(); document.write(`" + escaped + "`); document.close();";
        webkit_web_view_evaluate_javascript(wv(), js.c_str(), -1, nullptr, nullptr, nullptr, nullptr, nullptr);
    }

    gboolean on_inspector_key(guint keyval, guint, GdkModifierType state) {
        if ((state & GDK_CONTROL_MASK) && keyval == GDK_KEY_Return) {
            inspector_apply(); return TRUE;
        }
        if (keyval == GDK_KEY_Escape) { close_inspector(); return TRUE; }
        return FALSE;
    }

    // ── Descargas ─────────────────────────────────────────────────────────────

    void setup_download_handler(WebKitWebView* wview) {
        WebKitNetworkSession* ns = webkit_web_view_get_network_session(wview);
        if (ns) {
            g_signal_connect(ns, "download-started",
                G_CALLBACK(+[](WebKitNetworkSession*, WebKitDownload* dl, gpointer d){
                    static_cast<BrowserWindow*>(d)->on_download_started(dl);
                }), this);
        }
    }

    void on_download_started(WebKitDownload* dl) {
        g_signal_connect(dl, "decide-destination",
            G_CALLBACK(+[](WebKitDownload* d, gchar* suggested, gpointer ud) -> gboolean {
                static_cast<BrowserWindow*>(ud)->on_decide_destination(d, suggested);
                return TRUE;
            }), this);
        g_signal_connect(dl, "failed",
            G_CALLBACK(+[](WebKitDownload* d, GError* err, gpointer ud){
                static_cast<BrowserWindow*>(ud)->on_download_failed(d, err);
            }), this);
    }

    void on_decide_destination(WebKitDownload* dl, const char* suggested_filename) {
        std::string fname = suggested_filename ? suggested_filename : "";
        if (fname.empty()) {
            WebKitURIRequest* req = webkit_download_get_request(dl);
            if (req) {
                const char* uri = webkit_uri_request_get_uri(req);
                if (uri) {
                    std::string u = uri;
                    size_t p = u.rfind('/');
                    fname = (p != std::string::npos) ? u.substr(p+1) : "descarga";
                }
            }
            if (fname.empty()) fname = "descarga";
        }

        GtkFileDialog* dialog = gtk_file_dialog_new();
        gtk_file_dialog_set_title(dialog, "Guardar archivo");
        gtk_file_dialog_set_initial_name(dialog, fname.c_str());

        auto* ctx = new std::pair<BrowserWindow*,WebKitDownload*>(this, dl);
        g_object_ref(dl);
        gtk_file_dialog_save(dialog, GTK_WINDOW(window), nullptr,
            [](GObject* src, GAsyncResult* res, gpointer d){
                auto* p = static_cast<std::pair<BrowserWindow*,WebKitDownload*>*>(d);
                GError* err = nullptr;
                GFile* gfile = gtk_file_dialog_save_finish(GTK_FILE_DIALOG(src), res, &err);
                if (gfile) {
                    p->first->on_save_dialog_done(gfile, p->second);
                    g_object_unref(gfile);
                } else {
                    webkit_download_cancel(p->second);
                    if (err) g_error_free(err);
                }
                g_object_unref(p->second);
                delete p;
            }, ctx);
        g_object_unref(dialog);
    }

    void on_save_dialog_done(GFile* gfile, WebKitDownload* dl) {
        char* dest_c = g_file_get_path(gfile);
        if (!dest_c) { webkit_download_cancel(dl); return; }
        std::string dest = dest_c;
        g_free(dest_c);
        std::string fname = dest.substr(dest.rfind('/')+1);

        webkit_download_set_destination(dl, dest.c_str());

        gtk_label_set_text(GTK_LABEL(statusbar), ("Descargando: " + fname + "  0%").c_str());
        gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(dl_progress), 0.0);
        gtk_widget_set_visible(dl_progress, TRUE);

        struct DlCtx { BrowserWindow* win; std::string fname; };
        auto* ctx = new DlCtx{this, fname};

        using DlProgressCB = void(*)(WebKitDownload*, GParamSpec*, gpointer);
        using DlFinishedCB = void(*)(WebKitDownload*, gpointer);
        static GClosureNotify noop_destroy = [](gpointer, GClosure*){};

        DlProgressCB dl_progress_cb = [](WebKitDownload* d, GParamSpec*, gpointer ud) {
            auto* c = static_cast<DlCtx*>(ud);
            double p = webkit_download_get_estimated_progress(d);
            char buf[128];
            snprintf(buf, sizeof(buf), "Descargando: %s  %d%%", c->fname.c_str(), (int)(p*100));
            gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(c->win->dl_progress), p);
            gtk_label_set_text(GTK_LABEL(c->win->statusbar), buf);
        };

        DlFinishedCB dl_finished_cb = [](WebKitDownload*, gpointer ud) {
            auto* c = static_cast<DlCtx*>(ud);
            gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(c->win->dl_progress), 1.0);
            gtk_label_set_text(GTK_LABEL(c->win->statusbar),
                ("Descarga completa: " + c->fname).c_str());
            g_timeout_add(3500, [](gpointer wd) -> gboolean {
                auto* w = static_cast<BrowserWindow*>(wd);
                gtk_widget_set_visible(w->dl_progress, FALSE);
                gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(w->dl_progress), 0.0);
                gtk_label_set_text(GTK_LABEL(w->statusbar), "");
                return G_SOURCE_REMOVE;
            }, c->win);
            delete c;
        };

        g_signal_connect_data(dl, "notify::estimated-progress",
            G_CALLBACK(dl_progress_cb), ctx, noop_destroy, G_CONNECT_DEFAULT);

        g_signal_connect_data(dl, "finished",
            G_CALLBACK(dl_finished_cb), ctx, noop_destroy, G_CONNECT_DEFAULT);
    }

    void on_download_failed(WebKitDownload*, GError* err) {
        std::string msg = err ? err->message : "error desconocido";
        g_idle_add([](gpointer d) -> gboolean {
            auto* p = static_cast<std::pair<BrowserWindow*,std::string>*>(d);
            gtk_widget_set_visible(p->first->dl_progress, FALSE);
            gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(p->first->dl_progress), 0.0);
            gtk_label_set_text(GTK_LABEL(p->first->statusbar),
                ("Error de descarga: " + p->second).c_str());
            g_timeout_add(4000, [](gpointer wd) -> gboolean {
                gtk_label_set_text(GTK_LABEL(static_cast<BrowserWindow*>(wd)->statusbar), "");
                return G_SOURCE_REMOVE;
            }, p->first);
            delete p;
            return G_SOURCE_REMOVE;
        }, new std::pair<BrowserWindow*,std::string>(this, msg));
    }

    // ── Terminal: toggle ─────────────────────────────────────────────────────

    void on_toggle_terminal() {
        if (inspector_mode) {
            gtk_label_set_text(GTK_LABEL(statusbar), "Cierra el inspector primero (Esc)");
            g_timeout_add(2000, [](gpointer d) -> gboolean {
                gtk_label_set_text(GTK_LABEL(static_cast<BrowserWindow*>(d)->statusbar), "");
                return G_SOURCE_REMOVE;
            }, this);
            return;
        }
        if (terminal_visible) {
            gtk_box_remove(GTK_BOX(content_area), term_scroll);
            terminal_visible = false;
        } else {
            gtk_box_append(GTK_BOX(content_area), term_scroll);
            terminal_visible = true;
            gtk_widget_grab_focus(terminal_tv);
        }
    }

    // ── Modos de red ─────────────────────────────────────────────────────────

    void enable_network_mode(const std::string& mode) {
        TabData& t = td();
        if (t.mode == mode) {
            term_print("  La pestaña ya está en modo " + mode + ".");
            term_prompt();
            return;
        }
        const char* old_uri_c = webkit_web_view_get_uri(t.webview);
        std::string old_uri = old_uri_c ? old_uri_c : app->home_uri;

        WebKitWebView* new_wv = make_webview(mode);
        int idx = current_tab;
        char name[32];
        snprintf(name, sizeof(name), "tab%d", idx);

        gtk_stack_remove(GTK_STACK(tab_stack), GTK_WIDGET(t.webview));
        t.webview = new_wv;
        t.mode    = mode;
        gtk_stack_add_named(GTK_STACK(tab_stack), GTK_WIDGET(new_wv), name);
        gtk_stack_set_visible_child_name(GTK_STACK(tab_stack), name);
        webkit_web_view_load_uri(new_wv,
            (old_uri == "about:blank") ? app->home_uri.c_str() : old_uri.c_str());
        update_badge(mode);

        if (mode == "tor") {
            term_print("  MODO TOR ACTIVADO — WebRTC deshabilitado");
            term_print("  Usa http:// (sin s) para sitios .onion");
        } else if (mode == "i2p") {
            term_print("  MODO I2P ACTIVADO — Proxy HTTP 127.0.0.1:4444");
            term_print("  Navega a sitios .i2p normalmente");
        }
        term_prompt();
    }

    void disable_network_mode() {
        TabData& t = td();
        if (t.mode == "normal") {
            term_print("  La pestaña ya está en modo normal.");
            term_prompt();
            return;
        }
        const char* old_uri_c = webkit_web_view_get_uri(t.webview);
        std::string old_uri = old_uri_c ? old_uri_c : app->home_uri;

        WebKitWebView* new_wv = make_webview("normal");
        int idx = current_tab;
        char name[32];
        snprintf(name, sizeof(name), "tab%d", idx);

        gtk_stack_remove(GTK_STACK(tab_stack), GTK_WIDGET(t.webview));
        t.webview = new_wv;
        t.mode    = "normal";
        gtk_stack_add_named(GTK_STACK(tab_stack), GTK_WIDGET(new_wv), name);
        gtk_stack_set_visible_child_name(GTK_STACK(tab_stack), name);
        webkit_web_view_load_uri(new_wv,
            (old_uri == "about:blank") ? app->home_uri.c_str() : old_uri.c_str());
        update_badge("normal");
        term_print("  Modo normal restaurado.");
        term_prompt();
    }

    // ── Terminal: entrada/salida ─────────────────────────────────────────────

    void term_print(const std::string& text, bool no_nl = false) {
        GtkTextIter end;
        gtk_text_buffer_get_end_iter(terminal_buf, &end);
        std::string out = no_nl ? text : text + "\n";
        gtk_text_buffer_insert(terminal_buf, &end, out.c_str(), -1);
        gtk_text_view_scroll_to_iter(GTK_TEXT_VIEW(terminal_tv), &end, 0.0, TRUE, 0.0, 1.0);
    }

    void term_prompt() {
        GtkTextIter end;
        gtk_text_buffer_get_end_iter(terminal_buf, &end);
        gtk_text_buffer_insert(terminal_buf, &end, "> ", -1);
        gtk_text_buffer_get_end_iter(terminal_buf, &end);
        prompt_end_mark = gtk_text_buffer_create_mark(terminal_buf, "prompt_end", &end, TRUE);
    }

    gboolean on_terminal_key(guint keyval, guint, GdkModifierType) {
        if (keyval == GDK_KEY_Return || keyval == GDK_KEY_KP_Enter) {
            GtkTextIter s, e;
            gtk_text_buffer_get_start_iter(terminal_buf, &s);
            gtk_text_buffer_get_end_iter(terminal_buf, &e);
            gchar* full_c = gtk_text_buffer_get_text(terminal_buf, &s, &e, FALSE);
            std::string full = full_c ? full_c : "";
            g_free(full_c);
            // Quitar trailing whitespace
            while (!full.empty() && (full.back()=='\n'||full.back()=='\r'||full.back()==' '))
                full.pop_back();
            // Última línea
            size_t nl = full.rfind('\n');
            std::string last = (nl == std::string::npos) ? full : full.substr(nl+1);
            last = str_trim(last);
            if (last.substr(0,2) == "> ") {
                std::string cmd = str_trim(last.substr(2));
                if (!cmd.empty()) {
                    term_print("");
                    run_command(cmd);
                    return TRUE;
                }
            }
            term_print("");
            term_prompt();
            return TRUE;
        }

        // Proteger el prompt
        if (keyval == GDK_KEY_BackSpace || keyval == GDK_KEY_Delete ||
            keyval == GDK_KEY_Left      || keyval == GDK_KEY_Home   ||
            keyval == GDK_KEY_KP_Left   || keyval == GDK_KEY_KP_Home) {
            if (prompt_end_mark) {
                GtkTextMark* insert_mark = gtk_text_buffer_get_insert(terminal_buf);
                GtkTextIter cursor, limit;
                gtk_text_buffer_get_iter_at_mark(terminal_buf, &cursor, insert_mark);
                gtk_text_buffer_get_iter_at_mark(terminal_buf, &limit, prompt_end_mark);
                if (gtk_text_iter_compare(&cursor, &limit) <= 0) return TRUE;
            }
        }
        return FALSE;
    }

    // ── Comandos de terminal ─────────────────────────────────────────────────

    void run_command(const std::string& raw) {
        std::string trimmed = str_trim(raw);
        size_t sp = trimmed.find(' ');
        std::string cmd  = str_tolower(sp == std::string::npos ? trimmed : trimmed.substr(0, sp));
        std::string args = sp == std::string::npos ? "" : str_trim(trimmed.substr(sp+1));

        auto nav = [&](const std::string& url) {
            webkit_web_view_load_uri(wv(), url.c_str());
        };

        if (cmd == "help") {
            term_print(
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
            );
        } else if (cmd == "open" || cmd == "new") {
            if (!args.empty()) nav(resolve_input(args));
            else term_print("Uso: open <url>");
        } else if (cmd == "newtab") {
            open_tab(args.empty() ? "" : resolve_input(args));
        } else if (cmd == "closetab") {
            on_close_tab(current_tab);
        } else if (cmd == "tab") {
            try {
                int n = std::stoi(args) - 1;
                switch_tab(n);
            } catch (...) {
                term_print("Uso: tab <número>");
            }
        } else if (cmd == "back") {
            if (webkit_web_view_can_go_back(wv())) webkit_web_view_go_back(wv());
        } else if (cmd == "forward") {
            if (webkit_web_view_can_go_forward(wv())) webkit_web_view_go_forward(wv());
        } else if (cmd == "reload") {
            webkit_web_view_reload(wv());
        } else if (cmd == "reloadhard") {
            webkit_web_view_reload_bypass_cache(wv());
        } else if (cmd == "home") {
            nav(app->home_uri);
        } else if (cmd == "zoom") {
            if (!args.empty()) {
                try {
                    double level = std::stod(args);
                    if (level >= 0.1 && level <= 5.0) {
                        webkit_web_view_set_zoom_level(wv(), level);
                        char buf[64];
                        snprintf(buf, sizeof(buf), "Zoom: %.1fx", level);
                        term_print(buf);
                    } else {
                        term_print("Zoom válido: 0.1 – 5.0 (1.0 = normal)");
                    }
                } catch (...) {
                    term_print("Uso: zoom <número>  (ej: zoom 1.5)");
                }
            } else {
                char buf[64];
                snprintf(buf, sizeof(buf), "Zoom actual: %.1fx  — uso: zoom <número>",
                         webkit_web_view_get_zoom_level(wv()));
                term_print(buf);
            }
        } else if (cmd == "ddg") {
            nav(args.empty() ? "https://duckduckgo.com" :
                "https://duckduckgo.com/?q=" + url_encode(args));
        } else if (cmd == "google") {
            nav(args.empty() ? "https://www.google.com" :
                "https://www.google.com/search?q=" + url_encode(args));
        } else if (cmd == "yt") {
            nav(args.empty() ? "https://www.youtube.com" :
                "https://www.youtube.com/results?search_query=" + url_encode(args));
        } else if (cmd == "wiki") {
            nav(args.empty() ? "https://es.wikipedia.org" :
                "https://es.wikipedia.org/wiki/" + url_encode(args));
        } else if (cmd == "loki") {
            if (!args.empty()) {
                std::string addr = str_trim(args);
                // Quitar http/https
                if (addr.substr(0,7)  == "http://")  addr = addr.substr(7);
                if (addr.substr(0,8)  == "https://") addr = addr.substr(8);
                // Agregar .loki si no lo tiene
                if (addr.size() < 5 || addr.substr(addr.size()-5) != ".loki")
                    addr += ".loki";
                nav("http://" + addr);
            } else {
                term_print("Uso: loki <direccion>  (ejemplo: loki stats.i2p.rocks)");
            }
        } else if (cmd == "tormode") {
            enable_network_mode("tor"); return;
        } else if (cmd == "i2pmode") {
            enable_network_mode("i2p"); return;
        } else if (cmd == "clearnet") {
            disable_network_mode(); return;
        } else if (cmd == "whoami") {
            term_print("Consultando IP pública...");
            // Async en hilo separado
            BrowserWindow* self = this;
            std::thread([self](){
                // Usar curl si está disponible, de lo contrario conectar TCP
                FILE* f = popen("curl -s --max-time 7 https://api.ipify.org 2>/dev/null", "r");
                std::string ip;
                if (f) {
                    char buf[256] = {};
                    if (fgets(buf, sizeof(buf), f)) ip = str_trim(buf);
                    pclose(f);
                }
                auto* result = new std::pair<BrowserWindow*,std::string>(self,
                    ip.empty() ? "Error: no se pudo obtener IP" : "IP pública: " + ip);
                g_idle_add([](gpointer d) -> gboolean {
                    auto* p = static_cast<std::pair<BrowserWindow*,std::string>*>(d);
                    p->first->term_print(p->second);
                    p->first->term_print("");
                    p->first->term_prompt();
                    delete p;
                    return G_SOURCE_REMOVE;
                }, result);
            }).detach();
            return;
        } else if (cmd == "serverip") {
            if (td().mode == "tor" || td().mode == "i2p") {
                term_print("serverip no disponible en modo " + str_tolower(td().mode) + ".");
            } else {
                const char* uri_c = webkit_web_view_get_uri(wv());
                if (!uri_c || strncmp(uri_c,"file://",7)==0) {
                    term_print("Sin página cargada.");
                } else {
                    std::string scheme, host;
                    parse_uri(uri_c, scheme, host);
                    BrowserWindow* self = this;
                    std::thread([self, host](){
                        struct hostent* he = gethostbyname(host.c_str());
                        std::string result;
                        if (he && he->h_addr_list[0]) {
                            char buf[INET6_ADDRSTRLEN];
                            inet_ntop(he->h_addrtype, he->h_addr_list[0], buf, sizeof(buf));
                            result = host + " → " + buf;
                        } else {
                            result = "Error: no se pudo resolver " + host;
                        }
                        auto* p = new std::pair<BrowserWindow*,std::string>(self, result);
                        g_idle_add([](gpointer d) -> gboolean {
                            auto* pp = static_cast<std::pair<BrowserWindow*,std::string>*>(d);
                            pp->first->term_print(pp->second);
                            pp->first->term_print("");
                            pp->first->term_prompt();
                            delete pp;
                            return G_SOURCE_REMOVE;
                        }, p);
                    }).detach();
                    return;
                }
            }
        } else if (cmd == "bookmark") {
            const char* uri_c = webkit_web_view_get_uri(wv());
            if (!uri_c || strcmp(uri_c,"about:blank")==0) {
                term_print("Sin página activa.");
            } else {
                std::string uri = uri_c;
                const char* title_c = webkit_web_view_get_title(wv());
                if (app->is_bookmarked(uri)) {
                    app->remove_bookmark(uri);
                    term_print("Marcador eliminado: " + uri);
                } else {
                    app->add_bookmark(uri, title_c ? title_c : uri);
                    term_print("Marcador guardado: " + std::string(title_c ? title_c : uri));
                }
                gtk_button_set_label(GTK_BUTTON(bookmark_star), "★");
            }
        } else if (cmd == "bookmarks") {
            if (app->bookmarks.empty()) {
                term_print("Sin marcadores guardados.");
            } else {
                term_print("Marcadores guardados:");
                int i = 1;
                for (auto& b : app->bookmarks) {
                    char buf[32];
                    snprintf(buf, sizeof(buf), "  %3d.", i++);
                    term_print(std::string(buf) + " " + b.value("title","") +
                               "\n       " + b.value("url",""));
                }
            }
        } else if (cmd == "history") {
            int n = 10;
            if (!args.empty()) {
                try { n = std::stoi(args); } catch (...) { n = 10; }
            }
            if (app->history.empty()) {
                term_print("El historial está vacío.");
            } else {
                char buf[64];
                snprintf(buf, sizeof(buf), "Últimas %d páginas:", n);
                term_print(buf);
                int start = std::max(0, (int)app->history.size() - n);
                std::vector<json> slice(app->history.begin() + start, app->history.end());
                std::reverse(slice.begin(), slice.end());
                int i = 1;
                for (auto& h : slice) {
                    std::string ts = h.value("ts","");
                    if (ts.size() > 19) ts = ts.substr(0,19);
                    // Reemplazar T por espacio
                    for (char& c : ts) if (c=='T') c=' ';
                    char lb[32];
                    snprintf(lb, sizeof(lb), "  %3d.", i++);
                    term_print(std::string(lb) + " [" + ts + "] " + h.value("title",h.value("url","")) +
                               "\n       " + h.value("url",""));
                }
            }
        } else if (cmd == "dark") {
            app->dark_mode = !app->dark_mode;
            term_print(std::string("Modo oscuro ") + (app->dark_mode ? "activado." : "desactivado."));
            if (app->dark_mode) {
                g_idle_add([](gpointer d) -> gboolean {
                    static_cast<BrowserWindow*>(d)->apply_dark_css();
                    return G_SOURCE_REMOVE;
                }, this);
            }
        } else if (cmd == "calc") {
            if (!args.empty()) {
                term_print(args + " = " + safe_eval(args));
            } else {
                term_print("Uso: calc <expresión>");
            }
        } else if (cmd == "time") {
            auto now = std::chrono::system_clock::now();
            std::time_t t = std::chrono::system_clock::to_time_t(now);
            char buf[16];
            strftime(buf, sizeof(buf), "%H:%M:%S", localtime(&t));
            term_print(buf);
        } else if (cmd == "date") {
            auto now = std::chrono::system_clock::now();
            std::time_t t = std::chrono::system_clock::to_time_t(now);
            char buf[16];
            strftime(buf, sizeof(buf), "%Y-%m-%d", localtime(&t));
            term_print(buf);
        } else if (cmd == "echo") {
            if (!args.empty()) term_print(args);
        } else if (cmd == "clear" || cmd == "clean") {
            gtk_text_buffer_set_text(terminal_buf, "", -1);
        } else if (cmd == "about") {
            term_print(
                "PrekT-BR v2.1 — Hardened Edition\n"
                "WebKitGTK 6 + GTK 4 + C++17\n"
                "Redes: Tor (SOCKS5 :9050), I2P (HTTP :4444)\n"
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
                "  [*] calc: evaluador AST seguro\n"
                "  [*] DevTools: deshabilitadas\n"
                "  [*] Historial/marcadores: cifrados en disco\n"
                "Comandos: clearcookies | clearall\n"
            );
        } else if (cmd == "clearcookies") {
            clear_tab_data(td());
            term_print("Cookies y datos de sesión de la pestaña actual eliminados.");
        } else if (cmd == "clearall") {
            for (auto& t : tabs) clear_tab_data(t);
            term_print("Datos de todas las pestañas eliminados.");
        } else if (cmd == "quit" || cmd == "exit") {
            g_application_quit(G_APPLICATION(app->app));
            return;
        } else {
            term_print("Comando desconocido: '" + cmd + "'  —  escribe 'help'");
        }

        term_print("");
        term_prompt();
    }
};

// ─── Punto de entrada GTK ─────────────────────────────────────────────────────

static PrekTBR* g_prektbr = nullptr;

static void on_activate(GtkApplication* gapp, gpointer) {
    GtkWindow* existing = gtk_application_get_active_window(gapp);
    if (existing) { gtk_window_present(existing); return; }

    auto* bwin = new BrowserWindow();
    bwin->app  = g_prektbr;

    bwin->window = GTK_APPLICATION_WINDOW(
        gtk_application_window_new(gapp));
    gtk_window_set_title(GTK_WINDOW(bwin->window), "PrekT-BR");
    gtk_window_set_default_size(GTK_WINDOW(bwin->window), 1280, 800);

    bwin->build_ui();
    bwin->open_tab(g_prektbr->initial_url);
    gtk_window_present(GTK_WINDOW(bwin->window));
}

static void on_open(GtkApplication* gapp, GFile** files, gint n_files,
                    const gchar*, gpointer) {
    on_activate(gapp, nullptr);
    GtkWindow* win = gtk_application_get_active_window(gapp);
    if (win && n_files > 0) {
        // Obtener BrowserWindow* desde la ventana — buscamos en ventanas registradas
        // (simplificación: abrir en la última ventana activa vía señal activate)
        char* uri = g_file_get_uri(files[0]);
        if (uri) {
            // Buscar BrowserWindow activa — usamos user-data
            gpointer ud = g_object_get_data(G_OBJECT(win), "browser-window");
            if (ud) static_cast<BrowserWindow*>(ud)->open_tab(uri);
            g_free(uri);
        }
    }
}

int main(int argc, char* argv[]) {
    // Configurar variables de entorno
    setenv("GDK_DEBUG", "portals", 0);
    setenv("GTK_A11Y", "none", 0);

    // Inicializar rutas y clave
    init_data_paths();
    g_key = derive_key();

    g_prektbr = new PrekTBR();

    GtkApplication* gapp = gtk_application_new(
        "com.cinnamolhyia.prektbr",
        G_APPLICATION_HANDLES_OPEN
    );
    g_prektbr->app = gapp;

    g_signal_connect(gapp, "activate", G_CALLBACK(on_activate), nullptr);
    g_signal_connect(gapp, "open",     G_CALLBACK(on_open),     nullptr);

    // CSS global
    GtkCssProvider* provider = gtk_css_provider_new();
    gtk_css_provider_load_from_string(provider, GLOBAL_CSS);
    // Se aplica en activate (después de crear el display)
    g_signal_connect(gapp, "startup", G_CALLBACK(+[](GtkApplication*, gpointer p){
        GdkDisplay* disp = gdk_display_get_default();
        if (disp) {
            gtk_style_context_add_provider_for_display(disp,
                GTK_STYLE_PROVIDER(static_cast<GtkCssProvider*>(p)),
                GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
        }
    }), provider);

    // SIGINT → quit
    signal(SIGINT, [](int){ if (g_prektbr && g_prektbr->app) g_application_quit(G_APPLICATION(g_prektbr->app)); });

    int status = g_application_run(G_APPLICATION(gapp), argc, argv);

    g_object_unref(gapp);
    delete g_prektbr;
    return status;
}
