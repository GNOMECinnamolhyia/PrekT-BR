/*
 * PrekT-BR — Navegador casero en C con GTK4 + WebKitGTK 6
 *
 * Compilar:
 *   gcc $(pkg-config --cflags --libs gtk4 webkitgtk-6.0) -lm -o prektbr main.c
 *
 * Dependencias (Debian/Ubuntu):
 *   sudo apt install libgtk-4-dev libwebkitgtk-6.0-dev
 */

#include <gtk/gtk.h>
#include <webkit/webkit.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ctype.h>
#include <pthread.h>
#include <unistd.h>

/* ─── Constantes ─────────────────────────────────────────────── */
#define NUM_TABS      3
#define MAX_HISTORY   512
#define MAX_URI       2048
#define APP_ID        "com.cinnamolhyia.prektbr"
#define APP_VERSION   "1.0.1 (C port)"

/* ─── Estructuras ────────────────────────────────────────────── */

typedef struct {
    WebKitWebView *webview;
    gboolean       tor_active;
} TabInfo;

typedef struct _BrowserApp  BrowserApp;
typedef struct _BrowserWin  BrowserWin;

struct _BrowserApp {
    GtkApplication parent;
    char  home_uri[MAX_URI];
    char  initial_url[MAX_URI];
    gboolean dark_mode;
    char  url_history[MAX_HISTORY][MAX_URI];
    int   history_count;
};

struct _BrowserWin {
    GtkApplicationWindow parent;

    BrowserApp *app;

    /* Pestañas */
    TabInfo    tabs[NUM_TABS];
    int        current_tab;

    /* Widgets */
    GtkStack      *tab_stack;
    GtkButton     *tab_buttons[NUM_TABS];
    GtkEntry      *url_entry;
    GtkTextBuffer *terminal_buffer;
    GtkTextView   *terminal_view;
    GtkWidget     *scroll_terminal;
    GtkBox        *content_box;
    gboolean       terminal_visible;
};

/* ─── Declaraciones forward ──────────────────────────────────── */
static void     browser_win_init           (BrowserWin *win, BrowserApp *app);
static WebKitWebView *create_webview       (BrowserWin *win, gboolean tor);
static void     swap_webview_in_tab        (BrowserWin *win, int idx, WebKitWebView *new_wv, const char *load_uri);
static WebKitWebView *active_wv            (BrowserWin *win);
static void     print_to_terminal          (BrowserWin *win, const char *text, gboolean no_newline);
static void     print_prompt               (BrowserWin *win);
static void     clear_terminal             (BrowserWin *win);
static void     process_command            (BrowserWin *win, const char *cmd);
static void     enable_tor_mode            (BrowserWin *win);
static void     disable_tor_mode           (BrowserWin *win);
static void     apply_dark_css             (BrowserWin *win);
static void     history_push               (BrowserApp *app, const char *uri);
static void     load_uri_smart             (BrowserWin *win, const char *raw);
static gboolean on_terminal_key_pressed    (GtkEventControllerKey *ctrl, guint keyval,
                                            guint keycode, GdkModifierType state, gpointer user_data);
static void     on_uri_changed             (WebKitWebView *wv, GParamSpec *pspec, gpointer user_data);
static void     on_title_changed           (WebKitWebView *wv, GParamSpec *pspec, gpointer user_data);
static void     on_load_changed            (WebKitWebView *wv, WebKitLoadEvent evt, gpointer user_data);
static void     on_tab_clicked             (GtkButton *btn, gpointer user_data);
static void     on_go_clicked              (GtkButton *btn, gpointer user_data);
static void     on_home_clicked            (GtkButton *btn, gpointer user_data);
static void     on_back_clicked            (GtkButton *btn, gpointer user_data);
static void     on_forward_clicked         (GtkButton *btn, gpointer user_data);
static void     on_reload_clicked          (GtkButton *btn, gpointer user_data);
static void     on_toggle_terminal         (GtkButton *btn, gpointer user_data);
static void     on_url_activate            (GtkEntry *entry, gpointer user_data);
static void     app_activate               (GApplication *app, gpointer user_data);

/* ─── Helpers ────────────────────────────────────────────────── */

static WebKitWebView *active_wv(BrowserWin *win) {
    return win->tabs[win->current_tab].webview;
}

static void history_push(BrowserApp *app, const char *uri) {
    if (!uri || strcmp(uri, "about:blank") == 0) return;
    if (app->history_count > 0 &&
        strcmp(app->url_history[app->history_count - 1], uri) == 0) return;
    if (app->history_count < MAX_HISTORY) {
        strncpy(app->url_history[app->history_count], uri, MAX_URI - 1);
        app->history_count++;
    } else {
        /* Shift left cuando el buffer está lleno */
        memmove(app->url_history[0], app->url_history[1],
                (MAX_HISTORY - 1) * MAX_URI);
        strncpy(app->url_history[MAX_HISTORY - 1], uri, MAX_URI - 1);
    }
}

static void load_uri_smart(BrowserWin *win, const char *raw) {
    if (!raw || raw[0] == '\0') return;
    char url[MAX_URI];
    if (strncmp(raw, "http://",  7) == 0 ||
        strncmp(raw, "https://", 8) == 0 ||
        strncmp(raw, "file://",  7) == 0 ||
        strncmp(raw, "about:",   6) == 0) {
        strncpy(url, raw, MAX_URI - 1);
    } else {
        snprintf(url, MAX_URI, "https://%s", raw);
    }
    webkit_web_view_load_uri(active_wv(win), url);
}

/* ─── Terminal ───────────────────────────────────────────────── */

static void print_to_terminal(BrowserWin *win, const char *text, gboolean no_newline) {
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(win->terminal_buffer, &end);
    if (no_newline) {
        gtk_text_buffer_insert(win->terminal_buffer, &end, text, -1);
    } else {
        char *line = g_strdup_printf("%s\n", text);
        gtk_text_buffer_insert(win->terminal_buffer, &end, line, -1);
        g_free(line);
    }
    gtk_text_view_scroll_to_iter(win->terminal_view, &end, 0.0, TRUE, 0.0, 1.0);
}

static void print_prompt(BrowserWin *win) {
    print_to_terminal(win, "> ", TRUE);
}

static void clear_terminal(BrowserWin *win) {
    gtk_text_buffer_set_text(win->terminal_buffer, "", -1);
    print_prompt(win);
}

/* ─── safe_eval (solo operaciones aritméticas básicas) ──────── */

static double safe_eval_expr(const char *expr, int *error) {
    /* Evaluamos con popen("python3 -c") pero sin ejecutar nada peligroso.
     * Para mayor seguridad solo permitimos: dígitos, +, -, *, /, (, ), ., espacio */
    *error = 0;
    for (const char *p = expr; *p; p++) {
        if (!strchr("0123456789+-*/().% ", *p)) {
            *error = 1;
            return 0;
        }
    }
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "echo '%s' | bc -l 2>/dev/null", expr);
    FILE *f = popen(cmd, "r");
    if (!f) { *error = 1; return 0; }
    double result = 0;
    if (fscanf(f, "%lf", &result) != 1) *error = 1;
    pclose(f);
    return result;
}

/* ─── Comandos async (whoami, serverip) ─────────────────────── */

typedef struct { BrowserWin *win; } AsyncCtx;

static gboolean whoami_done(gpointer data) {
    char **parts = (char **)data;
    BrowserWin *win = (BrowserWin *)(void *)parts[0];
    print_to_terminal(win, parts[1] ? parts[1] : "No se pudo obtener la IP.", FALSE);
    print_to_terminal(win, "", FALSE);
    print_prompt(win);
    g_free(parts[1]);
    g_free(parts);
    return G_SOURCE_REMOVE;
}

static void *whoami_thread(void *arg) {
    BrowserWin *win = (BrowserWin *)arg;
    char **parts = g_new0(char *, 2);
    parts[0] = (char *)(void *)win;

    FILE *f = popen("curl -s --max-time 5 https://api.ipify.org", "r");
    if (f) {
        char buf[64] = {0};
        if (fgets(buf, sizeof(buf), f)) {
            /* Quitar newline */
            buf[strcspn(buf, "\r\n")] = '\0';
            parts[1] = g_strdup_printf("Tu IP pública: %s", buf);
        }
        pclose(f);
    }
    g_idle_add(whoami_done, parts);
    return NULL;
}

typedef struct {
    BrowserWin *win;
    char        lines[NUM_TABS][MAX_URI];
} ServerIpCtx;

static gboolean serverip_done(gpointer data) {
    ServerIpCtx *ctx = (ServerIpCtx *)data;
    for (int i = 0; i < NUM_TABS; i++)
        print_to_terminal(ctx->win, ctx->lines[i], FALSE);
    print_to_terminal(ctx->win, "", FALSE);
    print_prompt(ctx->win);
    g_free(ctx);
    return G_SOURCE_REMOVE;
}

static void *serverip_thread(void *arg) {
    ServerIpCtx *ctx = (ServerIpCtx *)arg;
    for (int i = 0; i < NUM_TABS; i++) {
        const char *uri = webkit_web_view_get_uri(ctx->win->tabs[i].webview);
        if (!uri || strncmp(uri, "file://", 7) == 0 || strcmp(uri, "about:blank") == 0) {
            snprintf(ctx->lines[i], MAX_URI, "  Tab %d: sin página cargada", i + 1);
            continue;
        }
        /* Extraer hostname */
        char host[256] = {0};
        const char *start = strstr(uri, "://");
        if (start) start += 3; else start = uri;
        const char *end = strchr(start, '/');
        size_t len = end ? (size_t)(end - start) : strlen(start);
        if (len >= sizeof(host)) len = sizeof(host) - 1;
        strncpy(host, start, len);
        /* Quitar puerto si lo hay */
        char *colon = strchr(host, ':');
        if (colon) *colon = '\0';

        struct hostent *he = gethostbyname(host);
        if (he) {
            unsigned char *addr = (unsigned char *)he->h_addr_list[0];
            snprintf(ctx->lines[i], MAX_URI,
                     "  Tab %d: %s → %d.%d.%d.%d",
                     i + 1, host,
                     addr[0], addr[1], addr[2], addr[3]);
        } else {
            snprintf(ctx->lines[i], MAX_URI,
                     "  Tab %d: %s → error al resolver", i + 1, host);
        }
    }
    g_idle_add(serverip_done, ctx);
    return NULL;
}

/* ─── Modo oscuro ────────────────────────────────────────────── */

static void apply_dark_css(BrowserWin *win) {
    const char *js =
        "(function() {"
        "  let style = document.getElementById('prekt-dark');"
        "  if (!style) {"
        "    style = document.createElement('style');"
        "    style.id = 'prekt-dark';"
        "    style.textContent = ':root{color-scheme:dark!important}"
        "      *{background:#111!important;color:#eee!important;border-color:#333!important}"
        "      a{color:#8cf!important}';"
        "    document.head.appendChild(style);"
        "  }"
        "})();";
    webkit_web_view_evaluate_javascript(active_wv(win), js, -1,
                                        NULL, NULL, NULL, NULL, NULL);
}

/* ─── Modo Tor ───────────────────────────────────────────────── */

static WebKitWebView *create_webview(BrowserWin *win, gboolean tor);

static void enable_tor_mode(BrowserWin *win) {
    TabInfo *tab = &win->tabs[win->current_tab];
    if (tab->tor_active) {
        char msg[128];
        snprintf(msg, sizeof(msg),
                 "La Tab %d ya tiene Tor activo.", win->current_tab + 1);
        print_to_terminal(win, msg, FALSE);
        return;
    }
    WebKitWebView *new_wv = create_webview(win, TRUE);
    swap_webview_in_tab(win, win->current_tab, new_wv, NULL);
    tab->tor_active = TRUE;

    char msg[128];
    snprintf(msg, sizeof(msg),
             "  MODO TOR ACTIVADO EN TAB %d", win->current_tab + 1);
    print_to_terminal(win, msg, FALSE);
    print_to_terminal(win, "  WebRTC DESACTIVADO.", FALSE);
    print_to_terminal(win, "  TEN CUIDADO.", FALSE);
    print_to_terminal(win, "  QUITA LA S DE LOS HTTPS:// EN SITIOS .ONION.", FALSE);
}

static void disable_tor_mode(BrowserWin *win) {
    TabInfo *tab = &win->tabs[win->current_tab];
    if (!tab->tor_active) {
        char msg[128];
        snprintf(msg, sizeof(msg),
                 "La Tab %d no tiene Tor activo.", win->current_tab + 1);
        print_to_terminal(win, msg, FALSE);
        return;
    }
    WebKitWebView *new_wv = create_webview(win, FALSE);
    swap_webview_in_tab(win, win->current_tab, new_wv, NULL);
    tab->tor_active = FALSE;

    char msg[128];
    snprintf(msg, sizeof(msg),
             "  MODO TOR DESACTIVADO EN TAB %d", win->current_tab + 1);
    print_to_terminal(win, msg, FALSE);
    print_to_terminal(win, "  Volviendo a sesión normal.", FALSE);
}

/* ─── process_command ────────────────────────────────────────── */

static void process_command(BrowserWin *win, const char *cmd_raw) {
    /* Copiar para tokenizar */
    char buf[1024];
    strncpy(buf, cmd_raw, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    /* Separar comando y args */
    char *space = strchr(buf, ' ');
    char command[256] = {0};
    char args[768]    = {0};
    if (space) {
        size_t cmd_len = space - buf;
        if (cmd_len >= sizeof(command)) cmd_len = sizeof(command) - 1;
        strncpy(command, buf, cmd_len);
        /* Saltar espacios iniciales en args */
        const char *a = space + 1;
        while (*a == ' ') a++;
        strncpy(args, a, sizeof(args) - 1);
    } else {
        strncpy(command, buf, sizeof(command) - 1);
    }

    /* Convertir command a minúsculas */
    for (char *p = command; *p; p++)
        *p = (char)tolower((unsigned char)*p);

    /* ─── Comandos ─── */

    if (strcmp(command, "help") == 0) {
        print_to_terminal(win,
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
            "  whoami                    → tu IP pública\n"
            "  serverip                  → IPs de los servidores de las 3 pestañas\n"
            "  historyten                → últimas 10 páginas visitadas",
            FALSE);

    } else if (strcmp(command, "tormode") == 0) {
        enable_tor_mode(win);

    } else if (strcmp(command, "untor") == 0) {
        disable_tor_mode(win);

    } else if (strcmp(command, "whoami") == 0) {
        print_to_terminal(win, "Consultando IP pública...", FALSE);
        pthread_t t;
        pthread_create(&t, NULL, whoami_thread, win);
        pthread_detach(t);
        return; /* no imprimir prompt doble */

    } else if (strcmp(command, "serverip") == 0) {
        if (win->tabs[win->current_tab].tor_active) {
            print_to_terminal(win,
                "serverip no está disponible en modo Tor (por tu seguridad).", FALSE);
        } else {
            print_to_terminal(win, "Resolviendo IPs de las 3 pestañas...", FALSE);
            ServerIpCtx *ctx = g_new0(ServerIpCtx, 1);
            ctx->win = win;
            pthread_t t;
            pthread_create(&t, NULL, serverip_thread, ctx);
            pthread_detach(t);
            return; /* no imprimir prompt doble */
        }

    } else if (strcmp(command, "historyten") == 0) {
        if (win->app->history_count == 0) {
            print_to_terminal(win, "El historial está vacío.", FALSE);
        } else {
            print_to_terminal(win, "Últimas páginas visitadas:", FALSE);
            int start = win->app->history_count - 10;
            if (start < 0) start = 0;
            int n = win->app->history_count - start;
            for (int i = 0; i < n; i++) {
                char line[MAX_URI + 8];
                snprintf(line, sizeof(line), "  %2d. %s",
                         i + 1,
                         win->app->url_history[win->app->history_count - n + i]);
                print_to_terminal(win, line, FALSE);
            }
        }

    } else if (strcmp(command, "home") == 0) {
        webkit_web_view_load_uri(active_wv(win), win->app->home_uri);

    } else if (strcmp(command, "google") == 0) {
        char url[MAX_URI];
        if (args[0]) {
            /* Codificación URL muy básica: solo reemplaza espacios con + */
            char encoded[MAX_URI];
            int j = 0;
            for (int i = 0; args[i] && j < (int)sizeof(encoded) - 4; i++) {
                if (args[i] == ' ') { encoded[j++] = '+'; }
                else { encoded[j++] = args[i]; }
            }
            encoded[j] = '\0';
            snprintf(url, MAX_URI, "https://www.google.com/search?q=%s", encoded);
        } else {
            strncpy(url, "https://www.google.com", MAX_URI - 1);
        }
        webkit_web_view_load_uri(active_wv(win), url);

    } else if (strcmp(command, "yt") == 0) {
        char url[MAX_URI];
        if (args[0]) {
            char encoded[MAX_URI];
            int j = 0;
            for (int i = 0; args[i] && j < (int)sizeof(encoded) - 4; i++) {
                if (args[i] == ' ') { encoded[j++] = '+'; }
                else { encoded[j++] = args[i]; }
            }
            encoded[j] = '\0';
            snprintf(url, MAX_URI,
                     "https://www.youtube.com/results?search_query=%s", encoded);
        } else {
            strncpy(url, "https://www.youtube.com", MAX_URI - 1);
        }
        webkit_web_view_load_uri(active_wv(win), url);

    } else if (strcmp(command, "wiki") == 0) {
        char url[MAX_URI];
        if (args[0]) {
            char encoded[MAX_URI];
            int j = 0;
            for (int i = 0; args[i] && j < (int)sizeof(encoded) - 4; i++) {
                if (args[i] == ' ') { encoded[j++] = '_'; }
                else { encoded[j++] = args[i]; }
            }
            encoded[j] = '\0';
            snprintf(url, MAX_URI,
                     "https://es.wikipedia.org/wiki/%s", encoded);
        } else {
            strncpy(url, "https://es.wikipedia.org", MAX_URI - 1);
        }
        webkit_web_view_load_uri(active_wv(win), url);

    } else if (strcmp(command, "cat") == 0) {
        webkit_web_view_load_uri(active_wv(win),
            "https://www.google.com/search?q=gatos+graciosos&tbm=isch");

    } else if (strcmp(command, "calc") == 0) {
        if (args[0]) {
            int err = 0;
            double result = safe_eval_expr(args, &err);
            char line[256];
            if (err)
                snprintf(line, sizeof(line), "Error: expresión no válida");
            else
                snprintf(line, sizeof(line), "%s = %g", args, result);
            print_to_terminal(win, line, FALSE);
        }

    } else if (strcmp(command, "time") == 0) {
        time_t now = time(NULL);
        struct tm *tm_info = localtime(&now);
        char buf2[32];
        strftime(buf2, sizeof(buf2), "%H:%M:%S", tm_info);
        print_to_terminal(win, buf2, FALSE);

    } else if (strcmp(command, "date") == 0) {
        time_t now = time(NULL);
        struct tm *tm_info = localtime(&now);
        char buf2[32];
        strftime(buf2, sizeof(buf2), "%Y-%m-%d", tm_info);
        print_to_terminal(win, buf2, FALSE);

    } else if (strcmp(command, "duckduckgo") == 0) {
        char url[MAX_URI];
        if (args[0]) {
            char encoded[MAX_URI];
            int j = 0;
            for (int i = 0; args[i] && j < (int)sizeof(encoded) - 4; i++) {
                if (args[i] == ' ') { encoded[j++] = '+'; }
                else { encoded[j++] = args[i]; }
            }
            encoded[j] = '\0';
            snprintf(url, MAX_URI, "https://duckduckgo.com/?q=%s", encoded);
        } else {
            strncpy(url, "https://duckduckgo.com", MAX_URI - 1);
        }
        webkit_web_view_load_uri(active_wv(win), url);

    } else if (strcmp(command, "new") == 0) {
        if (args[0]) load_uri_smart(win, args);

    } else if (strcmp(command, "dark") == 0) {
        win->app->dark_mode = !win->app->dark_mode;
        if (win->app->dark_mode) apply_dark_css(win);

    } else if (strcmp(command, "say") == 0) {
        if (args[0]) {
            GtkAlertDialog *dlg = gtk_alert_dialog_new("%s", args);
            gtk_alert_dialog_set_detail(dlg, "Mensaje de PrekT-BR");
            const char *buttons[] = {"OK", NULL};
            gtk_alert_dialog_set_buttons(dlg, buttons);
            gtk_alert_dialog_show(dlg, GTK_WINDOW(win));
            g_object_unref(dlg);
        }

    } else if (strcmp(command, "arburarbustribiet") == 0) {
        GtkAlertDialog *dlg = gtk_alert_dialog_new("Arbur Arbustribiet");
        gtk_alert_dialog_set_detail(dlg, "");
        const char *buttons[] = {"OK", NULL};
        gtk_alert_dialog_set_buttons(dlg, buttons);
        gtk_alert_dialog_show(dlg, GTK_WINDOW(win));
        g_object_unref(dlg);
        print_to_terminal(win, "Arbur Arbustribiet", FALSE);

    } else if (strcmp(command, "about") == 0) {
        char msg[256];
        snprintf(msg, sizeof(msg),
                 "PrekT-BR\nNavegador casero con WebKitGTK + terminal\nv%s",
                 APP_VERSION);
        print_to_terminal(win, msg, FALSE);

    } else if (strcmp(command, "clear") == 0 ||
               strcmp(command, "clean") == 0) {
        clear_terminal(win);
        return; /* clear ya pone el prompt */

    } else if (strcmp(command, "reload") == 0) {
        webkit_web_view_reload(active_wv(win));

    } else if (strcmp(command, "back") == 0) {
        if (webkit_web_view_can_go_back(active_wv(win)))
            webkit_web_view_go_back(active_wv(win));

    } else if (strcmp(command, "forward") == 0) {
        if (webkit_web_view_can_go_forward(active_wv(win)))
            webkit_web_view_go_forward(active_wv(win));

    } else if (strcmp(command, "echo") == 0) {
        if (args[0]) print_to_terminal(win, args, FALSE);

    } else if (strcmp(command, "quit") == 0 ||
               strcmp(command, "exit") == 0) {
        g_application_quit(G_APPLICATION(win->app));

    } else {
        char msg[256];
        snprintf(msg, sizeof(msg),
                 "Comando desconocido: %s\nPrueba 'help'", cmd_raw);
        print_to_terminal(win, msg, FALSE);
    }

    print_to_terminal(win, "", FALSE);
    print_prompt(win);
}

/* ─── Callbacks de WebView ───────────────────────────────────── */

static void on_uri_changed(WebKitWebView *wv, GParamSpec *pspec, gpointer user_data) {
    BrowserWin *win = (BrowserWin *)user_data;
    const char *uri = webkit_web_view_get_uri(wv);
    if (!uri || strcmp(uri, "about:blank") == 0) return;
    if (wv == active_wv(win))
        gtk_editable_set_text(GTK_EDITABLE(win->url_entry), uri);
    history_push(win->app, uri);
}

static void on_title_changed(WebKitWebView *wv, GParamSpec *pspec, gpointer user_data) {
    BrowserWin *win = (BrowserWin *)user_data;
    const char *title = webkit_web_view_get_title(wv);
    for (int i = 0; i < NUM_TABS; i++) {
        if (win->tabs[i].webview == wv) {
            char short_title[20];
            if (title && strlen(title) > 12) {
                strncpy(short_title, title, 12);
                strcpy(short_title + 12, "…");
            } else {
                snprintf(short_title, sizeof(short_title),
                         "%s", title ? title : "");
            }
            char label[32];
            snprintf(label, sizeof(label), " %s ", short_title[0] ? short_title : "");
            if (!short_title[0]) snprintf(label, sizeof(label), " Tab %d ", i + 1);
            gtk_button_set_label(win->tab_buttons[i], label);
            break;
        }
    }
    if (wv == active_wv(win)) {
        gtk_window_set_title(GTK_WINDOW(win),
                             title && title[0] ? title : "PrekT-BR :3");
    }
}

static gboolean dark_css_idle(gpointer user_data) {
    apply_dark_css((BrowserWin *)user_data);
    return G_SOURCE_REMOVE;
}

static void on_load_changed(WebKitWebView *wv, WebKitLoadEvent evt, gpointer user_data) {
    BrowserWin *win = (BrowserWin *)user_data;
    if (evt == WEBKIT_LOAD_FINISHED && win->app->dark_mode)
        g_timeout_add(600, dark_css_idle, win);
}

/* ─── Callbacks de UI ────────────────────────────────────────── */

static void on_tab_clicked(GtkButton *btn, gpointer user_data) {
    BrowserWin *win = (BrowserWin *)((gpointer *)user_data)[0];
    int idx = (int)(intptr_t)((gpointer *)user_data)[1];

    for (int i = 0; i < NUM_TABS; i++)
        gtk_widget_remove_css_class(GTK_WIDGET(win->tab_buttons[i]), "tab-active");

    win->current_tab = idx;
    gtk_widget_add_css_class(GTK_WIDGET(win->tab_buttons[idx]), "tab-active");

    char name[16];
    snprintf(name, sizeof(name), "tab%d", idx);
    gtk_stack_set_visible_child_name(win->tab_stack, name);

    const char *uri = webkit_web_view_get_uri(active_wv(win));
    gtk_editable_set_text(GTK_EDITABLE(win->url_entry),
                          (uri && strcmp(uri, "about:blank") != 0)
                          ? uri : win->app->home_uri);

    const char *title = webkit_web_view_get_title(active_wv(win));
    char win_title[256];
    snprintf(win_title, sizeof(win_title), "[Tab %d] %s",
             idx + 1, title ? title : "");
    gtk_window_set_title(GTK_WINDOW(win), win_title);
}

static void on_url_activate(GtkEntry *entry, gpointer user_data) {
    BrowserWin *win = (BrowserWin *)user_data;
    const char *text = gtk_editable_get_text(GTK_EDITABLE(entry));
    load_uri_smart(win, text);
}

static void on_go_clicked(GtkButton *btn, gpointer user_data) {
    BrowserWin *win = (BrowserWin *)user_data;
    const char *text = gtk_editable_get_text(GTK_EDITABLE(win->url_entry));
    load_uri_smart(win, text);
}

static void on_home_clicked(GtkButton *btn, gpointer user_data) {
    BrowserWin *win = (BrowserWin *)user_data;
    webkit_web_view_load_uri(active_wv(win), win->app->home_uri);
}

static void on_back_clicked(GtkButton *btn, gpointer user_data) {
    BrowserWin *win = (BrowserWin *)user_data;
    if (webkit_web_view_can_go_back(active_wv(win)))
        webkit_web_view_go_back(active_wv(win));
}

static void on_forward_clicked(GtkButton *btn, gpointer user_data) {
    BrowserWin *win = (BrowserWin *)user_data;
    if (webkit_web_view_can_go_forward(active_wv(win)))
        webkit_web_view_go_forward(active_wv(win));
}

static void on_reload_clicked(GtkButton *btn, gpointer user_data) {
    BrowserWin *win = (BrowserWin *)user_data;
    webkit_web_view_reload(active_wv(win));
}

static void on_toggle_terminal(GtkButton *btn, gpointer user_data) {
    BrowserWin *win = (BrowserWin *)user_data;
    if (win->terminal_visible) {
        gtk_box_remove(win->content_box, win->scroll_terminal);
        win->terminal_visible = FALSE;
    } else {
        gtk_box_append(win->content_box, win->scroll_terminal);
        win->terminal_visible = TRUE;
        gtk_widget_grab_focus(GTK_WIDGET(win->terminal_view));
    }
}

static gboolean on_terminal_key_pressed(GtkEventControllerKey *ctrl,
                                         guint keyval, guint keycode,
                                         GdkModifierType state,
                                         gpointer user_data) {
    BrowserWin *win = (BrowserWin *)user_data;
    if (keyval == GDK_KEY_Return || keyval == GDK_KEY_KP_Enter) {
        GtkTextIter start, end;
        gtk_text_buffer_get_bounds(win->terminal_buffer, &start, &end);
        char *full_text = gtk_text_buffer_get_text(win->terminal_buffer,
                                                    &start, &end, FALSE);
        /* Buscar la última línea */
        char *last_nl = strrchr(full_text, '\n');
        const char *last_line = last_nl ? last_nl + 1 : full_text;

        /* Quitar trailing whitespace */
        char line_copy[1024];
        strncpy(line_copy, last_line, sizeof(line_copy) - 1);
        line_copy[sizeof(line_copy) - 1] = '\0';
        size_t ll = strlen(line_copy);
        while (ll > 0 && (line_copy[ll-1] == '\n' || line_copy[ll-1] == '\r' ||
                           line_copy[ll-1] == ' '))
            line_copy[--ll] = '\0';

        if (strncmp(line_copy, "> ", 2) == 0) {
            const char *command = line_copy + 2;
            /* Saltar espacios */
            while (*command == ' ') command++;
            if (*command) {
                print_to_terminal(win, "", FALSE);
                process_command(win, command);
                /* process_command ya llama print_prompt */
                g_free(full_text);
                return TRUE;
            }
        }
        g_free(full_text);
        print_to_terminal(win, "", FALSE);
        print_prompt(win);
        return TRUE;
    }
    return FALSE;
}

/* ─── WebView factory ────────────────────────────────────────── */

static WebKitWebView *create_webview(BrowserWin *win, gboolean tor) {
    WebKitWebView *wv;

    if (tor) {
        WebKitNetworkSession *session = webkit_network_session_new_ephemeral();
        WebKitNetworkProxySettings *proxy =
            webkit_network_proxy_settings_new("socks5://127.0.0.1:9050", NULL);
        webkit_network_session_set_proxy_settings(
            session, WEBKIT_NETWORK_PROXY_MODE_CUSTOM, proxy);
        webkit_network_proxy_settings_free(proxy);
        wv = g_object_new(WEBKIT_TYPE_WEB_VIEW,
                          "network-session", session, NULL);
        g_object_unref(session);

        WebKitSettings *settings = webkit_settings_new();
        webkit_settings_set_enable_webrtc(settings, FALSE);
        webkit_settings_set_enable_mediasource(settings, FALSE);
        webkit_settings_set_user_agent(settings,
            "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0");
        webkit_web_view_set_settings(wv, settings);
        g_object_unref(settings);
    } else {
        wv = WEBKIT_WEB_VIEW(webkit_web_view_new());
    }

    gtk_widget_set_vexpand(GTK_WIDGET(wv), TRUE);
    gtk_widget_set_hexpand(GTK_WIDGET(wv), TRUE);

    g_signal_connect(wv, "notify::uri",      G_CALLBACK(on_uri_changed),   win);
    g_signal_connect(wv, "notify::title",    G_CALLBACK(on_title_changed), win);
    g_signal_connect(wv, "load-changed",     G_CALLBACK(on_load_changed),  win);

    return wv;
}

/* ─── swap_webview_in_tab ────────────────────────────────────── */

static void swap_webview_in_tab(BrowserWin *win, int idx,
                                 WebKitWebView *new_wv,
                                 const char *load_uri_override) {
    WebKitWebView *old_wv = win->tabs[idx].webview;
    const char *current_uri = webkit_web_view_get_uri(old_wv);
    char saved_uri[MAX_URI] = {0};
    if (current_uri) strncpy(saved_uri, current_uri, MAX_URI - 1);

    char name[16];
    snprintf(name, sizeof(name), "tab%d", idx);
    gtk_stack_remove(win->tab_stack, GTK_WIDGET(old_wv));
    win->tabs[idx].webview = new_wv;
    gtk_stack_add_named(win->tab_stack, GTK_WIDGET(new_wv), name);

    if (idx == win->current_tab)
        gtk_stack_set_visible_child_name(win->tab_stack, name);

    const char *uri_to_load = load_uri_override
                              ? load_uri_override
                              : (saved_uri[0] ? saved_uri : NULL);
    if (uri_to_load && strcmp(uri_to_load, "about:blank") != 0)
        webkit_web_view_load_uri(new_wv, uri_to_load);
    else
        webkit_web_view_load_uri(new_wv, win->app->home_uri);
}

/* ─── Construcción de la ventana ─────────────────────────────── */

static void browser_win_init(BrowserWin *win, BrowserApp *app) {
    win->app          = app;
    win->current_tab  = 0;
    win->terminal_visible = FALSE;

    gtk_window_set_title(GTK_WINDOW(win), "PrekT-BR");
    gtk_window_set_default_size(GTK_WINDOW(win), 1200, 800);

    /* CSS */
    GtkCssProvider *provider = gtk_css_provider_new();
    gtk_css_provider_load_from_string(provider,
        ".matrix-terminal {"
        "  background-color: #000000;"
        "  color: #00FF00;"
        "  font-family: monospace;"
        "  font-size: 14px;"
        "  padding: 8px;"
        "  caret-color: #00FF00;"
        "}"
        ".tab-active {"
        "  background: #444;"
        "  color: #fff;"
        "  font-weight: bold;"
        "}");
    GdkDisplay *display = gtk_widget_get_display(GTK_WIDGET(win));
    gtk_style_context_add_provider_for_display(display,
        GTK_STYLE_PROVIDER(provider),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(provider);

    /* Crear WebViews para las 3 pestañas */
    for (int i = 0; i < NUM_TABS; i++) {
        win->tabs[i].webview    = create_webview(win, FALSE);
        win->tabs[i].tor_active = FALSE;
        webkit_web_view_load_uri(win->tabs[i].webview, app->home_uri);
    }

    /* ── Barra de pestañas ── */
    GtkBox *tab_bar = GTK_BOX(gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4));
    gtk_widget_set_margin_start(GTK_WIDGET(tab_bar), 12);
    gtk_widget_set_margin_top(GTK_WIDGET(tab_bar), 4);

    /* Necesitamos pasar (win, index) a cada callback — usamos arrays estáticos */
    static gpointer tab_cb_data[NUM_TABS][2];
    for (int i = 0; i < NUM_TABS; i++) {
        char label[16];
        snprintf(label, sizeof(label), " Tab %d ", i + 1);
        GtkButton *btn = GTK_BUTTON(gtk_button_new_with_label(label));
        win->tab_buttons[i] = btn;
        tab_cb_data[i][0] = win;
        tab_cb_data[i][1] = (gpointer)(intptr_t)i;
        g_signal_connect(btn, "clicked", G_CALLBACK(on_tab_clicked), tab_cb_data[i]);
        gtk_box_append(tab_bar, GTK_WIDGET(btn));
    }
    gtk_widget_add_css_class(GTK_WIDGET(win->tab_buttons[0]), "tab-active");

    /* ── Barra de navegación ── */
    win->url_entry = GTK_ENTRY(gtk_entry_new());
    gtk_editable_set_text(GTK_EDITABLE(win->url_entry), app->initial_url);
    gtk_widget_set_hexpand(GTK_WIDGET(win->url_entry), TRUE);
    g_signal_connect(win->url_entry, "activate", G_CALLBACK(on_url_activate), win);

    GtkButton *go_btn      = GTK_BUTTON(gtk_button_new_with_label("Ir"));
    GtkButton *back_btn    = GTK_BUTTON(gtk_button_new_with_label(" ← "));
    GtkButton *forward_btn = GTK_BUTTON(gtk_button_new_with_label(" → "));
    GtkButton *reload_btn  = GTK_BUTTON(gtk_button_new_with_label(" ↻ "));
    GtkButton *home_btn    = GTK_BUTTON(gtk_button_new_with_label("Home"));
    GtkButton *term_btn    = GTK_BUTTON(gtk_button_new_with_label("Terminal"));

    g_signal_connect(go_btn,      "clicked", G_CALLBACK(on_go_clicked),       win);
    g_signal_connect(back_btn,    "clicked", G_CALLBACK(on_back_clicked),     win);
    g_signal_connect(forward_btn, "clicked", G_CALLBACK(on_forward_clicked),  win);
    g_signal_connect(reload_btn,  "clicked", G_CALLBACK(on_reload_clicked),   win);
    g_signal_connect(home_btn,    "clicked", G_CALLBACK(on_home_clicked),     win);
    g_signal_connect(term_btn,    "clicked", G_CALLBACK(on_toggle_terminal),  win);

    GtkBox *header = GTK_BOX(gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8));
    gtk_widget_set_margin_top(GTK_WIDGET(header), 6);
    gtk_widget_set_margin_bottom(GTK_WIDGET(header), 6);
    gtk_widget_set_margin_start(GTK_WIDGET(header), 12);
    gtk_widget_set_margin_end(GTK_WIDGET(header), 12);

    gtk_box_append(header, GTK_WIDGET(back_btn));
    gtk_box_append(header, GTK_WIDGET(forward_btn));
    gtk_box_append(header, GTK_WIDGET(reload_btn));
    gtk_box_append(header, GTK_WIDGET(home_btn));
    gtk_box_append(header, GTK_WIDGET(term_btn));
    gtk_box_append(header, GTK_WIDGET(win->url_entry));
    gtk_box_append(header, GTK_WIDGET(go_btn));

    /* ── Terminal ── */
    win->terminal_buffer = gtk_text_buffer_new(NULL);
    win->terminal_view   = GTK_TEXT_VIEW(gtk_text_view_new_with_buffer(win->terminal_buffer));
    gtk_text_view_set_editable(win->terminal_view, TRUE);
    gtk_text_view_set_cursor_visible(win->terminal_view, TRUE);
    gtk_text_view_set_wrap_mode(win->terminal_view, GTK_WRAP_WORD_CHAR);
    gtk_text_view_set_monospace(win->terminal_view, TRUE);
    gtk_widget_add_css_class(GTK_WIDGET(win->terminal_view), "matrix-terminal");

    win->scroll_terminal = gtk_scrolled_window_new();
    gtk_widget_set_vexpand(win->scroll_terminal, TRUE);
    gtk_widget_set_hexpand(win->scroll_terminal, TRUE);
    gtk_widget_set_size_request(win->scroll_terminal, 300, -1);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(win->scroll_terminal),
                                   GTK_WIDGET(win->terminal_view));

    GtkEventControllerKey *key_ctrl = GTK_EVENT_CONTROLLER_KEY(
        gtk_event_controller_key_new());
    g_signal_connect(key_ctrl, "key-pressed",
                     G_CALLBACK(on_terminal_key_pressed), win);
    gtk_widget_add_controller(GTK_WIDGET(win->terminal_view),
                               GTK_EVENT_CONTROLLER(key_ctrl));

    /* ── Stack de pestañas ── */
    win->tab_stack = GTK_STACK(gtk_stack_new());
    gtk_widget_set_vexpand(GTK_WIDGET(win->tab_stack), TRUE);
    gtk_widget_set_hexpand(GTK_WIDGET(win->tab_stack), TRUE);
    for (int i = 0; i < NUM_TABS; i++) {
        char name[16];
        snprintf(name, sizeof(name), "tab%d", i);
        gtk_stack_add_named(win->tab_stack,
                            GTK_WIDGET(win->tabs[i].webview), name);
    }
    gtk_stack_set_visible_child_name(win->tab_stack, "tab0");

    /* ── Layout principal ── */
    win->content_box = GTK_BOX(gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0));
    gtk_widget_set_vexpand(GTK_WIDGET(win->content_box), TRUE);
    gtk_widget_set_hexpand(GTK_WIDGET(win->content_box), TRUE);
    gtk_box_append(win->content_box, GTK_WIDGET(win->tab_stack));

    GtkBox *main_box = GTK_BOX(gtk_box_new(GTK_ORIENTATION_VERTICAL, 0));
    gtk_box_append(main_box, GTK_WIDGET(tab_bar));
    gtk_box_append(main_box, GTK_WIDGET(header));
    gtk_box_append(main_box, GTK_WIDGET(win->content_box));

    gtk_window_set_child(GTK_WINDOW(win), GTK_WIDGET(main_box));

    /* Mensaje inicial en la terminal */
    print_to_terminal(win, "PrekT-BR terminal", FALSE);
    print_to_terminal(win, "FUNCIONES: 'help' para ver todos los comandos\n", FALSE);
    print_prompt(win);
}

/* Variable global — patrón estándar en aplicaciones GTK/C */
static BrowserApp *g_browser_app = NULL;

/* ─── GApplication activate ──────────────────────────────────── */

static void app_activate(GApplication *gapp, gpointer user_data) {
    BrowserApp *app = g_browser_app;

    GtkWindow *existing = gtk_application_get_active_window(GTK_APPLICATION(gapp));
    if (existing) {
        gtk_window_present(existing);
        return;
    }

    /* Crear ventana como GtkApplicationWindow normal */
    GtkWidget *win_widget = gtk_application_window_new(GTK_APPLICATION(gapp));
    BrowserWin *win = g_new0(BrowserWin, 1);

    /* Reemplazar el widget interno con nuestra estructura
     * (usamos user_data en el widget para apuntar a win) */
    g_object_set_data(G_OBJECT(win_widget), "browser-win", win);

    /* Inicializar nuestro BrowserWin usando win_widget como ventana */
    win->app = app;
    win->current_tab = 0;
    win->terminal_visible = FALSE;

    gtk_window_set_title(GTK_WINDOW(win_widget), "PrekT-BR");
    gtk_window_set_default_size(GTK_WINDOW(win_widget), 1200, 800);

    /* CSS */
    GtkCssProvider *provider = gtk_css_provider_new();
    gtk_css_provider_load_from_string(provider,
        ".matrix-terminal {"
        "  background-color: #000000;"
        "  color: #00FF00;"
        "  font-family: monospace;"
        "  font-size: 14px;"
        "  padding: 8px;"
        "  caret-color: #00FF00;"
        "}"
        ".tab-active {"
        "  background: #444;"
        "  color: #fff;"
        "  font-weight: bold;"
        "}");
    GdkDisplay *display = gtk_widget_get_display(win_widget);
    gtk_style_context_add_provider_for_display(display,
        GTK_STYLE_PROVIDER(provider),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(provider);

    /* Crear WebViews */
    for (int i = 0; i < NUM_TABS; i++) {
        win->tabs[i].webview    = create_webview(win, FALSE);
        win->tabs[i].tor_active = FALSE;
        webkit_web_view_load_uri(win->tabs[i].webview, app->home_uri);
    }

    /* Barra de pestañas */
    GtkBox *tab_bar = GTK_BOX(gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4));
    gtk_widget_set_margin_start(GTK_WIDGET(tab_bar), 12);
    gtk_widget_set_margin_top(GTK_WIDGET(tab_bar), 4);

    static gpointer tab_cb_data[NUM_TABS][2];
    for (int i = 0; i < NUM_TABS; i++) {
        char label[16];
        snprintf(label, sizeof(label), " Tab %d ", i + 1);
        GtkButton *btn = GTK_BUTTON(gtk_button_new_with_label(label));
        win->tab_buttons[i] = btn;
        tab_cb_data[i][0] = win;
        tab_cb_data[i][1] = (gpointer)(intptr_t)i;
        g_signal_connect(btn, "clicked", G_CALLBACK(on_tab_clicked), tab_cb_data[i]);
        gtk_box_append(tab_bar, GTK_WIDGET(btn));
    }
    gtk_widget_add_css_class(GTK_WIDGET(win->tab_buttons[0]), "tab-active");

    /* Barra de navegación */
    win->url_entry = GTK_ENTRY(gtk_entry_new());
    gtk_editable_set_text(GTK_EDITABLE(win->url_entry), app->initial_url);
    gtk_widget_set_hexpand(GTK_WIDGET(win->url_entry), TRUE);
    g_signal_connect(win->url_entry, "activate", G_CALLBACK(on_url_activate), win);

    GtkButton *go_btn      = GTK_BUTTON(gtk_button_new_with_label("Ir"));
    GtkButton *back_btn    = GTK_BUTTON(gtk_button_new_with_label(" ← "));
    GtkButton *forward_btn = GTK_BUTTON(gtk_button_new_with_label(" → "));
    GtkButton *reload_btn  = GTK_BUTTON(gtk_button_new_with_label(" ↻ "));
    GtkButton *home_btn    = GTK_BUTTON(gtk_button_new_with_label("Home"));
    GtkButton *term_btn    = GTK_BUTTON(gtk_button_new_with_label("Terminal"));

    g_signal_connect(go_btn,      "clicked", G_CALLBACK(on_go_clicked),       win);
    g_signal_connect(back_btn,    "clicked", G_CALLBACK(on_back_clicked),     win);
    g_signal_connect(forward_btn, "clicked", G_CALLBACK(on_forward_clicked),  win);
    g_signal_connect(reload_btn,  "clicked", G_CALLBACK(on_reload_clicked),   win);
    g_signal_connect(home_btn,    "clicked", G_CALLBACK(on_home_clicked),     win);
    g_signal_connect(term_btn,    "clicked", G_CALLBACK(on_toggle_terminal),  win);

    GtkBox *header = GTK_BOX(gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8));
    gtk_widget_set_margin_top(GTK_WIDGET(header), 6);
    gtk_widget_set_margin_bottom(GTK_WIDGET(header), 6);
    gtk_widget_set_margin_start(GTK_WIDGET(header), 12);
    gtk_widget_set_margin_end(GTK_WIDGET(header), 12);
    gtk_box_append(header, GTK_WIDGET(back_btn));
    gtk_box_append(header, GTK_WIDGET(forward_btn));
    gtk_box_append(header, GTK_WIDGET(reload_btn));
    gtk_box_append(header, GTK_WIDGET(home_btn));
    gtk_box_append(header, GTK_WIDGET(term_btn));
    gtk_box_append(header, GTK_WIDGET(win->url_entry));
    gtk_box_append(header, GTK_WIDGET(go_btn));

    /* Terminal */
    win->terminal_buffer = gtk_text_buffer_new(NULL);
    win->terminal_view   = GTK_TEXT_VIEW(gtk_text_view_new_with_buffer(win->terminal_buffer));
    gtk_text_view_set_editable(win->terminal_view, TRUE);
    gtk_text_view_set_cursor_visible(win->terminal_view, TRUE);
    gtk_text_view_set_wrap_mode(win->terminal_view, GTK_WRAP_WORD_CHAR);
    gtk_text_view_set_monospace(win->terminal_view, TRUE);
    gtk_widget_add_css_class(GTK_WIDGET(win->terminal_view), "matrix-terminal");

    win->scroll_terminal = gtk_scrolled_window_new();
    gtk_widget_set_vexpand(win->scroll_terminal, TRUE);
    gtk_widget_set_hexpand(win->scroll_terminal, TRUE);
    gtk_widget_set_size_request(win->scroll_terminal, 300, -1);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(win->scroll_terminal),
                                   GTK_WIDGET(win->terminal_view));

    GtkEventControllerKey *key_ctrl = GTK_EVENT_CONTROLLER_KEY(
        gtk_event_controller_key_new());
    g_signal_connect(key_ctrl, "key-pressed",
                     G_CALLBACK(on_terminal_key_pressed), win);
    gtk_widget_add_controller(GTK_WIDGET(win->terminal_view),
                               GTK_EVENT_CONTROLLER(key_ctrl));

    /* Stack de pestañas */
    win->tab_stack = GTK_STACK(gtk_stack_new());
    gtk_widget_set_vexpand(GTK_WIDGET(win->tab_stack), TRUE);
    gtk_widget_set_hexpand(GTK_WIDGET(win->tab_stack), TRUE);
    for (int i = 0; i < NUM_TABS; i++) {
        char name[16];
        snprintf(name, sizeof(name), "tab%d", i);
        gtk_stack_add_named(win->tab_stack,
                            GTK_WIDGET(win->tabs[i].webview), name);
    }
    gtk_stack_set_visible_child_name(win->tab_stack, "tab0");

    win->content_box = GTK_BOX(gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0));
    gtk_widget_set_vexpand(GTK_WIDGET(win->content_box), TRUE);
    gtk_widget_set_hexpand(GTK_WIDGET(win->content_box), TRUE);
    gtk_box_append(win->content_box, GTK_WIDGET(win->tab_stack));

    GtkBox *main_box = GTK_BOX(gtk_box_new(GTK_ORIENTATION_VERTICAL, 0));
    gtk_box_append(main_box, GTK_WIDGET(tab_bar));
    gtk_box_append(main_box, GTK_WIDGET(header));
    gtk_box_append(main_box, GTK_WIDGET(win->content_box));

    gtk_window_set_child(GTK_WINDOW(win_widget), GTK_WIDGET(main_box));

    print_to_terminal(win, "PrekT-BR terminal", FALSE);
    print_to_terminal(win, "FUNCIONES: 'help' para ver todos los comandos\n", FALSE);
    print_prompt(win);

    gtk_window_present(GTK_WINDOW(win_widget));
}

/* ─── main ───────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
    /* Construir el home_uri usando la ruta absoluta del ejecutable */
    char exe_dir[4096] = {0};
    ssize_t len = readlink("/proc/self/exe", exe_dir, sizeof(exe_dir) - 1);
    if (len > 0) {
        exe_dir[len] = '\0';
        char *slash = strrchr(exe_dir, '/');
        if (slash) *slash = '\0';
    } else {
        getcwd(exe_dir, sizeof(exe_dir));
    }

    BrowserApp *app = g_new0(BrowserApp, 1);
    snprintf(app->home_uri, MAX_URI, "file://%s/newtab.html", exe_dir);
    strncpy(app->initial_url, app->home_uri, MAX_URI - 1);
    app->dark_mode     = FALSE;
    app->history_count = 0;

    g_browser_app = app;

    GtkApplication *gapp = gtk_application_new(APP_ID,
                                                G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(gapp, "activate", G_CALLBACK(app_activate), NULL);

    int status = g_application_run(G_APPLICATION(gapp), argc, argv);
    g_object_unref(gapp);
    g_free(app);
    return status;
}
