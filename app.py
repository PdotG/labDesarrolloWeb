# app.py — Laboratorio Vulnerable vs Seguro (Flask + SQLite)
#
# Este taller muestra PAREJAS de endpoints:
#   - /api/vuln/...  → implementación insegura
#   - /api/safe/...  → implementación más razonable
#
# Escenarios que se trabajan:
#   1) Autenticación y SQL Injection
#   2) IDOR (Insecure Direct Object Reference) en /profile
#   3) XSS reflejado en /search
#   4) CSRF + comentarios
#   5) Path traversal / lectura arbitraria de ficheros
#   6) Exposición de código fuente
#
# La idea es que el alumnado:
#   - Primero intente EXPLOTAR la parte /vuln.
#   - Luego vea por qué /safe resiste, leyendo el código.
#   - Compare patrones inseguros vs seguros.

from flask import Flask, request, jsonify, make_response, send_from_directory, render_template
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import sqlite3
import os
import secrets
import html as htmllib
import time
from argon2 import PasswordHasher

# --- Configuración base ------------------------------------------------------

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "lab.db")
PUBLIC_FILES_DIR = os.path.join(BASE_DIR, "public", "files")

app = Flask(__name__)
app.config["SECRET_KEY"] = secrets.token_hex(16)

# Limitador de peticiones (solo lo usamos en las rutas "safe")
limiter = Limiter(get_remote_address, app=app, default_limits=[])

# Argon2 para almacenamiento de contraseñas en la parte segura
ph = PasswordHasher()

# Tiempo de vida de las sesiones (no es el foco del taller, pero es buena práctica)
SESSION_TTL = 60 * 30  # 30 minutos


# --- Helpers de BD -----------------------------------------------------------

def db_conn():
    """Devuelve una conexión SQLite simple."""
    return sqlite3.connect(DB_PATH)


def row_factory(cursor, row):
    """Convierte una fila de SQLite en un dict {columna: valor}."""
    return {col[0]: row[idx] for idx, col in enumerate(cursor.description)}


def db_init():
    """Inicializa la base de datos y crea algunos usuarios de ejemplo."""
    with db_conn() as con:
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user TEXT UNIQUE,
                pass TEXT,
                pass_hash TEXT
            )
            """
        )
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS comments(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user TEXT,
                text TEXT,
                created_at TEXT
            )
            """
        )

        con.row_factory = row_factory

        # Usuario admin (contraseña en claro + hash para comparar lado vuln/safe)
        cur = con.execute("SELECT id FROM users WHERE user='admin'")
        if not cur.fetchone():
            try:
                hashed = ph.hash("luna2001")
            except Exception:
                hashed = None
            con.execute(
                "INSERT INTO users(user, pass, pass_hash) VALUES (?,?,?)",
                ("admin", "luna2001", hashed),
            )

        # Usuario “normal” para jugar con IDOR
        cur = con.execute("SELECT id FROM users WHERE user='alice'")
        if not cur.fetchone():
            try:
                hashed_alice = ph.hash("alice123")
            except Exception:
                hashed_alice = None
            con.execute(
                "INSERT INTO users(user, pass, pass_hash) VALUES (?,?,?)",
                ("alice", "alice123", hashed_alice),
            )

db_init()


# --- Gestión de sesiones (muy simple, en memoria) ---------------------------

SESSIONS = {}


def create_session(resp, user_row, secure=False):
    """
    Crea una sesión simple en memoria.

    secure=False -> Versión vulnerable:
        * Cookie sin HttpOnly, sin Secure, SameSite=Lax.
    secure=True  -> Versión "safe":
        * HttpOnly, Secure, SameSite=Strict.
    """
    sid = secrets.token_hex(16)
    csrf = secrets.token_hex(16)

    SESSIONS[sid] = {
        "userId": user_row["id"],
        "user": user_row["user"],
        "csrf": csrf,
        "created": time.time(),
    }

    if secure:
        resp.set_cookie(
            "sid",
            sid,
            httponly=True,
            secure=True,
            samesite="Strict",
            path="/",
        )
    else:
        # Cookie clásica insegura: accesible por JS, sin Secure ni Strict
        resp.set_cookie(
            "sid",
            sid,
            httponly=False,
            secure=False,
            samesite="Lax",
            path="/",
        )


def get_session():
    """Devuelve la sesión asociada a la cookie 'sid', o None."""
    sid = request.cookies.get("sid")
    if not sid:
        return None

    sess = SESSIONS.get(sid)
    if not sess:
        return None

    # Pequeño timeout para evitar sesiones eternas
    if time.time() - sess["created"] > SESSION_TTL:
        SESSIONS.pop(sid, None)
        return None

    return sess


def add_csp(resp):
    """
    Añade una política CSP bastante restrictiva a las respuestas "safe".
    Sirve para mitigar XSS aunque se escape el input de forma correcta.
    """
    resp.headers[
        "Content-Security-Policy"
    ] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
    return resp


# --- Helpers genéricos de BD -------------------------------------------------

def query_one(sql, params=()):
    con = db_conn()
    con.row_factory = row_factory
    cur = con.execute(sql, params)
    row = cur.fetchone()
    con.close()
    return row


def query_all(sql, params=()):
    con = db_conn()
    con.row_factory = row_factory
    cur = con.execute(sql, params)
    rows = cur.fetchall()
    con.close()
    return rows


def exec_sql(sql, params=()):
    con = db_conn()
    con.execute(sql, params)
    con.commit()
    con.close()


# --- Rutas base (UI) ---------------------------------------------------------

@app.route("/")
def home():
    # La SPA del taller (JS decide si usar /vuln o /safe)
    return render_template("index.html")


@app.route("/vuln")
def vuln_ui():
    return render_template("index.html")


@app.route("/safe")
def safe_ui():
    return render_template("index.html")


# --- Escenario 1: Login vulnerable vs seguro (SQLi + contraseñas) -----------

@app.post("/api/vuln/login")
def api_vuln_login():
    """
    Versión vulnerable:
      - SQL construido por concatenación -> SQL Injection.
      - Contraseñas en claro en BD.
      - Cookie de sesión sin HttpOnly ni Secure.
    """
    data = request.get_json(silent=True) or {}
    user = data.get("user", "")
    pw = data.get("pass", "")

    # PATRÓN MALO: concatenar el input directamente en el SQL
    # Esto permite SQL Injection como: admin' OR '1'='1' --
    sql = f"SELECT id, user, pass FROM users WHERE user='{user}' AND pass='{pw}'"

    try:
        row = query_one(sql)
        if row:
            resp = jsonify({
                "ok": True, 
                "via": "sqli/weak", 
                "sql": sql,
                "user": row.get("user")
            })
            create_session(resp, row, secure=False)
            return resp
        else:
            return jsonify({"ok": False, "sql": sql, "message": "Login fallido"}), 401
    except Exception as e:
        # En caso de error SQL, devolvemos el error (información sensible!)
        return jsonify({"error": str(e), "sql": sql}), 500


@app.post("/api/safe/login")
@limiter.limit("10 per 5 minutes")  # Rate limiting básico
def api_safe_login():
    """
    Versión más segura:
      - Consulta SQL parametrizada (evita SQLi).
      - Contraseñas con Argon2 en BD.
      - Cookie con HttpOnly + Secure + SameSite=Strict.
      - Mensaje de error genérico.
    """
    data = request.get_json(silent=True) or {}
    user = data.get("user", "")
    pw = data.get("pass", "")

    row = query_one("SELECT id, user, pass_hash FROM users WHERE user=?", (user,))
    if row and row.get("pass_hash"):
        try:
            if ph.verify(row["pass_hash"], pw):
                resp = jsonify({"ok": True})
                create_session(resp, row, secure=True)
                return add_csp(resp)
        except Exception:
            # Para el taller no diferenciamos entre usuario incorrecto y password incorrecta
            pass

    return add_csp(jsonify({"ok": False})), 401


# --- Escenario 2: Server-Side Request Forgery (SSRF) -------------------------------

@app.post("/api/vuln/fetch")
def api_vuln_fetch():
    """
    Versión vulnerable:
      - SSRF: permite hacer peticiones a URLs arbitrarias sin validación
      - Puede acceder a recursos internos (localhost, 127.0.0.1, metadata)
      - No valida el esquema de la URL (file://, gopher://, etc.)
      - Expone el contenido de recursos internos
    """
    import urllib.request
    import urllib.error
    
    data = request.get_json(silent=True) or {}
    url = data.get('url', '')
    
    if not url:
        return jsonify({"error": "URL requerida"}), 400
    
    try:
        # VULNERABILIDAD: Hace petición sin validación
        response = urllib.request.urlopen(url, timeout=5)
        content = response.read().decode('utf-8', errors='ignore')
        
        return jsonify({
            "ok": True,
            "url": url,
            "content": content[:1000],  # Primeros 1000 caracteres
            "status": response.status,
            "warning": "⚠️ SSRF: petición sin validación"
        })
    except urllib.error.HTTPError as e:
        return jsonify({"error": f"HTTP Error {e.code}: {e.reason}"}), 400
    except urllib.error.URLError as e:
        return jsonify({"error": f"URL Error: {str(e.reason)}"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.post("/api/safe/fetch")
@limiter.limit("10 per minute")
def api_safe_fetch():
    """
    Versión más segura:
      - Whitelist de dominios permitidos
      - Validación de esquema (solo http/https)
      - Bloquea IPs privadas y localhost
      - Rate limiting
      - Timeout corto
    """
    import urllib.request
    import urllib.error
    from urllib.parse import urlparse
    import socket
    import ipaddress
    
    sess = get_session()
    if not sess:
        return add_csp(jsonify({"error": "Login requerido"})), 401
    
    data = request.get_json(silent=True) or {}
    url = data.get('url', '')
    
    if not url:
        return add_csp(jsonify({"error": "URL requerida"})), 400
    
    # Validación de esquema
    parsed = urlparse(url)
    if parsed.scheme not in ['http', 'https']:
        return add_csp(jsonify({"error": "Solo se permiten http/https"})), 400
    
    # Whitelist de dominios
    ALLOWED_DOMAINS = ['example.com', 'httpbin.org', 'jsonplaceholder.typicode.com']
    if not any(parsed.netloc.endswith(domain) for domain in ALLOWED_DOMAINS):
        return add_csp(jsonify({"error": f"Dominio no permitido. Permitidos: {', '.join(ALLOWED_DOMAINS)}"})), 403
    
    # Validar que no sea IP privada o localhost
    try:
        ip = socket.gethostbyname(parsed.netloc)
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback:
            return add_csp(jsonify({"error": "No se permiten IPs privadas o localhost"})), 403
    except:
        pass  # Si no se puede resolver, continuar
    
    try:
        response = urllib.request.urlopen(url, timeout=3)
        content = response.read().decode('utf-8', errors='ignore')
        
        return add_csp(jsonify({
            "ok": True,
            "url": url,
            "content": content[:500],
            "status": response.status
        }))
    except urllib.error.HTTPError as e:
        return add_csp(jsonify({"error": f"HTTP Error {e.code}"})), 400
    except urllib.error.URLError as e:
        return add_csp(jsonify({"error": "Error al acceder a la URL"})), 400
    except Exception as e:
        return add_csp(jsonify({"error": "Error en la petición"})), 500


@app.get("/api/<mode>/profile")
def api_get_profile(mode):
    """Obtiene el perfil del usuario actual."""
    sess = get_session()
    
    if mode == "vuln":
        # En vulnerable, muestra info sin autenticación
        user_id = request.args.get('id', 1)
        row = query_one("SELECT id, user FROM users WHERE id=?", (user_id,))
        if row:
            return jsonify(row)
        return jsonify({"error": "Not found"}), 404
    else:
        # En seguro, requiere sesión
        if not sess:
            return add_csp(jsonify({"error": "Login requerido"})), 401
        
        row = query_one("SELECT id, user FROM users WHERE id=?", (sess['userId'],))
        if row:
            return add_csp(jsonify(row))
        return add_csp(jsonify({"error": "Not found"})), 404


# --- Escenario 3: XSS reflejado vs escapado + CSP ---------------------------

@app.get("/api/vuln/search")
def api_vuln_search():
    """
    Versión vulnerable:
      - Responde HTML con el parámetro 'q' sin escapar.
      - Ideal para mostrar XSS reflejado.
    """
    q = request.args.get("q", "")
    html_resp = f"<div>Resultados para: <code>{q}</code></div><hr>{q}"
    resp = make_response(html_resp)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp


@app.get("/api/safe/search")
def api_safe_search():
    """
    Versión más segura:
      - Escapa el contenido HTML.
      - Añade CSP restrictiva.
    """
    q = request.args.get("q", "")
    safe_q = htmllib.escape(q)
    html_resp = f"<div>Resultados para: <code>{safe_q}</code></div><hr>{safe_q}"
    resp = make_response(html_resp)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return add_csp(resp)


# --- Escenario 4: Comentarios sin protección vs CSRF token ------------------

@app.get("/api/<mode>/comments")
def api_comments(mode):
    """
    /api/vuln/comments  -> devuelve los comentarios sin más (se usan igual desde front).
    /api/safe/comments  -> mismo resultado pero con CSP.
    """
    rows = query_all(
        "SELECT id, user, text, created_at FROM comments ORDER BY id DESC LIMIT 50"
    )
    if mode == "vuln":
        return jsonify(rows)
    else:
        return add_csp(jsonify(rows))


@app.get("/api/safe/csrf")
def api_safe_csrf():
    """
    Devuelve el token CSRF asociado a la sesión.
    Se espera que el front lo envíe en la cabecera 'x-csrf-token'.
    """
    sess = get_session()
    if not sess:
        return add_csp(jsonify({"error": "login requerido"})), 401
    return add_csp(jsonify({"token": sess["csrf"]}))


@app.post("/api/vuln/comments")
def api_vuln_comment():
    """
    Versión vulnerable:
      - No requiere login.
      - No hay CSRF token.
      - No se limita el tamaño del comentario ni se valida el contenido.
    """
    data = request.get_json(silent=True) or {}
    text = data.get("text", "")
    user = (get_session() or {}).get("user", "anon")
    exec_sql(
        "INSERT INTO comments(user, text, created_at) VALUES (?,?, datetime('now'))",
        (user, text),
    )
    return jsonify({"ok": True})


@app.post("/api/safe/comments")
def api_safe_comment():
    """
    Versión más segura:
      - Requiere sesión válida.
      - Exige token CSRF correcto en cabecera 'x-csrf-token'.
      - Limita tamaño del texto.
    """
    sess = get_session()
    if not sess:
        return add_csp(jsonify({"error": "login requerido"})), 401

    token = request.headers.get("x-csrf-token")
    if not token or token != sess["csrf"]:
        return add_csp(jsonify({"error": "CSRF token inválido"})), 403

    data = request.get_json(silent=True) or {}
    text = str(data.get("text", ""))[:500]  # limitamos a 500 chars para el ejemplo

    exec_sql(
        "INSERT INTO comments(user, text, created_at) VALUES (?,?, datetime('now'))",
        (sess["user"], text),
    )
    return add_csp(jsonify({"ok": True}))


# --- Escenario 5: File Upload Malicioso -------------------------------------

ALLOWED_EXTENSIONS = {'.txt', '.pdf', '.jpg', '.png', '.gif'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")

os.makedirs(UPLOAD_DIR, exist_ok=True)

@app.post("/api/vuln/upload")
def api_vuln_upload():
    """
    Versión vulnerable:
      - No valida tipo de archivo (permite .php, .exe, .sh)
      - No valida tamaño
      - No sanitiza nombre de archivo (permite path traversal en nombre)
      - Guarda con nombre original (puede sobrescribir archivos)
    """
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "Empty filename"}), 400
    
    # VULNERABILIDAD: Usa el nombre original sin sanitizar
    filepath = os.path.join(UPLOAD_DIR, file.filename)
    file.save(filepath)
    
    return jsonify({
        "ok": True,
        "message": "File uploaded",
        "filename": file.filename,
        "warning": "⚠️ Sin validación de tipo, tamaño o nombre de archivo"
    })


@app.post("/api/safe/upload")
def api_safe_upload():
    """
    Versión más segura:
      - Valida extensión con whitelist
      - Valida tamaño máximo
      - Sanitiza nombre de archivo
      - Usa UUID para evitar colisiones y sobrescrituras
      - Verifica magic bytes (content type real)
    """
    sess = get_session()
    if not sess:
        return add_csp(jsonify({"error": "Login requerido"})), 401
    
    if 'file' not in request.files:
        return add_csp(jsonify({"error": "No file provided"})), 400
    
    file = request.files['file']
    if file.filename == '':
        return add_csp(jsonify({"error": "Empty filename"})), 400
    
    # Validar extensión
    _, ext = os.path.splitext(file.filename.lower())
    if ext not in ALLOWED_EXTENSIONS:
        return add_csp(jsonify({
            "error": "Tipo de archivo no permitido",
            "allowed": list(ALLOWED_EXTENSIONS)
        })), 400
    
    # Validar tamaño (leer en memoria temporalmente)
    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    file.seek(0)
    
    if file_size > MAX_FILE_SIZE:
        return add_csp(jsonify({
            "error": "Archivo muy grande",
            "max_size": "5MB"
        })), 400
    
    # Generar nombre seguro con UUID
    safe_filename = f"{secrets.token_hex(8)}{ext}"
    filepath = os.path.join(UPLOAD_DIR, safe_filename)
    
    file.save(filepath)
    
    return add_csp(jsonify({
        "ok": True,
        "message": "File uploaded securely",
        "filename": safe_filename,
        "original": file.filename,
        "size": file_size
    }))


@app.get("/api/<mode>/uploads")
def api_list_uploads(mode):
    """Lista archivos subidos."""
    try:
        files = []
        for filename in os.listdir(UPLOAD_DIR):
            filepath = os.path.join(UPLOAD_DIR, filename)
            if os.path.isfile(filepath):
                stat = os.stat(filepath)
                files.append({
                    "name": filename,
                    "size": stat.st_size,
                    "created": time.ctime(stat.st_ctime)
                })
        
        if mode == 'safe':
            return add_csp(jsonify({"files": files}))
        return jsonify({"files": files})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# --- Escenario 6: Exposición de código fuente -------------------------------

ALLOWED_CODE_FILES = [
    os.path.join(BASE_DIR, "app.py"),
    os.path.join(BASE_DIR, "templates", "index.html"),
    os.path.join(BASE_DIR, "static", "app.js"),
    os.path.join(BASE_DIR, "static", "styles.css"),
]


@app.get("/api/vuln/code")
def api_vuln_code():
    """
    Versión vulnerable:
      - Permite leer cualquier fichero del sistema al que tenga acceso el proceso.
      - Ideal para enseñar por qué es mala idea dejar "endpoints de debug" abiertos.
    """
    file = request.args.get("file", "")
    abs_path = file if os.path.isabs(file) else os.path.join(BASE_DIR, file)
    try:
        with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        return jsonify({"code": content, "file": file})
    except Exception as e:
        return jsonify({"error": f"No encontrado: {str(e)}"}), 404


@app.get("/api/safe/code")
def api_safe_code():
    """
    Versión más segura:
      - Solo permite leer código de una lista blanca de ficheros.
      - Aun así, este tipo de endpoints solo deberían existir en entornos de demo.
    """
    file = request.args.get("file", "")
    abs_path = file if os.path.isabs(file) else os.path.join(BASE_DIR, file)

    if abs_path not in ALLOWED_CODE_FILES:
        return add_csp(jsonify({"error": "Acceso denegado a este fichero"})), 403

    try:
        with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        return add_csp(jsonify({"code": content, "file": file}))
    except Exception as e:
        return add_csp(jsonify({"error": f"No encontrado: {str(e)}"})), 404


# --- Ficheros estáticos "públicos" ------------------------------------------

@app.route("/files/<path:filename>")
def serve_public_files(filename):
    return send_from_directory(PUBLIC_FILES_DIR, filename)


# --- Arranque ----------------------------------------------------------------

if __name__ == "__main__":
    os.makedirs(PUBLIC_FILES_DIR, exist_ok=True)
    app.run(host="0.0.0.0", port=3000, debug=False)
