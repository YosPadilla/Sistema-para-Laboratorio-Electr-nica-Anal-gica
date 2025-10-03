# app.py — Flask + oracledb (thin) + bloqueo usando USUARIO como clave + sesión/roles
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
import os, re
import oracledb
from datetime import datetime, timezone, timedelta
from functools import wraps
from dotenv import load_dotenv

# ========= .env & Flask =========
load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET", "supersecretkey")

# Cookies/TTL de sesión
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    # Si sirves por HTTPS, descomenta:
    # SESSION_COOKIE_SECURE=True,
)

# ========= DB (modo thin) =========
DB_USER = os.getenv("DB_USER", "PROYECTO_USER")
DB_PASS = os.getenv("DB_PASSWORD", "proyecto123")
DB_DSN  = os.getenv("DB_DSN",  "localhost:1521/XEPDB1")

POOL = oracledb.create_pool(user=DB_USER, password=DB_PASS, dsn=DB_DSN, min=1, max=5, increment=1)
def _conn(): return POOL.acquire()

# ========= Parámetros bloqueo =========
LOCK_MAX_ATTEMPTS = int(os.getenv("LOCK_MAX_ATTEMPTS", "5"))
LOCK_TIME_MIN     = int(os.getenv("LOCK_TIME_MIN", "15"))

# ========= Validaciones =========
NAME_RE = re.compile(r"^[A-Za-zÁÉÍÓÚáéíóúÑñ ]+$")
USER_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
NC_RE   = re.compile(r"^(?:[Cc]\d{8}|\d{8})$")
# Dominio vigente:
MAIL_RE = re.compile(r"^l\d{8}@saltillo\.tecnm\.mx$", re.IGNORECASE)

def norm_nc(s):
    # Guardamos control en MAYÚSCULAS (acepta 'c' o 'C' pero se normaliza)
    return (s or "").strip().upper()

def norm_mail(s):
    # Elimina TODOS los espacios (externos e internos) y pasa a minúsculas
    return "".join((s or "").split()).lower()

def _now_utc(): 
    return datetime.now(timezone.utc)

# ========= Decoradores de acceso =========
def login_required(role=None):
    """
    Requiere sesión. Si 'role' es 0 o 1, además valida el tipo de usuario.
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = session.get("usuario")
            tipo = session.get("tipo")
            if not user:
                # guarda a dónde quería ir
                return redirect(url_for("login", next=request.path))
            if role is not None and tipo != role:
                abort(403)
            return fn(*args, **kwargs)
        return wrapper
    return decorator

# ========= Auth con bloqueo (clave = USUARIO) =========
def _get_user_row(cur, usuario):
    cur.execute("""
        SELECT usuario, password, tipo, intentos_fallidos, bloqueado_hasta
          FROM usuarios
         WHERE UPPER(usuario)=UPPER(:usr)
    """, usr=usuario)
    return cur.fetchone()

def auth_with_lock(usuario: str, contrasena: str):
    """
    Devuelve (ok:bool, tipo:int|None, msg:str).
    Bloqueo validado en SQL con SYSTIMESTAMP/SYSDATE.
    """
    with _conn() as con, con.cursor() as cur:
        cur.execute("""
            SELECT usuario, password, tipo, intentos_fallidos, bloqueado_hasta
              FROM usuarios
             WHERE UPPER(usuario)=UPPER(:u)
        """, u=usuario)
        row = cur.fetchone()
        if not row:
            return (False, None, "Verifica tu usuario y contraseña")

        usr_db, pwd_db, tipo, intentos, bloqueado = row

        # ¿Bloqueado aún?
        cur.execute("""
            SELECT CASE WHEN bloqueado_hasta IS NOT NULL AND bloqueado_hasta > SYSTIMESTAMP
                        THEN 1 ELSE 0 END
              FROM usuarios
             WHERE UPPER(usuario)=UPPER(:u)
        """, u=usuario)
        if int(cur.fetchone()[0]) == 1:
            cur.execute("""
                SELECT CEIL( (CAST(bloqueado_hasta AS DATE) - SYSDATE) * 24*60 )
                  FROM usuarios
                 WHERE UPPER(usuario)=UPPER(:u)
            """, u=usuario)
            mins_left = cur.fetchone()[0]
            mins_left = int(mins_left) if mins_left is not None and mins_left > 0 else 1
            return (False, None, f"Cuenta bloqueada por intentos fallidos. Intenta en ~{mins_left} min.")

        # ¿Password correcta?
        if contrasena == (pwd_db or ""):
            cur.execute("""
                UPDATE usuarios
                   SET intentos_fallidos=0,
                       bloqueado_hasta=NULL
                 WHERE UPPER(usuario)=UPPER(:u)
            """, u=usuario)
            con.commit()
            return (True, int(tipo), "Acceso concedido")

        # Password incorrecta → sumar intento y bloquear si procede
        cur.execute("""
            UPDATE usuarios
               SET intentos_fallidos = intentos_fallidos + 1
             WHERE UPPER(usuario)=UPPER(:u)
        """, u=usuario)
        cur.execute("""
            SELECT intentos_fallidos
              FROM usuarios
             WHERE UPPER(usuario)=UPPER(:u)
        """, u=usuario)
        new_attempts = int(cur.fetchone()[0])

        if new_attempts >= LOCK_MAX_ATTEMPTS:
            cur.execute("""
                UPDATE usuarios
                   SET bloqueado_hasta = SYSTIMESTAMP + NUMTODSINTERVAL(:mins,'MINUTE')
                 WHERE UPPER(usuario)=UPPER(:u)
            """, mins=LOCK_TIME_MIN, u=usuario)
            con.commit()
            return (False, None, f"Cuenta bloqueada por {LOCK_TIME_MIN} min por múltiples intentos fallidos.")
        else:
            con.commit()
            restantes = LOCK_MAX_ATTEMPTS - new_attempts
            return (False, None, f"Credenciales inválidas. Intentos restantes: {restantes}")

# ========= BD: pre-registro =========
def registrar_alumno(nombre, numero_control, correo, especialidad, semestre):
    try:
        nc_norm, mail_norm = norm_nc(numero_control), norm_mail(correo)
        with _conn() as con, con.cursor() as cur:
            # Validación de unicidad por NC o correo
            cur.execute("""
                SELECT COUNT(*)
                  FROM alumnos
                 WHERE UPPER(numerocontrol)=:nc OR LOWER(correo)=:mail
            """, nc=nc_norm, mail=mail_norm)
            if int(cur.fetchone()[0]) > 0:
                return "duplicado"

            # Inserción
            cur.execute("""
                INSERT INTO alumnos (nombre, numerocontrol, correo, especialidad, semestre)
                VALUES (:nombre, :nc, :correo, :esp, :sem)
            """, nombre=nombre.strip(), nc=nc_norm, correo=mail_norm,
                 esp=especialidad.strip(), sem=int(semestre))
            # IMPORTANTE: commit DENTRO del with
            con.commit()
        return "ok"
    except oracledb.IntegrityError:
        return "duplicado"
    except oracledb.Error as e:
        # Log al servidor; mensaje neutro al usuario
        print("Oracle registrar_alumno:", e)
        return "error"

# ========= Rutas =========
@app.route("/", methods=["GET","POST"])
def login():
    # soporta "next" para volver donde ibas
    next_url = request.args.get("next") or request.form.get("next")
    if request.method == "POST":
        usuario    = (request.form.get("usuario") or "").strip()
        contrasena = (request.form.get("contrasena") or "").strip()

        if not usuario and not contrasena:
            flash("Ingresa tu usuario y contraseña")
            return render_template("inicioAdmin.html", next=next_url)
        if usuario and not contrasena:
            flash("Ingresa tu contraseña")
            return render_template("inicioAdmin.html", next=next_url)
        if contrasena and not usuario:
            flash("Ingresa tu usuario")
            return render_template("inicioAdmin.html", next=next_url)
        if not USER_RE.match(usuario):
            flash("El usuario solo puede contener letras, números y _ . -")
            return render_template("inicioAdmin.html", next=next_url)

        ok, tipo, msg = auth_with_lock(usuario, contrasena)
        if not ok:
            flash(msg)
            return render_template("inicioAdmin.html", next=next_url)

        # --- marcar sesión ---
        session.permanent = True
        session["usuario"] = usuario
        session["tipo"]    = tipo  # 0=admin, 1=aux

        destino = next_url or ("interface_admin" if tipo == 0 else "interface_aux")
        return redirect(url_for(destino))

    return render_template("inicioAdmin.html", next=next_url)

@app.route("/logout")
def logout():
    session.clear()
    flash("Sesión cerrada", "success")
    return redirect(url_for("login"))

@app.route("/interface_admin")
@login_required(role=0)  # solo admin
def interface_admin():
    return render_template("interfaceAdmin.html")

@app.route("/interface_aux")
@login_required(role=1)  # solo auxiliar
def interface_aux():
    return render_template("interfaceAux.html")

@app.route("/registro_alumno", methods=["GET","POST"])
def registro_alumno_route():
    if request.method == "POST":
        nombre         = (request.form.get("nombre") or "").strip()
        numero_control = (request.form.get("numero_control") or "").strip()
        correo_input   = (request.form.get("correo") or "")
        especialidad   = (request.form.get("carrera") or "").strip()
        semestre       = (request.form.get("semestre") or "").strip()

        if not (nombre and numero_control and correo_input and especialidad and semestre):
            flash("Completa los campos faltantes", "error")
            return render_template("inicioAlumno.html")

        if not NAME_RE.match(nombre) or not NC_RE.match(numero_control):
            flash("Verifica el formato de los datos ingresados", "error")
            return render_template("inicioAlumno.html")

        # Normaliza correo (sin espacios, minúsculas) y valida dominio
        mail_norm = norm_mail(correo_input)
        if not MAIL_RE.match(mail_norm):
            flash("Verifica el formato del correo institucional (@saltillo.tecnm.mx)", "error")
            return render_template("inicioAlumno.html")

        r = registrar_alumno(nombre, numero_control, mail_norm, especialidad, semestre)
        flash(
            "Ya estás registrado" if r == "duplicado"
            else ("Te has registrado con éxito" if r == "ok" else "Error al registrar alumno. Intenta de nuevo."),
            "error" if r in ("duplicado","error") else "success"
        )
    return render_template("inicioAlumno.html")

# --- Inventario placeholder (protegido para usuarios autenticados) ---
@app.route("/inventario")
@login_required()
def inventario():
    try:
        with _conn() as con, con.cursor() as cur:
            cur.execute("SELECT * FROM inventario ORDER BY 1")
            items = cur.fetchall()
        return render_template("inventario.html", items=items)
    except Exception as e:
        flash(f"Error cargando inventario: {e}", "error")
        return render_template("inventario.html", items=[])

# --- Diagnóstico (puedes borrar en prod) ---
@app.route("/healthz")
def healthz(): 
    return {"status":"ok"}

@app.route("/dbcheck")
def dbcheck():
    try:
        with _conn() as con, con.cursor() as cur:
            cur.execute("SELECT 1 FROM dual"); row = cur.fetchone()
        return {"db":"ok","probe":row[0] if row else None}
    except oracledb.Error as e:
        return {"db":"error","detail":str(e)}, 500

@app.route("/__routes")
def __routes():
    return {"routes": sorted([f"{r.endpoint} -> {r.rule}" for r in app.url_map.iter_rules()])}

@app.route("/__user/<usuario>")
def __user(usuario):
    with _conn() as con, con.cursor() as cur:
        cur.execute("""
          SELECT usuario, intentos_fallidos,
                 TO_CHAR(bloqueado_hasta,'YYYY-MM-DD HH24:MI:SS')
            FROM usuarios
           WHERE UPPER(usuario)=UPPER(:u)
        """, u=usuario)
        row = cur.fetchone()
    return {"row": row}

@app.route("/__unlock/<usuario>")
def __unlock(usuario):
    with _conn() as con, con.cursor() as cur:
        cur.execute("""
          UPDATE usuarios
             SET intentos_fallidos=0, bloqueado_hasta=NULL
           WHERE UPPER(usuario)=UPPER(:u)
        """, u=usuario)
        con.commit()
    return {"usuario": usuario, "status":"unlocked"}

if __name__ == "__main__":
    app.run(debug=True)
