# app.py
from flask import Flask, render_template, request, redirect, url_for, flash
import oracledb
import re

app = Flask(__name__)
app.secret_key = "supersecretkey"

# ===================== CONFIG DB =====================
DB_USER = "PROYECTO_USER"          # usuario Oracle existente
DB_PASS = "proyecto123"            # contraseña confirmada
DB_DSN  = "localhost:1521/XEPDB1"  # SERVICE de la PDB (no SID)

def _conn():
    return oracledb.connect(user=DB_USER, password=DB_PASS, dsn=DB_DSN)

# ===================== VALIDACIONES / NORMALIZADORES =====================
NAME_RE = re.compile(r"^[A-Za-zÁÉÍÓÚáéíóúÑñ ]+$")

# NC: 8 dígitos o 'C'/'c' + 8 dígitos
NC_RE   = re.compile(r"^(?:[Cc]\d{8}|\d{8})$")

# Correo institucional: L + 8 dígitos + @saltillo.tecnm.mx (case-insensitive)
MAIL_RE = re.compile(r"^l\d{8}@saltillo\.tecnm\.mx$", re.IGNORECASE)

def norm_nc(s: str) -> str:
    return (s or "").strip().upper()

def norm_mail(s: str) -> str:
    return (s or "").strip().lower()

# ===================== FUNCIONES BD =====================
def validar_usuario(usuario, contrasena):
    """Devuelve tipo (0/1) si user/pass correctos; None si no."""
    try:
        with _conn() as connection, connection.cursor() as cursor:
            cursor.execute("""
                SELECT tipo
                FROM usuarios
                WHERE usuario = :usr AND password = :pwd
            """, usr=usuario, pwd=contrasena)
            row = cursor.fetchone()
            return int(row[0]) if row else None
    except oracledb.DatabaseError as e:
        print("Error Oracle en validar_usuario:", e)
        return None

def usuario_existe(usuario):
    """True si el usuario existe (sin validar password)."""
    try:
        with _conn() as connection, connection.cursor() as cursor:
            cursor.execute("SELECT 1 FROM usuarios WHERE usuario = :usr", usr=usuario)
            return cursor.fetchone() is not None
    except oracledb.DatabaseError as e:
        print("Error Oracle en usuario_existe:", e)
        return False

def registrar_alumno(nombre, numero_control, correo, especialidad, semestre):
    """Inserta un alumno respetando unicidad por numerocontrol y correo (case-insensitive)."""
    try:
        nc_norm   = norm_nc(numero_control)
        mail_norm = norm_mail(correo)

        with _conn() as connection, connection.cursor() as cursor:
            # verificar duplicados por NC (en mayúsculas) o correo (en minúsculas)
            cursor.execute("""
                SELECT COUNT(*)
                  FROM alumnos
                 WHERE UPPER(numerocontrol) = :nc
                    OR LOWER(correo)        = :mail
            """, nc=nc_norm, mail=mail_norm)
            if cursor.fetchone()[0] > 0:
                return "duplicado"

            cursor.execute("""
                INSERT INTO alumnos (nombre, numerocontrol, correo, especialidad, semestre)
                VALUES (:nombre, :nc, :correo, :esp, :sem)
            """, nombre=nombre.strip(),
                 nc=nc_norm, correo=mail_norm,
                 esp=especialidad.strip(), sem=int(semestre))
            connection.commit()
            return "ok"
    except oracledb.IntegrityError:
        return "duplicado"
    except oracledb.DatabaseError as e:
        print("Error Oracle en registrar_alumno:", e)
        return "error"

# ===================== RUTAS =====================
@app.route("/", methods=["GET", "POST"])
def login():
    """Login jefe/auxiliar → inicioAdmin.html"""
    if request.method == "POST":
        usuario    = (request.form.get("usuario") or "").strip()
        contrasena = (request.form.get("contrasena") or "").strip()

        if not usuario and not contrasena:
            flash("Ingresa tu usuario y contraseña")
        elif usuario and not contrasena:
            flash("Ingresa tu contraseña")
        elif contrasena and not usuario:
            flash("Ingresa tu usuario")
        else:
            # Si quieres solo letras en 'usuario', deja esta regla:
            if usuario and not NAME_RE.match(usuario):
                flash("El usuario solo puede contener letras")
                return render_template("inicioAdmin.html")

            tipo = validar_usuario(usuario, contrasena)
            if tipo is None:
                flash("Verifica tu usuario y contraseña" if usuario_existe(usuario)
                     else "El usuario y contraseña que ingresaste no existen")
            else:
                return redirect(url_for("interface_admin" if tipo == 0 else "interface_aux"))

    return render_template("inicioAdmin.html")

@app.route("/interface_admin")
def interface_admin():
    return render_template("interfaceAdmin.html")

@app.route("/interface_aux")
def interface_aux():
    return render_template("interfaceAux.html")

@app.route("/registro_alumno", methods=["GET", "POST"])
def registro_alumno():
    """Registro de alumnos → inicioAlumno.html"""
    if request.method == "POST":
        nombre         = (request.form.get("nombre") or "").strip()
        numero_control = (request.form.get("numero_control") or "").strip()
        correo         = (request.form.get("correo") or "").strip()
        especialidad   = (request.form.get("carrera") or "").strip()
        semestre       = (request.form.get("semestre") or "").strip()

        # Requeridos
        if not (nombre and numero_control and correo and especialidad and semestre):
            flash("Completa los campos faltantes", "error")
            return render_template("inicioAlumno.html")

        # Formatos exactos de los casos de prueba
        if not NAME_RE.match(nombre) or not NC_RE.match(numero_control):
            flash("Verifica el formato de los datos ingresados", "error")
            return render_template("inicioAlumno.html")

        if not MAIL_RE.match(correo):
            flash("Verifica el formato del correo institucional", "error")
            return render_template("inicioAlumno.html")

        # Insert
        resultado = registrar_alumno(nombre, numero_control, correo, especialidad, semestre)
        if resultado == "duplicado":
            flash("Ya estás registrado", "error")
        elif resultado == "ok":
            flash("Te has registrado con éxito", "success")
        else:
            flash("Error al registrar alumno. Intenta de nuevo.", "error")

    return render_template("inicioAlumno.html")

# ===================== MAIN =====================
if __name__ == "__main__":
    app.run(debug=True)
