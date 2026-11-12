#!/usr/bin/env python3
"""
Auditor de hardening para Linux (universal)

Funciona en Rocky/RHEL/AlmaLinux/CentOS/Fedora, Ubuntu/Debian, openSUSE y
otras distribuciones: detecta que herramientas tiene el servidor (dnf, apt,
firewalld, ufw, nftables, SELinux, AppArmor...) y usa las correctas.

Revisa 10 controles, muestra PASS/FAIL (o N/A si no aplica), calcula una nota
de 0 a 100 ponderada por gravedad y genera un reporte HTML (y JSON si se pide).

Uso:  sudo python3 auditor.py            (ver opciones con --help)
"""

import argparse
import glob
import html
import http.server
import json
import os
import re
import shutil
import socket
import socketserver
import subprocess
import sys
import tempfile
import time
from datetime import datetime

VERSION = "2.0"

# Peso de cada gravedad en la nota final
PESOS = {"Alta": 3, "Media": 2, "Baja": 1}


# --------------------------------------------------------------------------
# Utilidades
# --------------------------------------------------------------------------
def ejecutar(comando, timeout=60):
    """Corre un comando y devuelve (salida, codigo). Si falla o tarda, codigo -1.

    Siempre fuerza LC_ALL=C para que la salida salga en ingles y se pueda
    analizar igual en un servidor en espanol que en uno en ingles.
    """
    entorno = dict(os.environ, LC_ALL="C", LANG="C")
    try:
        r = subprocess.run(comando, shell=True, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, universal_newlines=True,
                           timeout=timeout, env=entorno)
        return r.stdout.strip(), r.returncode
    except (subprocess.TimeoutExpired, OSError):
        return "", -1


def existe(programa):
    return shutil.which(programa) is not None


def leer(ruta):
    """Devuelve el contenido de un archivo o None si no se puede leer."""
    try:
        with open(ruta, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return None


def servicio_activo(nombre):
    s, _ = ejecutar(f"systemctl is-active {nombre}")
    return s == "active"


def nombre_distro():
    contenido = leer("/etc/os-release") or ""
    for linea in contenido.splitlines():
        if linea.startswith("PRETTY_NAME="):
            return linea.split("=", 1)[1].strip().strip('"')
    return "Linux (distribucion desconocida)"


class Resultado:
    def __init__(self, nombre, gravedad, estado, detalle, solucion=""):
        self.nombre = nombre
        self.gravedad = gravedad      # Alta, Media o Baja
        self.estado = estado          # PASS, FAIL o N/A
        self.detalle = detalle
        self.solucion = solucion

    def a_dict(self):
        return {"control": self.nombre, "gravedad": self.gravedad,
                "estado": self.estado, "detalle": self.detalle,
                "solucion": self.solucion if self.estado == "FAIL" else ""}


# --------------------------------------------------------------------------
# Lectura de la configuracion de SSH
# --------------------------------------------------------------------------
def config_sshd_desde_archivo(ruta="/etc/ssh/sshd_config", _vistos=None):
    """Lee sshd_config como lo hace sshd: gana la PRIMERA aparicion de cada
    opcion, se siguen los Include y se para en el primer bloque Match."""
    if _vistos is None:
        _vistos = set()
    config = {}
    if ruta in _vistos:
        return config, False
    _vistos.add(ruta)
    contenido = leer(ruta)
    if contenido is None:
        return config, False
    for linea in contenido.splitlines():
        linea = linea.split("#", 1)[0].strip()
        if not linea:
            continue
        partes = linea.replace("=", " ", 1).split()
        clave = partes[0].lower()
        valor = " ".join(partes[1:])
        if clave == "match":
            return config, True           # lo que sigue ya no es global
        if clave == "include":
            for patron in partes[1:]:
                if not os.path.isabs(patron):
                    patron = os.path.join("/etc/ssh", patron)
                for incluido in sorted(glob.glob(patron)):
                    sub, hubo_match = config_sshd_desde_archivo(incluido, _vistos)
                    for k, v in sub.items():
                        config.setdefault(k, v)
                    if hubo_match:
                        return config, True
            continue
        config.setdefault(clave, valor.lower())
    return config, False


def config_sshd():
    """Configuracion efectiva de sshd. Usa 'sshd -T' (lo mas fiable) y si
    falla lee los archivos a mano."""
    for sshd in ("sshd", "/usr/sbin/sshd"):
        salida, codigo = ejecutar(f"{sshd} -T 2>/dev/null")
        if codigo == 0 and salida:
            config = {}
            for linea in salida.splitlines():
                partes = linea.split(None, 1)
                if len(partes) == 2:
                    config[partes[0].lower()] = partes[1].strip().lower()
            return config, "sshd -T"
    config, _ = config_sshd_desde_archivo()
    return config, "sshd_config"


def ssh_instalado():
    return (existe("sshd") or os.path.exists("/usr/sbin/sshd")
            or os.path.exists("/etc/ssh/sshd_config"))


# --------------------------------------------------------------------------
# Controles
# --------------------------------------------------------------------------
def control_root_ssh(ssh):
    nombre = "Root por SSH"
    if ssh is None:
        return Resultado(nombre, "Alta", "N/A", "SSH no esta instalado en este servidor")
    config, fuente = ssh
    valor = config.get("permitrootlogin", "prohibit-password")
    estado = "FAIL" if valor == "yes" else "PASS"
    return Resultado(nombre, "Alta", estado, f"PermitRootLogin = {valor} (segun {fuente})",
                     "Pon 'PermitRootLogin no' en /etc/ssh/sshd_config y ejecuta "
                     "sudo systemctl restart sshd")


def control_password_ssh(ssh):
    nombre = "Contrasenas por SSH"
    if ssh is None:
        return Resultado(nombre, "Media", "N/A", "SSH no esta instalado en este servidor")
    config, fuente = ssh
    valor = config.get("passwordauthentication", "yes")
    kbd = config.get("kbdinteractiveauthentication",
                     config.get("challengeresponseauthentication", "no"))
    usa_pam = config.get("usepam", "no") == "yes"
    permite = valor == "yes" or (kbd == "yes" and usa_pam)
    detalle = f"PasswordAuthentication = {valor}"
    if kbd == "yes" and usa_pam:
        detalle += ", KbdInteractiveAuthentication = yes con PAM"
    return Resultado(nombre, "Media", "FAIL" if permite else "PASS",
                     detalle + f" (segun {fuente})",
                     "Usa llaves SSH y pon 'PasswordAuthentication no' y "
                     "'KbdInteractiveAuthentication no' en /etc/ssh/sshd_config")


def control_anti_fuerza_bruta(ssh):
    nombre = "Proteccion contra fuerza bruta"
    if ssh is None:
        return Resultado(nombre, "Baja", "N/A", "SSH no esta instalado en este servidor")
    for servicio in ("fail2ban", "sshguard", "crowdsec"):
        if servicio_activo(servicio):
            return Resultado(nombre, "Baja", "PASS", f"{servicio} esta activo")
    return Resultado(nombre, "Baja", "FAIL", "No hay fail2ban, sshguard ni crowdsec activos",
                     "Instala fail2ban (sudo apt install fail2ban / sudo dnf install "
                     "fail2ban) y activalo con sudo systemctl enable --now fail2ban")


def puertos_expuestos():
    """Devuelve el conjunto de puertos TCP que escuchan fuera de localhost,
    o None si no hay ss ni netstat."""
    if existe("ss"):
        salida, _ = ejecutar("ss -tln | tail -n +2")
    elif existe("netstat"):
        salida, _ = ejecutar("netstat -tln | tail -n +3")
    else:
        return None
    return analizar_puertos(salida)


def analizar_puertos(salida):
    puertos = set()
    for linea in salida.splitlines():
        cols = linea.split()
        if len(cols) < 4:
            continue
        local = cols[3]
        direccion, _, puerto = local.rpartition(":")
        direccion = direccion.strip("[]").split("%")[0]
        if (direccion.startswith("127.") or direccion == "::1"
                or direccion.startswith("::ffff:127.")):
            continue
        if puerto.isdigit():
            puertos.add(int(puerto))
    return puertos


def control_puertos(maximo):
    nombre = "Puertos abiertos"
    puertos = puertos_expuestos()
    if puertos is None:
        return Resultado(nombre, "Media", "N/A", "No hay ss ni netstat para revisar los puertos")
    lista = ", ".join(str(p) for p in sorted(puertos))
    detalle = f"{len(puertos)} puertos TCP escuchando fuera de localhost"
    if lista:
        detalle += f" ({lista})"
    return Resultado(nombre, "Media", "PASS" if len(puertos) <= maximo else "FAIL",
                     detalle + f"; maximo permitido: {maximo}",
                     "Cierra los servicios que no uses (sudo systemctl disable --now "
                     "servicio) o haz que escuchen solo en 127.0.0.1")


def nft_bloquea_entrada(ruleset):
    """True si alguna cadena con 'hook input' tiene policy drop o reglas
    drop/reject. Se mira cadena por cadena, no todo el texto junto."""
    for bloque in re.split(r"\n\s*chain\s+", "\n" + ruleset)[1:]:
        if "hook input" not in bloque:
            continue
        if re.search(r"policy\s+drop", bloque) or re.search(r"\b(drop|reject)\b", bloque):
            return True
    return False


def iptables_bloquea_entrada(reglas):
    """True si INPUT tiene policy DROP o alguna regla DROP/REJECT, directa o
    en una cadena a la que salta INPUT."""
    if re.search(r"^-P INPUT (DROP|REJECT)", reglas, re.M):
        return True
    cadenas = {"INPUT"}
    for linea in reglas.splitlines():
        m = re.match(r"-A INPUT .*-j (\S+)", linea)
        if m and m.group(1) not in ("ACCEPT", "DROP", "REJECT", "RETURN", "LOG"):
            cadenas.add(m.group(1))
    for linea in reglas.splitlines():
        m = re.match(r"-A (\S+) .*-j (DROP|REJECT)\b", linea)
        if m and m.group(1) in cadenas:
            return True
    return False


def detectar_firewall():
    if existe("firewall-cmd") and servicio_activo("firewalld"):
        return "firewalld"
    if existe("ufw"):
        s, _ = ejecutar("ufw status")
        if "Status: active" in s:
            return "ufw"
    if existe("nft"):
        s, c = ejecutar("nft list ruleset")
        if c == 0 and nft_bloquea_entrada(s):
            return "nftables"
    if existe("iptables"):
        s, c = ejecutar("iptables -S")
        if c == 0 and iptables_bloquea_entrada(s):
            return "iptables"
    return None


def control_firewall(firewall):
    nombre = "Firewall"
    if firewall:
        return Resultado(nombre, "Alta", "PASS", f"Activo y filtrando entrada ({firewall})")
    return Resultado(nombre, "Alta", "FAIL",
                     "No se detecto ningun firewall que bloquee trafico de entrada",
                     "Activa uno: sudo systemctl enable --now firewalld (RHEL/Rocky) "
                     "o sudo ufw allow OpenSSH && sudo ufw enable (Ubuntu/Debian)")


def estado_selinux():
    if existe("getenforce"):
        s, c = ejecutar("getenforce")
        if c == 0 and s:
            return s
    valor = leer("/sys/fs/selinux/enforce")
    if valor is not None:
        return "Enforcing" if valor.strip() == "1" else "Permissive"
    return None


def apparmor_activo():
    if (leer("/sys/module/apparmor/parameters/enabled") or "").strip() != "Y":
        return False
    if existe("aa-status"):
        _, c = ejecutar("aa-status --enabled")
        return c == 0
    return True


def control_mac():
    nombre = "SELinux / AppArmor"
    selinux = estado_selinux()
    if selinux == "Enforcing":
        return Resultado(nombre, "Media", "PASS", "SELinux esta en Enforcing")
    if apparmor_activo():
        return Resultado(nombre, "Media", "PASS", "AppArmor esta activo")
    if selinux:
        return Resultado(nombre, "Media", "FAIL", f"SELinux esta en {selinux}",
                         "Ejecuta sudo setenforce 1 y pon SELINUX=enforcing en "
                         "/etc/selinux/config")
    return Resultado(nombre, "Media", "FAIL", "No se detecto SELinux ni AppArmor activos",
                     "Instala y activa AppArmor (Ubuntu/Debian/SUSE) o SELinux (RHEL/Rocky)")


def dias_desde(ruta):
    try:
        return (time.time() - os.path.getmtime(ruta)) / 86400
    except OSError:
        return None


def control_actualizaciones(refrescar):
    nombre = "Actualizaciones"
    if existe("apt-get"):
        if refrescar:
            ejecutar("apt-get update -q", timeout=300)
        s, c = ejecutar("apt-get -s -q upgrade", timeout=180)
        if c != 0:
            return Resultado(nombre, "Alta", "N/A", "No se pudo verificar con apt-get")
        n = len([l for l in s.splitlines() if l.startswith("Inst ")])
        detalle = "Sistema al dia" if n == 0 else f"{n} paquetes por actualizar"
        antig = dias_desde("/var/cache/apt/pkgcache.bin")
        if antig is None:
            antig = dias_desde("/var/lib/apt/lists")
        if antig is not None and antig > 7 and not refrescar:
            detalle += (f" (la lista de paquetes tiene {int(antig)} dias; "
                        "usa --refrescar para un resultado fiable)")
        return Resultado(nombre, "Alta", "PASS" if n == 0 else "FAIL", detalle,
                         "Ejecuta: sudo apt update && sudo apt upgrade -y")
    if existe("dnf") or existe("yum"):
        gestor = "dnf" if existe("dnf") else "yum"
        _, c = ejecutar(f"{gestor} check-update -q", timeout=300)
        if c == 0:
            return Resultado(nombre, "Alta", "PASS", "Sistema al dia")
        if c == 100:
            return Resultado(nombre, "Alta", "FAIL", "Hay actualizaciones pendientes",
                             f"Ejecuta: sudo {gestor} upgrade -y")
        return Resultado(nombre, "Alta", "N/A",
                         "No se pudo verificar (tardo demasiado o no hay conexion)")
    if existe("zypper"):
        if refrescar:
            ejecutar("zypper -q --non-interactive refresh", timeout=300)
        s, c = ejecutar("zypper -q --non-interactive list-updates", timeout=180)
        if c != 0:
            return Resultado(nombre, "Alta", "N/A", "No se pudo verificar con zypper")
        n = len([l for l in s.splitlines() if l.startswith("v ")])
        return Resultado(nombre, "Alta", "PASS" if n == 0 else "FAIL",
                         "Sistema al dia" if n == 0 else f"{n} paquetes por actualizar",
                         "Ejecuta: sudo zypper update -y")
    return Resultado(nombre, "Alta", "N/A", "Gestor de paquetes no reconocido")


def control_actualizaciones_auto():
    nombre = "Actualizaciones automaticas"
    if existe("apt-get"):
        conf = ""
        for ruta in sorted(glob.glob("/etc/apt/apt.conf.d/*")):
            conf += (leer(ruta) or "") + "\n"
        activo = re.search(r'APT::Periodic::Unattended-Upgrade\s+"1"', conf)
        if existe("unattended-upgrade") and activo:
            return Resultado(nombre, "Baja", "PASS", "unattended-upgrades esta activo")
        return Resultado(nombre, "Baja", "FAIL", "unattended-upgrades no esta activo",
                         "Ejecuta: sudo apt install unattended-upgrades && "
                         "sudo dpkg-reconfigure -plow unattended-upgrades")
    if existe("dnf"):
        for timer in ("dnf-automatic.timer", "dnf-automatic-install.timer",
                      "dnf5-automatic.timer"):
            if servicio_activo(timer):
                return Resultado(nombre, "Baja", "PASS", f"{timer} esta activo")
        return Resultado(nombre, "Baja", "FAIL", "dnf-automatic no esta activo",
                         "Ejecuta: sudo dnf install dnf-automatic && "
                         "sudo systemctl enable --now dnf-automatic.timer")
    return Resultado(nombre, "Baja", "N/A", "No se revisa en este gestor de paquetes")


def control_uid0():
    nombre = "Cuentas con UID 0"
    contenido = leer("/etc/passwd")
    if contenido is None:
        return Resultado(nombre, "Alta", "N/A", "No se pudo leer /etc/passwd")
    extra = [l.split(":")[0] for l in contenido.splitlines()
             if l.count(":") >= 3 and l.split(":")[2] == "0" and l.split(":")[0] != "root"]
    if extra:
        return Resultado(nombre, "Alta", "FAIL",
                         "Otras cuentas con privilegios de root: " + ", ".join(extra),
                         "Revisa esas cuentas; si no son necesarias, borralas con "
                         "sudo userdel nombre")
    return Resultado(nombre, "Alta", "PASS", "Solo root tiene UID 0")


def control_contrasenas_vacias():
    nombre = "Cuentas sin contrasena"
    contenido = leer("/etc/shadow")
    if contenido is None:
        return Resultado(nombre, "Alta", "N/A", "No se pudo leer /etc/shadow")
    vacias = [l.split(":")[0] for l in contenido.splitlines()
              if l.count(":") >= 1 and l.split(":")[1] == ""]
    if vacias:
        return Resultado(nombre, "Alta", "FAIL",
                         "Cuentas que entran sin contrasena: " + ", ".join(vacias),
                         "Ponles contrasena (sudo passwd nombre) o bloqueala "
                         "(sudo passwd -l nombre)")
    return Resultado(nombre, "Alta", "PASS", "Todas las cuentas tienen contrasena o estan bloqueadas")


def calcular_nota(resultados):
    evaluados = [r for r in resultados if r.estado != "N/A"]
    total = sum(PESOS[r.gravedad] for r in evaluados)
    if not total:
        return 0
    obtenido = sum(PESOS[r.gravedad] for r in evaluados if r.estado == "PASS")
    return round(obtenido / total * 100)


# --------------------------------------------------------------------------
# Reportes
# --------------------------------------------------------------------------
COLORES = {"PASS": "#1e8e4e", "FAIL": "#c0392b", "N/A": "#7f8c8d"}


def generar_html(resultados, nota, info):
    e = html.escape
    filas = ""
    for r in resultados:
        filas += (f"<tr><td>{e(r.nombre)}</td><td>{e(r.gravedad)}</td>"
                  f"<td class='estado' style='background:{COLORES[r.estado]}'>{e(r.estado)}</td>"
                  f"<td>{e(r.detalle)}</td>"
                  f"<td>{e(r.solucion) if r.estado == 'FAIL' else ''}</td></tr>\n")
    color_nota = "#1e8e4e" if nota >= 80 else "#d68910" if nota >= 50 else "#c0392b"
    return f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Auditoria {e(info['servidor'])}</title>
<style>
 body{{font-family:system-ui,sans-serif;margin:32px;color:#222;background:#fafafa}}
 table{{border-collapse:collapse;width:100%;background:#fff}}
 th,td{{border:1px solid #ddd;padding:8px;text-align:left;vertical-align:top}}
 th{{background:#f0f0f0}}
 td.estado{{color:#fff;text-align:center;font-weight:bold}}
 .nota{{font-size:2em;font-weight:bold;color:{color_nota}}}
</style></head><body>
<h1>Auditoria de hardening</h1>
<p>Servidor: <b>{e(info['servidor'])}</b> | Sistema: {e(info['sistema'])}</p>
<p>Fecha: {e(info['fecha'])} | Auditor v{VERSION}</p>
<p class="nota">Nota: {nota}/100</p>
<table>
<tr><th>Control</th><th>Gravedad</th><th>Estado</th><th>Detalle</th><th>Como corregir</th></tr>
{filas}</table>
<p><small>La nota pondera por gravedad (Alta=3, Media=2, Baja=1). Los controles N/A no cuentan.</small></p>
</body></html>"""


# --------------------------------------------------------------------------
# Servir el reporte por la red (opcional)
# --------------------------------------------------------------------------
def usuario_sin_privilegios():
    """UID/GID a los que bajar antes de servir: el usuario que llamo a sudo
    o, si no hay, 'nobody'."""
    import pwd
    if os.environ.get("SUDO_UID") and os.environ.get("SUDO_UID") != "0":
        return int(os.environ["SUDO_UID"]), int(os.environ.get("SUDO_GID", os.environ["SUDO_UID"]))
    p = pwd.getpwnam("nobody")
    return p.pw_uid, p.pw_gid


def servir_reporte(ruta_reporte, firewall, ip, puerto):
    carpeta = tempfile.mkdtemp(prefix="reporte_web_")
    os.chmod(carpeta, 0o755)
    destino = os.path.join(carpeta, "reporte.html")
    shutil.copy(ruta_reporte, destino)
    os.chmod(destino, 0o644)

    socketserver.TCPServer.allow_reuse_address = True
    try:
        servidor = socketserver.TCPServer((ip, puerto), http.server.SimpleHTTPRequestHandler)
    except OSError as err:
        print(f"No se pudo abrir el puerto {puerto}: {err}. Prueba con --puerto otro_numero")
        shutil.rmtree(carpeta, ignore_errors=True)
        return

    abierto = False
    if firewall == "firewalld":
        abierto = ejecutar(f"firewall-cmd --add-port={puerto}/tcp")[1] == 0
    elif firewall == "ufw":
        abierto = ejecutar(f"ufw allow {puerto}/tcp")[1] == 0
    elif firewall:
        print(f"Aviso: con {firewall} tienes que abrir el puerto {puerto}/tcp a mano.")

    ips = [ip] if ip else ejecutar("hostname -I")[0].split()
    for direccion in ips:
        print(f"Abre en el navegador: http://{direccion}:{puerto}/reporte.html")
    print("Aviso: el reporte muestra los puntos debiles del servidor. "
          "Cualquiera en la red puede verlo mientras esto este abierto.")
    print("Presiona Ctrl+C para detener.")

    hijo = os.fork()
    if hijo == 0:
        # Proceso hijo: deja de ser root antes de atender peticiones
        try:
            uid, gid = usuario_sin_privilegios()
            os.setgroups([])
            os.setgid(gid)
            os.setuid(uid)
            os.chdir(carpeta)
            servidor.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            os._exit(0)

    servidor.server_close()
    try:
        os.waitpid(hijo, 0)
    except KeyboardInterrupt:
        try:
            os.kill(hijo, 15)
            os.waitpid(hijo, 0)
        except OSError:
            pass
    finally:
        if abierto and firewall == "firewalld":
            ejecutar(f"firewall-cmd --remove-port={puerto}/tcp")
        elif abierto and firewall == "ufw":
            ejecutar(f"ufw delete allow {puerto}/tcp")
        shutil.rmtree(carpeta, ignore_errors=True)
        print("\nServidor detenido.")


# --------------------------------------------------------------------------
# Programa principal
# --------------------------------------------------------------------------
def leer_argumentos(argv=None):
    p = argparse.ArgumentParser(
        description="Auditor de hardening para servidores Linux.",
        epilog="Usalo solo en servidores propios o con autorizacion.")
    p.add_argument("-o", "--salida", default="reporte.html",
                   help="archivo HTML del reporte (por defecto: reporte.html)")
    p.add_argument("--json", metavar="ARCHIVO",
                   help="guarda tambien los resultados en JSON ('-' para pantalla)")
    p.add_argument("--max-puertos", type=int, default=3,
                   help="puertos TCP expuestos permitidos (por defecto: 3)")
    p.add_argument("--refrescar", action="store_true",
                   help="actualiza la lista de paquetes antes de revisar (apt/zypper)")
    p.add_argument("--nota-minima", type=int, metavar="N",
                   help="sale con codigo 2 si la nota es menor que N (util en cron/CI)")
    grupo = p.add_mutually_exclusive_group()
    grupo.add_argument("--servir", action="store_true",
                       help="sirve el reporte por HTTP sin preguntar")
    grupo.add_argument("--no-servir", action="store_true",
                       help="no pregunta si servir el reporte")
    p.add_argument("--ip", default="",
                   help="IP en la que servir el reporte (por defecto: todas)")
    p.add_argument("--puerto", type=int, default=8000,
                   help="puerto para servir el reporte (por defecto: 8000)")
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return p.parse_args(argv)


def main(argv=None):
    args = leer_argumentos(argv)
    silencioso = args.json == "-"

    def mostrar(texto=""):
        if not silencioso:
            print(texto)

    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        print("Este auditor necesita permisos de administrador. "
              "Ejecutalo con: sudo python3 auditor.py", file=sys.stderr)
        return 1

    info = {"servidor": socket.gethostname(), "sistema": nombre_distro(),
            "fecha": datetime.now().strftime("%Y-%m-%d %H:%M")}
    mostrar(f"Auditando: {info['sistema']} ({info['servidor']})\n")

    ssh = config_sshd() if ssh_instalado() else None
    firewall = detectar_firewall()

    controles = [
        lambda: control_root_ssh(ssh),
        lambda: control_password_ssh(ssh),
        lambda: control_anti_fuerza_bruta(ssh),
        lambda: control_puertos(args.max_puertos),
        lambda: control_firewall(firewall),
        control_mac,
        lambda: control_actualizaciones(args.refrescar),
        control_actualizaciones_auto,
        control_uid0,
        control_contrasenas_vacias,
    ]

    resultados = []
    for control in controles:
        try:
            r = control()
        except Exception as err:        # un control roto no tumba la auditoria
            r = Resultado("Control con error", "Baja", "N/A", f"Error inesperado: {err}")
        mostrar(f"[{r.estado:4}] {r.nombre}: {r.detalle}")
        resultados.append(r)

    nota = calcular_nota(resultados)
    mostrar(f"\nNota de seguridad: {nota}/100")

    with open(args.salida, "w", encoding="utf-8") as f:
        f.write(generar_html(resultados, nota, info))
    mostrar(f"Reporte guardado en {args.salida}")

    if args.json:
        datos = dict(info, version=VERSION, nota=nota,
                     resultados=[r.a_dict() for r in resultados])
        texto = json.dumps(datos, ensure_ascii=False, indent=2)
        if args.json == "-":
            print(texto)
        else:
            with open(args.json, "w", encoding="utf-8") as f:
                f.write(texto)
            mostrar(f"JSON guardado en {args.json}")

    servir = args.servir
    if not servir and not args.no_servir and not silencioso and sys.stdin.isatty():
        try:
            servir = input("\nQuieres ver el reporte desde otro equipo? (s/n): ").strip().lower() == "s"
        except (EOFError, KeyboardInterrupt):
            print()
    if servir:
        servir_reporte(args.salida, firewall, args.ip, args.puerto)

    if args.nota_minima is not None and nota < args.nota_minima:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
