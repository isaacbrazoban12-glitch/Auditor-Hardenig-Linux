#!/usr/bin/env python3
"""
Auditor de hardening para Linux (universal)

Funciona en Rocky/RHEL/AlmaLinux/CentOS/Fedora, Ubuntu/Debian, openSUSE y
otras distribuciones: detecta qué herramientas tiene el servidor (dnf, apt,
firewalld, ufw, SELinux, AppArmor...) y usa las correctas.

Revisa 5 controles básicos, muestra PASS/FAIL (o N/A si no aplica), calcula
una nota de 0 a 100 y genera un reporte HTML (reporte.html).

Uso:  sudo python3 auditor.py
"""

import http.server
import os
import shutil
import socket
import socketserver
import subprocess
import sys
from datetime import datetime


# --- Herramientas que usan los 5 chequeos ---
def ejecutar(comando, timeout=60):
    """Corre un comando y devuelve (salida, codigo). Si falla o tarda, codigo -1."""
    try:
        r = subprocess.run(comando, shell=True, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, universal_newlines=True,
                           timeout=timeout)
        return r.stdout.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", -1


def existe(programa):
    return shutil.which(programa) is not None


def nombre_distro():
    try:
        with open("/etc/os-release") as f:
            for linea in f:
                if linea.startswith("PRETTY_NAME="):
                    return linea.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return "Linux (distribucion desconocida)"


resultados = []


def agregar(nombre, estado, detalle, solucion):
    """estado puede ser PASS, FAIL o N/A (no aplica / no se pudo verificar)."""
    print(f"[{estado}] {nombre}: {detalle}")
    resultados.append((nombre, estado, detalle, solucion))


if os.geteuid() != 0:
    print("Este auditor necesita permisos de administrador. Ejecutalo con: sudo python3 auditor.py")
    sys.exit(1)

distro = nombre_distro()
print(f"Auditando: {distro} ({socket.gethostname()})\n")

# --- 1. Root por SSH ---
if not existe("sshd") and not os.path.exists("/etc/ssh/sshd_config"):
    agregar("Root por SSH", "N/A", "SSH no esta instalado en este servidor", "")
else:
    valor = ""
    salida, _ = ejecutar("sshd -T 2>/dev/null | grep -i '^permitrootlogin'")
    if salida:
        valor = salida.split()[-1].lower()
    else:
        try:
            with open("/etc/ssh/sshd_config") as f:
                for linea in f:
                    linea = linea.strip()
                    if linea.lower().startswith("permitrootlogin"):
                        valor = linea.split()[1].lower()
        except (OSError, IndexError):
            pass
    if not valor:
        valor = "prohibit-password (por defecto)"
    agregar("Root por SSH", "PASS" if not valor.startswith("yes") else "FAIL",
            f"PermitRootLogin = {valor}",
            "Pon PermitRootLogin no en /etc/ssh/sshd_config y reinicia sshd")

# --- 2. Puertos abiertos (TCP, sin contar los que solo escuchan en localhost) ---
if existe("ss"):
    salida, _ = ejecutar("ss -tln | tail -n +2")
elif existe("netstat"):
    salida, _ = ejecutar("netstat -tln | tail -n +3")
else:
    salida = None

if salida is None:
    agregar("Puertos abiertos", "N/A", "No hay ss ni netstat para revisar los puertos", "")
else:
    puertos = set()
    for linea in salida.splitlines():
        cols = linea.split()
        if len(cols) < 4:
            continue
        local = cols[3]
        if local.startswith("127.") or local.startswith("[::1]") or local.startswith("::1"):
            continue
        puertos.add(local.rsplit(":", 1)[-1])
    lista = ", ".join(sorted(puertos, key=lambda p: int(p) if p.isdigit() else 0))
    agregar("Puertos abiertos", "PASS" if len(puertos) <= 3 else "FAIL",
            f"{len(puertos)} puertos TCP expuestos" + (f" ({lista})" if lista else ""),
            "Cierra los servicios que no uses (systemctl disable --now servicio)")

# --- 3. Firewall (firewalld, ufw, nftables o iptables) ---
firewall = None
if existe("firewall-cmd"):
    s, _ = ejecutar("systemctl is-active firewalld")
    if s == "active":
        firewall = "firewalld"
if not firewall and existe("ufw"):
    s, _ = ejecutar("LC_ALL=C ufw status")
    if "Status: active" in s:
        firewall = "ufw"
if not firewall and existe("nft"):
    s, _ = ejecutar("nft list ruleset")
    if "hook input" in s and ("drop" in s or "reject" in s):
        firewall = "nftables"
if not firewall and existe("iptables"):
    s, _ = ejecutar("iptables -S")
    if "-P INPUT DROP" in s or "-A INPUT" in s:
        firewall = "iptables"

if firewall:
    agregar("Firewall", "PASS", f"Activo ({firewall})", "")
else:
    agregar("Firewall", "FAIL", "No se detecto ningun firewall activo",
            "Activa uno: sudo systemctl enable --now firewalld (RHEL/Rocky) "
            "o sudo ufw enable (Ubuntu/Debian)")

# --- 4. Control de acceso obligatorio (SELinux o AppArmor) ---
if existe("getenforce"):
    s, _ = ejecutar("getenforce")
    agregar("SELinux / AppArmor", "PASS" if s == "Enforcing" else "FAIL",
            f"SELinux esta en {s}",
            "Ejecuta: sudo setenforce 1 y edita /etc/selinux/config a SELINUX=enforcing")
else:
    apparmor = False
    if existe("aa-status"):
        _, c = ejecutar("aa-status --enabled")
        apparmor = (c == 0)
    elif os.path.isdir("/sys/kernel/security/apparmor"):
        apparmor = True
    if apparmor:
        agregar("SELinux / AppArmor", "PASS", "AppArmor esta activo", "")
    else:
        agregar("SELinux / AppArmor", "FAIL", "No se detecto SELinux ni AppArmor activos",
                "Instala y activa AppArmor (Ubuntu/Debian) o SELinux (RHEL/Rocky)")

# --- 5. Actualizaciones pendientes (apt, dnf, yum o zypper) ---
print("Revisando actualizaciones (puede tardar un poco)...")
if existe("apt-get"):
    s, c = ejecutar("apt list --upgradable 2>/dev/null", timeout=180)
    n = len([l for l in s.splitlines() if "[upgradable" in l])
    if c == -1:
        agregar("Actualizaciones", "N/A", "No se pudo verificar (tardo demasiado)", "")
    else:
        agregar("Actualizaciones", "PASS" if n == 0 else "FAIL",
                "Sistema al dia" if n == 0 else f"{n} paquetes por actualizar",
                "Ejecuta: sudo apt update && sudo apt upgrade -y")
elif existe("dnf") or existe("yum"):
    gestor = "dnf" if existe("dnf") else "yum"
    _, c = ejecutar(f"{gestor} check-update -q", timeout=180)
    if c == 0:
        agregar("Actualizaciones", "PASS", "Sistema al dia", "")
    elif c == 100:
        agregar("Actualizaciones", "FAIL", "Hay actualizaciones pendientes",
                f"Ejecuta: sudo {gestor} update -y")
    else:
        agregar("Actualizaciones", "N/A",
                "No se pudo verificar (tardo demasiado o no hay conexion)", "")
elif existe("zypper"):
    s, c = ejecutar("zypper -q --non-interactive list-updates", timeout=180)
    n = len([l for l in s.splitlines() if l.startswith("v ")])
    if c == -1:
        agregar("Actualizaciones", "N/A", "No se pudo verificar (tardo demasiado)", "")
    else:
        agregar("Actualizaciones", "PASS" if n == 0 else "FAIL",
                "Sistema al dia" if n == 0 else f"{n} paquetes por actualizar",
                "Ejecuta: sudo zypper update -y")
else:
    agregar("Actualizaciones", "N/A", "Gestor de paquetes no reconocido", "")

# --- Nota final (los controles N/A no cuentan) ---
evaluados = [r for r in resultados if r[1] != "N/A"]
pasaron = len([r for r in evaluados if r[1] == "PASS"])
nota = int(pasaron / len(evaluados) * 100) if evaluados else 0
print(f"\nNota de seguridad: {nota}/100")

# --- Reporte HTML ---
colores = {"PASS": "#2ecc71", "FAIL": "#e74c3c", "N/A": "#95a5a6"}
filas = ""
for nombre, estado, detalle, solucion in resultados:
    corregir = solucion if estado == "FAIL" else ""
    filas += (f"<tr><td>{nombre}</td>"
              f"<td style='background:{colores[estado]};color:white;text-align:center'>{estado}</td>"
              f"<td>{detalle}</td><td>{corregir}</td></tr>")

html = f"""<html><head><meta charset='utf-8'><title>Auditoria</title></head>
<body style='font-family:sans-serif;margin:40px'>
<h1>Auditoria de hardening</h1>
<p>Servidor: {socket.gethostname()} | Sistema: {distro}</p>
<p>Fecha: {datetime.now():%Y-%m-%d %H:%M} | <b>Nota: {nota}/100</b></p>
<table border='1' cellpadding='8' style='border-collapse:collapse'>
<tr><th>Control</th><th>Estado</th><th>Detalle</th><th>Como corregir</th></tr>
{filas}</table></body></html>"""

with open("reporte.html", "w", encoding="utf-8") as f:
    f.write(html)
print("Reporte guardado en reporte.html")

# --- Ver el reporte desde otro equipo (opcional) ---
try:
    resp = input("Quieres ver el reporte desde otro equipo? (s/n): ")
except EOFError:
    resp = "n"

if resp.lower() == "s":
    os.makedirs("reporte_web", exist_ok=True)
    shutil.copy("reporte.html", "reporte_web/reporte.html")
    os.chdir("reporte_web")

    if firewall == "firewalld":
        ejecutar("firewall-cmd --add-port=8000/tcp")
    elif firewall == "ufw":
        ejecutar("ufw allow 8000/tcp")

    for ip in ejecutar("hostname -I")[0].split():
        print(f"Abre en el navegador: http://{ip}:8000/reporte.html")
    print("Presiona Ctrl+C para detener.")

    socketserver.TCPServer.allow_reuse_address = True
    try:
        with socketserver.TCPServer(("", 8000), http.server.SimpleHTTPRequestHandler) as s:
            s.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if firewall == "firewalld":
            ejecutar("firewall-cmd --remove-port=8000/tcp")
        elif firewall == "ufw":
            ejecutar("ufw delete allow 8000/tcp")
        print("Servidor detenido.")
