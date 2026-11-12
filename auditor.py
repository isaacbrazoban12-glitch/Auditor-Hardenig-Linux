#!/usr/bin/env python3
"""
Auditor de hardening para Linux (probado en Rocky Linux 9)

Revisa 5 controles básicos de seguridad, muestra PASS/FAIL en pantalla,
calcula una nota de 0 a 100 y genera un reporte en HTML (reporte.html).

Uso:  sudo python3 auditor.py
"""

import subprocess
from datetime import datetime


# --- Herramientas que usan los 5 chequeos ---
def ejecutar(comando):
    r = subprocess.run(comando, shell=True, capture_output=True, text=True)
    return r.stdout.strip(), r.returncode


resultados = []


def agregar(nombre, ok, detalle, solucion):
    estado = "PASS" if ok else "FAIL"
    print(f"[{estado}] {nombre}: {detalle}")
    resultados.append((nombre, ok, detalle, solucion))


# --- 1. Root por SSH ---
salida, _ = ejecutar("sshd -T | grep -i '^permitrootlogin'")
valor = salida.split()[-1] if salida else "desconocido"
agregar("Root por SSH", valor != "yes", f"PermitRootLogin = {valor}",
        "Pon PermitRootLogin no en /etc/ssh/sshd_config y reinicia sshd")

# --- 2. Puertos abiertos (TCP) ---
salida, _ = ejecutar("ss -tln | tail -n +2")
puertos = [l for l in salida.splitlines() if l.strip()]
agregar("Puertos abiertos", len(puertos) <= 3, f"{len(puertos)} puertos TCP escuchando",
        "Cierra los servicios que no uses (systemctl disable --now servicio)")

# --- 3. Firewall ---
salida, _ = ejecutar("systemctl is-active firewalld")
agregar("Firewall", salida == "active", f"firewalld esta {salida}",
        "Ejecuta: sudo systemctl enable --now firewalld")

# --- 4. SELinux ---
salida, _ = ejecutar("getenforce")
agregar("SELinux", salida == "Enforcing", f"SELinux esta en {salida}",
        "Ejecuta: sudo setenforce 1 y edita /etc/selinux/config a SELINUX=enforcing")

# --- 5. Actualizaciones (con aviso y límite de 3 minutos) ---
print("Revisando actualizaciones (puede tardar un poco)...")
try:
    r = subprocess.run("dnf check-update -q", shell=True, capture_output=True,
                       text=True, timeout=180)
    codigo = r.returncode
    agregar("Actualizaciones", codigo == 0,
            "Sistema al dia" if codigo == 0 else "Hay actualizaciones pendientes",
            "Ejecuta: sudo dnf update -y")
except subprocess.TimeoutExpired:
    agregar("Actualizaciones", False, "No se pudo verificar (tardó demasiado)",
            "Revisa tu conexión a internet y vuelve a correr el auditor")

# --- Nota final ---
nota = int(sum(1 for r in resultados if r[1]) / len(resultados) * 100)
print(f"\nNota de seguridad: {nota}/100")

# --- Reporte HTML ---
filas = ""
for nombre, ok, detalle, solucion in resultados:
    color = "#2ecc71" if ok else "#e74c3c"
    estado = "PASS" if ok else "FAIL"
    corregir = "" if ok else solucion
    filas += (f"<tr><td>{nombre}</td>"
              f"<td style='background:{color};color:white;text-align:center'>{estado}</td>"
              f"<td>{detalle}</td><td>{corregir}</td></tr>")

html = f"""<html><head><meta charset='utf-8'><title>Auditoria</title></head>
<body style='font-family:sans-serif;margin:40px'>
<h1>Auditoria de hardening</h1>
<p>Fecha: {datetime.now():%Y-%m-%d %H:%M} | <b>Nota: {nota}/100</b></p>
<table border='1' cellpadding='8' style='border-collapse:collapse'>
<tr><th>Control</th><th>Estado</th><th>Detalle</th><th>Como corregir</th></tr>
{filas}</table></body></html>"""

with open("reporte.html", "w", encoding="utf-8") as f:
    f.write(html)
print("Reporte guardado en reporte.html")

# --- Ver el reporte desde otro equipo (opcional) ---
import http.server
import os
import shutil
import socketserver

resp = input("¿Quieres ver el reporte desde otro equipo? (s/n): ")
if resp.lower() == "s":
    os.makedirs("reporte_web", exist_ok=True)
    shutil.copy("reporte.html", "reporte_web/reporte.html")
    os.chdir("reporte_web")
    ejecutar("firewall-cmd --add-port=8000/tcp")
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
        ejecutar("firewall-cmd --remove-port=8000/tcp")
        print("Servidor detenido.")
