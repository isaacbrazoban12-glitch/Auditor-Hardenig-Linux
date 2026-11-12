# Auditor de hardening para Linux

Script en Python, sin dependencias, que revisa la seguridad básica de un servidor Linux y genera un reporte con una nota de 0 a 100. Detecta la distribución y usa las herramientas que tenga el servidor, así que funciona en Rocky/RHEL/AlmaLinux/CentOS/Fedora, Ubuntu/Debian y openSUSE.

## Qué verifica

| Control | Gravedad | PASS si... |
|---|---|---|
| Root por SSH | Alta | `PermitRootLogin` no es `yes` |
| Firewall | Alta | firewalld, ufw, nftables o iptables está activo **y bloquea** tráfico de entrada |
| Actualizaciones | Alta | no hay parches pendientes (apt, dnf, yum o zypper) |
| Cuentas con UID 0 | Alta | solo `root` tiene UID 0 |
| Cuentas sin contraseña | Alta | ninguna cuenta de `/etc/shadow` tiene la contraseña vacía |
| Contraseñas por SSH | Media | `PasswordAuthentication no` (y sin teclado interactivo con PAM) |
| Puertos abiertos | Media | hay 3 o menos puertos TCP expuestos (no cuenta localhost; configurable) |
| SELinux / AppArmor | Media | SELinux en `Enforcing` **o** AppArmor activo |
| Protección contra fuerza bruta | Baja | fail2ban, sshguard o crowdsec activo |
| Actualizaciones automáticas | Baja | unattended-upgrades o dnf-automatic activos |

La nota pondera por gravedad (Alta = 3, Media = 2, Baja = 1). Si un control no aplica o no se puede verificar, sale como `N/A` y no cuenta.

La configuración de SSH se lee con `sshd -T` (la configuración real, con los `Include` ya resueltos). Si eso falla, se leen los archivos como lo hace sshd: gana la primera aparición de cada opción y se siguen los `Include`.

## Uso

```bash
sudo python3 auditor.py
```

Muestra PASS/FAIL por cada control y la nota final, y crea `reporte.html` con la tabla de resultados y cómo corregir cada fallo.

Opciones útiles:

```bash
sudo python3 auditor.py --refrescar              # actualiza la lista de paquetes antes (apt/zypper)
sudo python3 auditor.py --json resultados.json   # guarda también un JSON
sudo python3 auditor.py --json - --no-servir     # solo JSON por pantalla (para scripts)
sudo python3 auditor.py --nota-minima 80         # sale con código 2 si la nota es menor (cron/CI)
sudo python3 auditor.py --max-puertos 5          # cambia el límite de puertos expuestos
sudo python3 auditor.py --servir --ip 192.168.1.10 --puerto 8080
```

`python3 auditor.py --help` muestra todas las opciones.

### Ver el reporte desde otro equipo

Al final el script pregunta si quieres servir el reporte por HTTP (o usa `--servir`). En ese caso:

- copia el reporte a una carpeta temporal y sirve solo esa carpeta;
- el servidor web **deja de ser root** antes de atender peticiones (pasa al usuario que ejecutó `sudo`, o a `nobody`);
- con firewalld o ufw abre el puerto solo mientras dura y lo cierra al pulsar Ctrl+C.

El reporte muestra los puntos débiles del servidor y va sin contraseña por HTTP: úsalo solo en una red de confianza. Si no, cópialo con `scp`.

## Tests

Los tests simulan las salidas de los comandos, así que se pueden correr en cualquier equipo (no hace falta Linux ni root):

```bash
python3 -m unittest discover tests
```

## Requisitos

- Cualquier Linux con systemd
- Python 3.6 o superior (solo la librería estándar)
- Ejecutar con `sudo`

Úsalo solo en servidores propios o con autorización.
