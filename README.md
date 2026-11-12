# Auditor de hardening para Linux

Script en Python que revisa la seguridad básica de un servidor Linux y genera un reporte con una nota de 0 a 100. Detecta la distribución y usa las herramientas que tenga el servidor, así que funciona en Rocky/RHEL/AlmaLinux/CentOS/Fedora, Ubuntu/Debian y openSUSE.

## Qué verifica

| Control | PASS si... |
|---|---|
| Root por SSH | `PermitRootLogin` no es `yes` |
| Puertos abiertos | hay 3 o menos puertos TCP expuestos (no cuenta localhost) |
| Firewall | hay uno activo: firewalld, ufw, nftables o iptables |
| SELinux / AppArmor | SELinux en `Enforcing` o AppArmor activo |
| Actualizaciones | no hay parches pendientes (dnf, yum, apt o zypper) |

Si un control no aplica o no se puede verificar, sale como `N/A` y no cuenta para la nota.

## Uso

```bash
sudo python3 auditor.py
```

Muestra PASS/FAIL por cada control, la nota final y crea `reporte.html` con la tabla de resultados y cómo corregir cada fallo. Al final ofrece servir el reporte para verlo desde otro equipo de la red.

## Requisitos

- Cualquier Linux con systemd
- Python 3.6 o superior
- Ejecutar con `sudo`

Úsalo solo en servidores propios o con autorización.
