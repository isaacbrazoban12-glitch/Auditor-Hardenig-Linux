# Auditor de hardening para Linux

Script en Python que revisa la seguridad básica de un servidor Linux (probado en Rocky Linux 9) y genera un reporte con una nota de 0 a 100.

## Qué verifica

| Control | PASS si... |
|---|---|
| Root por SSH | `PermitRootLogin` no es `yes` |
| Puertos abiertos | hay 3 o menos puertos TCP escuchando |
| Firewall | `firewalld` está activo |
| SELinux | está en modo `Enforcing` |
| Actualizaciones | no hay parches pendientes |

## Uso

```bash
sudo python3 auditor.py
```

Muestra PASS/FAIL por cada control, la nota final y crea `reporte.html` con la tabla de resultados y cómo corregir cada fallo.

## Requisitos

- Rocky Linux / RHEL 9 (usa `firewalld`, `dnf` y SELinux)
- Python 3
- Ejecutar con `sudo`

Úsalo solo en servidores propios o con autorización.
