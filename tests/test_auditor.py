"""Tests del auditor. Simulan las salidas de los comandos, asi que se pueden
correr en cualquier equipo:  python3 -m unittest discover tests"""

import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import auditor  # noqa: E402


def falso_ejecutar(respuestas):
    """respuestas: {fragmento_del_comando: (salida, codigo)}"""
    def _ejecutar(comando, timeout=60):
        for fragmento, respuesta in respuestas.items():
            if fragmento in comando:
                return respuesta
        return "", 1
    return _ejecutar


class TestPuertos(unittest.TestCase):
    def test_ss_ignora_localhost(self):
        salida = (
            "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
            "LISTEN 0 128 [::]:22 [::]:*\n"
            "LISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:*\n"
            "LISTEN 0 128 [::1]:631 [::]:*\n"
            "LISTEN 0 128 *:443 *:*\n"
            "LISTEN 0 128 [::ffff:127.0.0.1]:9000 *:*\n")
        self.assertEqual(auditor.analizar_puertos(salida), {22, 443})

    def test_netstat(self):
        salida = ("tcp 0 0 0.0.0.0:80 0.0.0.0:* LISTEN\n"
                  "tcp6 0 0 :::22 :::* LISTEN\n"
                  "tcp 0 0 127.0.0.1:5432 0.0.0.0:* LISTEN\n")
        self.assertEqual(auditor.analizar_puertos(salida), {22, 80})


class TestFirewall(unittest.TestCase):
    def test_nft_con_drop_en_input(self):
        ruleset = ("table inet filter {\n\tchain input {\n"
                   "\t\ttype filter hook input priority filter; policy drop;\n"
                   "\t\ttcp dport 22 accept\n\t}\n}")
        self.assertTrue(auditor.nft_bloquea_entrada(ruleset))

    def test_nft_drop_solo_en_forward_no_cuenta(self):
        ruleset = ("table inet filter {\n\tchain input {\n"
                   "\t\ttype filter hook input priority filter; policy accept;\n\t}\n"
                   "\tchain forward {\n\t\ttype filter hook forward priority filter; policy drop;\n"
                   "\t}\n}")
        self.assertFalse(auditor.nft_bloquea_entrada(ruleset))

    def test_iptables_accept_todo_no_cuenta(self):
        self.assertFalse(auditor.iptables_bloquea_entrada(
            "-P INPUT ACCEPT\n-A INPUT -j ACCEPT\n"))

    def test_iptables_policy_drop(self):
        self.assertTrue(auditor.iptables_bloquea_entrada("-P INPUT DROP\n"))

    def test_iptables_drop_en_cadena_referenciada(self):
        reglas = ("-P INPUT ACCEPT\n-N MI_FILTRO\n-A INPUT -j MI_FILTRO\n"
                  "-A MI_FILTRO -p tcp --dport 23 -j DROP\n")
        self.assertTrue(auditor.iptables_bloquea_entrada(reglas))

    def test_iptables_drop_solo_en_forward_no_cuenta(self):
        self.assertFalse(auditor.iptables_bloquea_entrada(
            "-P INPUT ACCEPT\n-P FORWARD DROP\n-A FORWARD -j DROP\n"))


class TestSSH(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def escribir(self, nombre, texto):
        ruta = os.path.join(self.dir, nombre)
        with open(ruta, "w") as f:
            f.write(texto)
        return ruta

    def test_gana_la_primera_aparicion(self):
        ruta = self.escribir("sshd_config",
                             "PermitRootLogin no\nPermitRootLogin yes\n")
        config, _ = auditor.config_sshd_desde_archivo(ruta)
        self.assertEqual(config["permitrootlogin"], "no")

    def test_sigue_include_y_respeta_orden(self):
        self.escribir("50-cloud.conf", "PasswordAuthentication yes\n")
        ruta = self.escribir("sshd_config",
                             f"Include {self.dir}/*.conf\nPasswordAuthentication no\n")
        config, _ = auditor.config_sshd_desde_archivo(ruta)
        self.assertEqual(config["passwordauthentication"], "yes")

    def test_ignora_bloques_match_y_comentarios(self):
        ruta = self.escribir("sshd_config",
                             "#PermitRootLogin yes\nPermitRootLogin no\n"
                             "Match User admin\n  PermitRootLogin yes\n")
        config, _ = auditor.config_sshd_desde_archivo(ruta)
        self.assertEqual(config["permitrootlogin"], "no")

    def test_root_yes_falla(self):
        r = auditor.control_root_ssh(({"permitrootlogin": "yes"}, "sshd -T"))
        self.assertEqual(r.estado, "FAIL")

    def test_root_por_defecto_pasa(self):
        r = auditor.control_root_ssh(({}, "sshd_config"))
        self.assertEqual(r.estado, "PASS")

    def test_sin_ssh_es_na(self):
        self.assertEqual(auditor.control_root_ssh(None).estado, "N/A")

    def test_password_kbd_con_pam_falla(self):
        r = auditor.control_password_ssh(({"passwordauthentication": "no",
                                           "kbdinteractiveauthentication": "yes",
                                           "usepam": "yes"}, "sshd -T"))
        self.assertEqual(r.estado, "FAIL")


class TestMAC(unittest.TestCase):
    def test_ubuntu_con_getenforce_y_apparmor_pasa(self):
        # Antes daba FAIL: existia getenforce (Disabled) y no se miraba AppArmor
        archivos = {"/sys/module/apparmor/parameters/enabled": "Y\n"}
        with mock.patch.object(auditor, "existe", lambda p: p in ("getenforce", "aa-status")), \
             mock.patch.object(auditor, "leer", lambda r: archivos.get(r)), \
             mock.patch.object(auditor, "ejecutar", falso_ejecutar({
                 "getenforce": ("Disabled", 0), "aa-status": ("", 0)})):
            r = auditor.control_mac()
        self.assertEqual(r.estado, "PASS")
        self.assertIn("AppArmor", r.detalle)

    def test_selinux_permissive_falla(self):
        with mock.patch.object(auditor, "existe", lambda p: p == "getenforce"), \
             mock.patch.object(auditor, "leer", lambda r: None), \
             mock.patch.object(auditor, "ejecutar", falso_ejecutar({
                 "getenforce": ("Permissive", 0)})):
            self.assertEqual(auditor.control_mac().estado, "FAIL")


class TestActualizaciones(unittest.TestCase):
    def test_apt_cuenta_paquetes(self):
        salida = ("Reading package lists...\n"
                  "Inst openssl [3.0.2-0ubuntu1.1] (3.0.2-0ubuntu1.2 Ubuntu:22.04/jammy-updates)\n"
                  "Inst curl [7.81.0-1] (7.81.0-1ubuntu1.4 Ubuntu:22.04/jammy-updates)\n"
                  "Conf openssl (3.0.2-0ubuntu1.2)\n")
        with mock.patch.object(auditor, "existe", lambda p: p == "apt-get"), \
             mock.patch.object(auditor, "dias_desde", lambda r: 1), \
             mock.patch.object(auditor, "ejecutar", falso_ejecutar({
                 "apt-get -s": (salida, 0)})):
            r = auditor.control_actualizaciones(False)
        self.assertEqual(r.estado, "FAIL")
        self.assertIn("2 paquetes", r.detalle)

    def test_apt_avisa_si_la_lista_es_vieja(self):
        with mock.patch.object(auditor, "existe", lambda p: p == "apt-get"), \
             mock.patch.object(auditor, "dias_desde", lambda r: 30), \
             mock.patch.object(auditor, "ejecutar", falso_ejecutar({
                 "apt-get -s": ("Reading package lists...", 0)})):
            r = auditor.control_actualizaciones(False)
        self.assertEqual(r.estado, "PASS")
        self.assertIn("--refrescar", r.detalle)

    def test_ejecutar_fuerza_idioma_ingles(self):
        with mock.patch.object(auditor.subprocess, "run") as run:
            run.return_value = mock.Mock(stdout="", returncode=0)
            auditor.ejecutar("algo")
        self.assertEqual(run.call_args[1]["env"]["LC_ALL"], "C")

    def test_dnf_codigos(self):
        for codigo, esperado in ((0, "PASS"), (100, "FAIL"), (1, "N/A")):
            with mock.patch.object(auditor, "existe", lambda p: p == "dnf"), \
                 mock.patch.object(auditor, "ejecutar", falso_ejecutar({
                     "check-update": ("", codigo)})):
                self.assertEqual(auditor.control_actualizaciones(False).estado, esperado)


class TestCuentas(unittest.TestCase):
    def test_uid0_extra(self):
        passwd = "root:x:0:0::/root:/bin/bash\ntoor:x:0:0::/root:/bin/sh\nana:x:1000:1000::/home/ana:/bin/bash\n"
        with mock.patch.object(auditor, "leer", lambda r: passwd):
            r = auditor.control_uid0()
        self.assertEqual(r.estado, "FAIL")
        self.assertIn("toor", r.detalle)

    def test_contrasenas_vacias(self):
        shadow = "root:$6$abc:19000::::::\ndaemon:*:19000::::::\ninvitado::19000::::::\nana:!:19000::::::\n"
        with mock.patch.object(auditor, "leer", lambda r: shadow):
            r = auditor.control_contrasenas_vacias()
        self.assertEqual(r.estado, "FAIL")
        self.assertIn("invitado", r.detalle)
        self.assertNotIn("ana", r.detalle)


class TestNotaYReporte(unittest.TestCase):
    def test_nota_ponderada(self):
        R = auditor.Resultado
        resultados = [R("a", "Alta", "PASS", ""), R("b", "Baja", "FAIL", ""),
                      R("c", "Media", "N/A", "")]
        self.assertEqual(auditor.calcular_nota(resultados), 75)   # 3 de 4

    def test_todo_na_da_cero(self):
        self.assertEqual(auditor.calcular_nota([auditor.Resultado("a", "Alta", "N/A", "")]), 0)

    def test_html_escapa(self):
        r = auditor.Resultado("x", "Alta", "FAIL", "<script>alert(1)</script>", "arregla")
        pagina = auditor.generar_html([r], 0, {"servidor": "srv<b>", "sistema": "Linux",
                                              "fecha": "hoy"})
        self.assertNotIn("<script>", pagina)
        self.assertIn("&lt;script&gt;", pagina)


if __name__ == "__main__":
    unittest.main()
