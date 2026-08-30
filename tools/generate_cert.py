# -*- coding: utf-8 -*-
"""
================================================================================
 NetWatch Enterprise — tools/generate_cert.py
--------------------------------------------------------------------------------
 Génère un certificat TLS AUTO-SIGNÉ pour servir la console en HTTPS sur un
 réseau interne. Aucun accès Internet requis (la bibliothèque `cryptography`,
 déjà présente, fait tout localement).

 Usage :
     python tools/generate_cert.py                # dans data/ (cert.pem/key.pem)
     python tools/generate_cert.py --host 10.0.0.5
     python tools/generate_cert.py --out /chemin/dossier

 Puis lancez la console avec :
     set   NETWATCH_TLS_CERT=...\\data\\cert.pem   (Windows)
     set   NETWATCH_TLS_KEY=...\\data\\key.pem
     python app.py

 ⚠ Un certificat auto-signé déclenchera un avertissement du navigateur : c'est
   normal pour un usage interne. Pour un vrai domaine, utilisez une autorité de
   certification (ex. votre PKI interne, ou Let's Encrypt derrière un proxy).
================================================================================
"""

import argparse
import datetime
import ipaddress
import os
import socket
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config  # noqa: E402


def _local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def main() -> int:
    parser = argparse.ArgumentParser(description="Génère un certificat TLS auto-signé.")
    parser.add_argument("--host", default=None, help="Nom d'hôte / IP principal du certificat")
    parser.add_argument("--out", default=config.DATA_DIR, help="Dossier de sortie")
    parser.add_argument("--days", type=int, default=825, help="Durée de validité (jours)")
    args = parser.parse_args()

    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
    except ImportError:
        print("Le paquet « cryptography » est requis : pip install cryptography")
        return 1

    host = args.host or _local_ip()
    os.makedirs(args.out, exist_ok=True)
    cert_path = os.path.join(args.out, "cert.pem")
    key_path = os.path.join(args.out, "key.pem")

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # SAN : localhost + 127.0.0.1 + l'hôte fourni (nom DNS ou IP).
    sans = [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
    try:
        sans.append(x509.IPAddress(ipaddress.ip_address(host)))
    except ValueError:
        sans.append(x509.DNSName(host))

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NetWatch Enterprise"),
        x509.NameAttribute(NameOID.COMMON_NAME, host),
    ])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=args.days))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    with open(key_path, "wb") as fh:
        fh.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass
    with open(cert_path, "wb") as fh:
        fh.write(cert.public_bytes(serialization.Encoding.PEM))

    print("Certificat TLS auto-signé généré :")
    print(f"  Certificat : {cert_path}")
    print(f"  Clé privée : {key_path}")
    print(f"  Valide pour: {host} (+ localhost, 127.0.0.1), {args.days} jours")
    print("\nActivez-le :")
    print(f'  NETWATCH_TLS_CERT="{cert_path}"')
    print(f'  NETWATCH_TLS_KEY="{key_path}"')
    return 0


if __name__ == "__main__":
    sys.exit(main())
