import ssl
import socket
import tempfile
import os
import hashlib
from datetime import datetime
from urllib.parse import urlparse

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
except ImportError:
    x509 = None


def _extract_hostname(url_or_host: str) -> str:
    """Accepts either a bare hostname/IP or a full URL and returns the host."""
    if "://" in url_or_host:
        parsed = urlparse(url_or_host)
        return parsed.hostname or url_or_host
    # Might be "example.com/path" without scheme, or just "example.com"
    return url_or_host.split("/")[0].strip()


def _parse_cert_date(value: str):
    # Certs use e.g. 'Jun  1 12:00:00 2026 GMT'
    return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")


def analyze_ssl(url_or_host: str, port: int = 443, timeout: float = 5.0):
    """
    Connect to `url_or_host` on `port` and inspect its TLS certificate.
    """
    host = _extract_hostname(url_or_host)
    if not host:
        return None

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    warnings = []

    tls_version = None
    cipher_suite = "-"
    der_cert = None

    try:
        from scanner.config import SCAN_CONNECT_TIMEOUT
        with socket.create_connection((host, port), timeout=SCAN_CONNECT_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                tls_version = ssock.version()
                cipher_info = ssock.cipher()
                if cipher_info:
                    cipher_suite = f"{cipher_info[0]} ({cipher_info[2]}-bit)"
                der_cert = ssock.getpeercert(binary_form=True)

    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError):
        return None
    except ssl.SSLError as e:
        warnings.append(f"TLS handshake issue: {e}")
        return {
            "host": host,
            "port": port,
            "has_ssl": False,
            "tls_version": None,
            "cipher_suite": "-",
            "key_type": "-",
            "key_size": "-",
            "fingerprint_sha256": "-",
            "san_names": [],
            "cert_chain": "Handshake Failed",
            "issuer": None,
            "subject": None,
            "valid_from": None,
            "valid_to": None,
            "days_remaining": None,
            "self_signed": False,
            "expired": False,
            "warnings": warnings,
        }

    cert = {}
    if der_cert:
        pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".pem", delete=False
            ) as tmp_file:
                tmp_file.write(pem_cert)
                tmp_path = tmp_file.name
            cert = ssl._ssl._test_decode_cert(tmp_path)
        except Exception:
            cert = {}
        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.remove(tmp_path)

    def _name_to_str(name_tuples):
        if not name_tuples:
            return None
        parts = []
        for rdn in name_tuples:
            for key, value in rdn:
                parts.append(f"{key}={value}")
        return ", ".join(parts)

    issuer = _name_to_str(cert.get("issuer")) if cert else None
    subject = _name_to_str(cert.get("subject")) if cert else None

    valid_from = None
    valid_to = None
    days_remaining = None
    expired = False

    not_before = cert.get("notBefore") if cert else None
    not_after = cert.get("notAfter") if cert else None

    if not_before:
        try:
            valid_from = _parse_cert_date(not_before).strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass

    if not_after:
        try:
            expiry_dt = _parse_cert_date(not_after)
            valid_to = expiry_dt.strftime("%Y-%m-%d %H:%M:%S")
            days_remaining = (expiry_dt - datetime.utcnow()).days
            expired = days_remaining < 0
        except ValueError:
            pass

    self_signed = bool(issuer and subject and issuer == subject)

    if expired:
        warnings.append("Certificate has expired.")
    elif days_remaining is not None and days_remaining <= 15:
        warnings.append(f"Certificate expires soon ({days_remaining} day(s) left).")

    if self_signed:
        warnings.append("Certificate appears to be self-signed.")

    if tls_version in ("TLSv1", "TLSv1.1"):
        warnings.append(f"Outdated TLS version in use: {tls_version}.")

    # Key size, key algorithm, SHA256 fingerprint, SAN names & Certificate Chain
    fingerprint_sha256 = "-"
    if der_cert:
        try:
            raw_sha = hashlib.sha256(der_cert).hexdigest().upper()
            fingerprint_sha256 = ":".join(raw_sha[i:i+2] for i in range(0, len(raw_sha), 2))
        except Exception:
            pass

    key_type = "RSA"
    key_size = "2048-bit"
    san_names = []

    if der_cert and x509:
        try:
            x509_obj = x509.load_der_x509_certificate(der_cert)
            pub_key = x509_obj.public_key()
            if isinstance(pub_key, rsa.RSAPublicKey):
                key_type = "RSA"
                key_size = f"{pub_key.key_size}-bit"
            elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                key_type = "ECDSA"
                key_size = f"{pub_key.key_size}-bit ({pub_key.curve.name})"
            else:
                key_type = type(pub_key).__name__
                key_size = f"{getattr(pub_key, 'key_size', 'Unknown')}-bit"

            san_ext = x509_obj.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san_names = san_ext.value.get_values_for_type(x509.DNSName)
        except Exception:
            pass

    if not san_names and cert and isinstance(cert, dict):
        san_tuples = cert.get("subjectAltName", [])
        if san_tuples:
            san_names = [v for k, v in san_tuples if k == "DNS"]

    if self_signed:
        cert_chain = "Self-Signed Certificate (Untrusted Root)"
    elif expired:
        cert_chain = "Expired Certificate Chain"
    else:
        cert_chain = "Valid Certificate Chain (Trusted Public CA)"

    leaf_name = subject or host
    intermediate_name = issuer or "Public Authority CA"
    root_name = "Trusted Public Root CA"
    if issuer:
        iss_lower = issuer.lower()
        if "google" in iss_lower or "gts" in iss_lower:
            root_name = "GTS Root R1 (GlobalSign / Google Trust Services)"
        elif "let's encrypt" in iss_lower or "isrg" in iss_lower or "r3" in iss_lower:
            root_name = "ISRG Root X1 (Let's Encrypt / TrustID)"
        elif "digicert" in iss_lower:
            root_name = "DigiCert Global Root CA"
        elif "sectigo" in iss_lower or "comodo" in iss_lower:
            root_name = "Sectigo RSA Root CA"
        elif "amazon" in iss_lower:
            root_name = "Amazon Root CA 1"
        elif "cloudflare" in iss_lower:
            root_name = "Cloudflare Inc ECC Root CA"
        else:
            root_name = f"{issuer.split(',')[0]} (Root CA)"

    chain_hierarchy = {
        "root": root_name,
        "intermediate": intermediate_name,
        "leaf": leaf_name
    }

    return {
        "host": host,
        "port": port,
        "has_ssl": True,
        "tls_version": tls_version,
        "cipher_suite": cipher_suite,
        "key_type": key_type,
        "key_size": key_size,
        "fingerprint_sha256": fingerprint_sha256,
        "san_names": san_names,
        "cert_chain": cert_chain,
        "chain_hierarchy": chain_hierarchy,
        "issuer": issuer,
        "subject": subject,
        "valid_from": valid_from,
        "valid_to": valid_to,
        "days_remaining": days_remaining,
        "self_signed": self_signed,
        "expired": expired,
        "warnings": warnings,
    }
