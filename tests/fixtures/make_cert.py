"""Regenerate leaf.der. Run once; the DER file is the committed fixture."""

import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA R3")])
now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)

cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now)
    .not_valid_after(now + datetime.timedelta(days=90))
    .add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("example.com"), x509.DNSName("www.example.com")]),
        critical=False,
    )
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    .sign(key, hashes.SHA256())
)

Path(__file__).with_name("leaf.der").write_bytes(
    cert.public_bytes(serialization.Encoding.DER))
print("wrote leaf.der")
