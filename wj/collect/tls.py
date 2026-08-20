"""Layers 6 and 5: what was negotiated, which certificates were presented, and why they are trusted."""

import datetime
import re
import ssl
import subprocess
import time

from wj.schema import observed, unobserved

EXPIRY_WARN_DAYS = 21

# We offer only HTTP/1.1 because that is the only framing wj/collect/http.py
# writes. Offering h2 would make most servers agree to it and then fail on the
# HTTP/1.1 text we send. What the host *supports* is measured separately and
# more reliably from its DNS HTTPS record (dns.alpn_advertised).
ALPN_PROTOCOLS = ["http/1.1"]


def summarise_cert(der, now=None):
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.x509.oid import ExtensionOID, NameOID

    cert = x509.load_der_x509_certificate(der)
    now = now or datetime.datetime.now(datetime.timezone.utc)

    def common_name(name):
        values = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        if values:
            return values[0].value
        org = name.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        return org[0].value if org else None

    def organization(name):
        values = name.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        return values[0].value if values else None

    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        key_info = {"type": "RSA", "bits": key.key_size}
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key_info = {"type": "EC", "bits": key.curve.key_size}
    else:
        key_info = {"type": type(key).__name__, "bits": getattr(key, "key_size", None)}

    sans = []
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass

    is_ca = False
    try:
        is_ca = cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS).value.ca
    except x509.ExtensionNotFound:
        pass

    scts = 0
    try:
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS)
        scts = len(ext.value)
    except x509.ExtensionNotFound:
        pass

    ocsp = []
    try:
        aia = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
        ocsp = [d.access_location.value for d in aia
                if d.access_method.dotted_string == "1.3.6.1.5.5.7.48.1"]
    except x509.ExtensionNotFound:
        pass

    not_after = cert.not_valid_after_utc
    return {
        "subject_cn": common_name(cert.subject),
        "issuer_cn": common_name(cert.issuer),
        "issuer_org": organization(cert.issuer),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": not_after.isoformat(),
        "days_left": (not_after - now).days,
        "key": key_info,
        "sig_algo": cert.signature_algorithm_oid._name,
        "sans": list(sans),
        "scts": scts,
        "ocsp": ocsp,
        "is_ca": is_ca,
    }


def caa_allows(caa_records, issuer_cn, issuer_org=None):
    """True/False when CAA is published and comparable, None when it cannot be judged.

    Many real issuer Common Names are bare CA codes with no resemblance to a
    domain at all ("R11", "WE1", "GTS CA 1C3" — cryptography's common_name()
    only falls back to Organization when the CN is entirely absent, and a CA
    almost always sets both). Judging those against a CAA domain by substring
    match produces confident False positives, not honest unknowns, so both the
    CN and the Organization are considered, and a haystack with no comparable
    word-like token is refused outright rather than silently judged.
    """
    if not caa_records or not (issuer_cn or issuer_org):
        return None
    issuers = []
    for record in caa_records:
        match = re.search(r'issue(?:wild)?\s+"([^"]+)"', record.get("data", ""))
        if match:
            issuers.append(match.group(1).lower())
    if not issuers:
        return None
    haystack = " ".join(p for p in (issuer_cn, issuer_org) if p).lower()
    if not re.search(r"[a-z]{3,}", haystack):
        return None  # a bare CA code ("R11", "WE1") is not comparable to a domain
    if any(i in haystack for i in issuers):
        return True
    # A CA's issuer_cn/issuer_org (e.g. "Let's Encrypt") rarely spells its CAA
    # domain (e.g. "letsencrypt.org") verbatim, so compare on alphanumerics only
    # — and check every label of the domain, not only the first. Google Trust
    # Services' CAA domain is "pki.goog": the brand is the SECOND label, not the
    # first ("pki"), and a first-label-only check returns a false "False" against
    # a real, live "Google Trust Services"-issued certificate (verified against
    # google.com). "com"/"org"/"net"/"www" are excluded as too generic to prove
    # anything on their own.
    normalized_haystack = re.sub(r"[^a-z0-9]", "", haystack)
    generic_labels = {"com", "org", "net", "co", "www"}
    brands = []
    for i in issuers:
        for label in i.split("."):
            label = re.sub(r"[^a-z0-9]", "", label)
            if label and label not in generic_labels and label not in brands:
                brands.append(label)
    if any(brand in normalized_haystack for brand in brands):
        return None  # plausible match on the brand alone — not proof either way
    return False


def grade_expiry(days_left):
    if days_left < 0:
        return ("critical", f"certificate expired {abs(days_left)} days ago")
    if days_left <= EXPIRY_WARN_DAYS:
        return ("warn", f"certificate expires in {days_left} days")
    return None


def _chain_via_openssl(host, port, timeout):
    try:
        out = subprocess.run(
            ["openssl", "s_client", "-showcerts", "-servername", host,
             "-connect", f"{host}:{port}"],
            input="", capture_output=True, text=True, timeout=timeout).stdout
    except Exception:
        return []
    pems = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", out, re.S)
    return [ssl.PEM_cert_to_DER_cert(p) for p in pems]


def collect(ctx):
    if ctx.scheme != "https":
        return unobserved("plain HTTP requested — no TLS layer in this trace")

    tcp = ctx.results.get("tcp", {})
    sock = tcp.get("_socket")
    if sock is None:
        return unobserved("no TCP connection to negotiate over")

    context = ssl.create_default_context()
    context.set_alpn_protocols(ALPN_PROTOCOLS)
    sock.settimeout(ctx.budget_for(ctx.timeout))

    started = time.perf_counter()
    try:
        tls_sock = context.wrap_socket(sock, server_hostname=ctx.host)
    except ssl.SSLError as exc:
        return unobserved(f"TLS handshake failed: {exc}")
    except OSError as exc:
        return unobserved(f"TLS handshake failed: {exc}")
    handshake_ms = round((time.perf_counter() - started) * 1000, 1)

    ders = []
    getter = getattr(tls_sock, "get_verified_chain", None)
    if getter:
        try:
            ders = [c.public_bytes(ssl._ssl.ENCODING_DER) if hasattr(c, "public_bytes")
                    else c for c in getter()]
        except Exception:
            ders = []
    if not ders:
        leaf = tls_sock.getpeercert(True)
        ders = [leaf] if leaf else []
        ders += _chain_via_openssl(ctx.host, ctx.port, min(ctx.timeout, 5))[1:]

    chain = []
    if ctx.caps.has_lib("cryptography"):
        for der in ders:
            try:
                chain.append(summarise_cert(der))
            except Exception:
                continue

    caa_records = ctx.results.get("dns", {}).get("records", {}).get("CAA", [])
    issuer = chain[0]["issuer_cn"] if chain else None
    issuer_org = chain[0].get("issuer_org") if chain else None

    section = observed(
        version=tls_sock.version(),
        cipher=(tls_sock.cipher() or [None])[0],
        alpn=tls_sock.selected_alpn_protocol(),
        handshake_ms=handshake_ms,
        chain=chain,
        trust_root=chain[-1]["subject_cn"] if len(chain) > 1 else None,
        verified=True,
        caa_match=caa_allows(caa_records, issuer, issuer_org),
        resumption={"tested": False},
        legacy_versions_accepted=[],
    )
    section["_socket"] = tls_sock
    return section
