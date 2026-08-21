"""Layers 6 and 5: what was negotiated, which certificates were presented, and why they are trusted.

Each cert entry in the collected `chain` carries an `unmeasured` list -- field
names in that entry that were not derived, as opposed to fields that were
looked up and are genuinely absent. Without the optional `cryptography`
library, `ssl.SSLSocket.getpeercert()` still yields subject, issuer, validity,
SANs and OCSP for the leaf certificate straight from the handshake -- see
`summarise_cert_basic()` -- but `key`, `sig_algo`, `scts` and `is_ca` cannot be
derived from that dict, so those four are always in `unmeasured` on the
stdlib-only path (empty otherwise). `getpeercert()` only ever describes the
peer's own leaf certificate, so intermediates and the root -- present in `chain`
whenever cryptography is installed -- cannot be summarised at all without it;
`chain_unparsed` on the section counts how many certificates were presented but
could not be turned into a chain entry, so their absence is measured, not
silent.
"""

import datetime
import re
import ssl
import subprocess
import time

from wj.schema import observed, unobserved

EXPIRY_WARN_DAYS = 21

# The four cert fields that only cryptography's ASN.1 parsing can produce.
# ssl.SSLSocket.getpeercert()'s dict has no equivalent for any of these.
FIELDS_NEEDING_CRYPTOGRAPHY = ("key", "sig_algo", "scts", "is_ca")

# Offered over ALPN when negotiation has not run (redirect hops, direct calls).
# The negotiate collector overrides this per run.
ALPN_PROTOCOLS = ["http/1.1"]


def alpn_for(ctx):
    """What this run offers over ALPN, as decided by the negotiate collector."""
    negotiation = ctx.results.get("negotiation", {})
    if negotiation.get("observed"):
        offered = negotiation.get("offered")
        # A deliberate empty offer (negotiate.choose() returns [] for plain
        # HTTP, where ALPN does not apply at all) must stay empty, not be
        # silently upgraded to the fallback -- only a genuinely absent key
        # falls back to ALPN_PROTOCOLS.
        return list(offered) if offered is not None else list(ALPN_PROTOCOLS)
    return list(ALPN_PROTOCOLS)


def _peercert_name_component(rdns, attr):
    """Pull one attribute (e.g. 'commonName') out of getpeercert()'s subject/issuer shape.

    That shape is a tuple of RDNs, each itself a tuple of one or more
    (attribute, value) pairs: ((('commonName', 'example.com'),),).
    """
    for rdn in rdns or ():
        for key, value in rdn:
            if key == attr:
                return value
    return None


def _peercert_common_name(rdns):
    # Mirrors summarise_cert()'s common_name(): fall back to Organization only
    # when the Common Name is entirely absent.
    return (_peercert_name_component(rdns, "commonName")
            or _peercert_name_component(rdns, "organizationName"))


def _peercert_organization(rdns):
    return _peercert_name_component(rdns, "organizationName")


def _parse_peercert_time(text):
    # getpeercert() renders notBefore/notAfter as e.g. "Jul 29 22:10:08 2026 GMT".
    return datetime.datetime.strptime(text, "%b %d %H:%M:%S %Y %Z").replace(
        tzinfo=datetime.timezone.utc)


def summarise_cert_basic(cert_dict, now=None):
    """Summarise the leaf certificate from ssl.SSLSocket.getpeercert()'s dict form.

    Used when the `cryptography` library is not installed. Covers every field
    that dict can support -- subject_cn, issuer_cn, issuer_org, not_before,
    not_after, days_left, sans, ocsp -- verified byte-for-byte against
    summarise_cert() on a live host. key/sig_algo/scts/is_ca have no
    equivalent in getpeercert() and are honestly absent, listed in
    `unmeasured` rather than guessed.
    """
    now = now or datetime.datetime.now(datetime.timezone.utc)
    subject = cert_dict.get("subject") or ()
    issuer = cert_dict.get("issuer") or ()

    not_before_raw = cert_dict.get("notBefore")
    not_after_raw = cert_dict.get("notAfter")
    not_before = _parse_peercert_time(not_before_raw) if not_before_raw else None
    not_after = _parse_peercert_time(not_after_raw) if not_after_raw else None

    sans = [value for kind, value in cert_dict.get("subjectAltName") or () if kind == "DNS"]
    ocsp = list(cert_dict.get("OCSP") or ())

    return {
        "subject_cn": _peercert_common_name(subject),
        "issuer_cn": _peercert_common_name(issuer),
        "issuer_org": _peercert_organization(issuer),
        "not_before": not_before.isoformat() if not_before else None,
        "not_after": not_after.isoformat() if not_after else None,
        "days_left": (not_after - now).days if not_after else None,
        "key": None,
        "sig_algo": None,
        "sans": sans,
        "scts": None,
        "ocsp": ocsp,
        "is_ca": None,
        "unmeasured": list(FIELDS_NEEDING_CRYPTOGRAPHY),
    }


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
        "unmeasured": [],
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
            # RFC 8659 §4.2 allows semicolon-separated parameters after the
            # issuer domain itself ("pki.goog; cansignhttpexchanges=yes",
            # "letsencrypt.org; accounturi=...; validationmethods=...") — both
            # are common in the wild. Only the domain, the first field, is
            # ever compared; a parameter blob folded into the whole quoted
            # string normalises to noise that can never brand-match.
            issuer_domain = match.group(1).split(";", 1)[0].strip().lower()
            if issuer_domain:
                issuers.append(issuer_domain)
    if not issuers:
        return None
    haystack = " ".join(p for p in (issuer_cn, issuer_org) if p).lower()
    # A bare CA code is not comparable to a domain -- but the comparability
    # check has to be a real WORD, not just any run of 3+ letters: "GTS CA
    # 1C3" (no Organization attached) contains the 3-letter run "gts" and
    # would otherwise sail through as "comparable" while still being three
    # short, code-like tokens with nothing brand-like in them. Requiring 4+
    # consecutive letters excludes that shape while every genuine brand word
    # used elsewhere in this function ("letsencrypt", "google", "sectigo",
    # "digicert", ...) is well over that length.
    if not re.search(r"[a-z]{4,}", haystack):
        return None  # a bare CA code ("R11", "WE1", "GTS CA 1C3") is not comparable
    if any(i in haystack for i in issuers):
        return True
    # A CA's issuer_cn/issuer_org (e.g. "Let's Encrypt") rarely spells its CAA
    # domain (e.g. "letsencrypt.org") verbatim, so compare on alphanumerics only
    # — and check every label of the domain, not only the first. Google Trust
    # Services' CAA domain is "pki.goog": the brand is the SECOND label, not the
    # first ("pki"), and a first-label-only check returns a false "False" against
    # a real, live "Google Trust Services"-issued certificate (verified against
    # google.com). "com"/"org"/"net"/"www" are excluded as too generic to prove
    # anything on their own, and every label under 3 characters is excluded too
    # -- "actalis.it" and "telesec.de" otherwise brand-match on their bare
    # ccTLD ("it" inside "...Limited", "de" inside "IdenTrust"), which is a
    # spurious None, not a real brand plausibility.
    normalized_haystack = re.sub(r"[^a-z0-9]", "", haystack)
    generic_labels = {"com", "org", "net", "co", "www"}
    brands = []
    for i in issuers:
        for label in i.split("."):
            label = re.sub(r"[^a-z0-9]", "", label)
            if len(label) >= 3 and label not in generic_labels and label not in brands:
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
    context.set_alpn_protocols(alpn_for(ctx))
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
    else:
        # getpeercert()'s dict describes only the peer's own leaf certificate --
        # there is no stdlib way to summarise the intermediates/root in `ders`
        # without cryptography, so this path can only ever produce one entry.
        try:
            cert_dict = tls_sock.getpeercert()
        except Exception:
            cert_dict = None
        if cert_dict:
            chain.append(summarise_cert_basic(cert_dict))
    chain_unparsed = max(len(ders) - len(chain), 0)

    caa_records = ctx.results.get("dns", {}).get("records", {}).get("CAA", [])
    issuer = chain[0]["issuer_cn"] if chain else None
    issuer_org = chain[0].get("issuer_org") if chain else None

    section = observed(
        version=tls_sock.version(),
        cipher=(tls_sock.cipher() or [None])[0],
        alpn=tls_sock.selected_alpn_protocol(),
        handshake_ms=handshake_ms,
        chain=chain,
        chain_unparsed=chain_unparsed,
        trust_root=chain[-1]["subject_cn"] if len(chain) > 1 else None,
        verified=True,
        caa_match=caa_allows(caa_records, issuer, issuer_org),
        resumption={"tested": False},
        legacy_versions_accepted=[],
    )
    section["_socket"] = tls_sock
    return section
