"""
cert_utils.py - SSL Certificate parsing and manipulation utilities.

Handles PEM bundles, PFX/P12 files, and individual cert/key files.
Extracts certificate details, splits chains, and generates PFX archives.
"""

import re
import os
import tempfile
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Optional

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    NoEncryption,
    BestAvailableEncryption,
    pkcs12,
)


PEM_CERT_PATTERN = re.compile(
    rb"-----BEGIN CERTIFICATE-----[\s\r\n]+.+?[\s\r\n]+-----END CERTIFICATE-----",
    re.DOTALL,
)

PEM_KEY_PATTERN = re.compile(
    rb"-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----[\s\r\n]+.+?[\s\r\n]+-----END (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----",
    re.DOTALL,
)


def _strip_rtf(data: bytes) -> bytes:
    """Extract plain text PEM content from RTF-formatted files."""
    # Detect RTF by looking for the magic header
    if not data.lstrip().startswith(b"{\\rtf"):
        return data
    # Decode to string for easier processing
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        text = data.decode("latin-1", errors="replace")
    # Remove RTF control words and groups
    # Strip {\...} groups that don't contain PEM data
    text = re.sub(r'\{[^{}]*\}', '', text)
    # Remove RTF control words like \f0, \fs21, \cf0, \par, etc.
    text = re.sub(r'\\[a-zA-Z]+\d*\s?', '\n', text)
    # RTF uses \\ for literal backslash and \n for newline
    text = text.replace('\\\\', '')
    # Remove remaining braces
    text = text.replace('{', '').replace('}', '')
    # Clean up: remove any remaining lone backslashes
    text = text.replace('\\', '\n')
    # Clean up whitespace but preserve PEM structure
    lines = []
    for line in text.split('\n'):
        line = line.strip()
        if line:
            lines.append(line)
    text = '\n'.join(lines)
    return text.encode("utf-8")


def _normalize_pem(data: bytes) -> bytes:
    """Normalize line endings and strip BOM/extra whitespace from PEM data."""
    # Remove UTF-8 BOM if present
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    # Strip RTF formatting if present
    data = _strip_rtf(data)
    # Normalize line endings to \n
    data = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return data


@dataclass
class CertInfo:
    """Parsed certificate details."""
    subject: str = ""
    common_name: str = ""
    sans: list[str] = field(default_factory=list)
    issuer: str = ""
    serial_number: str = ""
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    thumbprint: str = ""
    is_ca: bool = False
    key_usage: str = ""
    pem_data: bytes = b""

    @property
    def is_expired(self) -> bool:
        if self.not_after is None:
            return False
        now = datetime.now(timezone.utc)
        return now > self.not_after

    @property
    def days_until_expiry(self) -> int:
        if self.not_after is None:
            return -1
        now = datetime.now(timezone.utc)
        delta = self.not_after - now
        return delta.days

    @property
    def validity_display(self) -> str:
        fmt = "%Y-%m-%d %H:%M UTC"
        start = self.not_before.strftime(fmt) if self.not_before else "Unknown"
        end = self.not_after.strftime(fmt) if self.not_after else "Unknown"
        return f"{start}  to  {end}"


@dataclass
class ParsedCertBundle:
    """Result of parsing a certificate bundle."""
    server_cert: Optional[CertInfo] = None
    intermediates: list[CertInfo] = field(default_factory=list)
    root_ca: Optional[CertInfo] = None
    private_key: Optional[bytes] = None  # PEM-encoded private key bytes
    has_private_key: bool = False
    errors: list[str] = field(default_factory=list)

    @property
    def chain_certs(self) -> list[CertInfo]:
        """All intermediate + root certs in order."""
        certs = list(self.intermediates)
        if self.root_ca:
            certs.append(self.root_ca)
        return certs

    @property
    def all_certs(self) -> list[CertInfo]:
        """All certs: server + chain."""
        certs = []
        if self.server_cert:
            certs.append(self.server_cert)
        certs.extend(self.chain_certs)
        return certs


def parse_x509_cert(cert_obj: x509.Certificate) -> CertInfo:
    """Extract human-readable info from an x509 Certificate object."""
    info = CertInfo()

    # Subject
    info.subject = cert_obj.subject.rfc4514_string()
    try:
        cn_attrs = cert_obj.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        info.common_name = cn_attrs[0].value if cn_attrs else ""
    except Exception:
        info.common_name = ""

    # Issuer
    info.issuer = cert_obj.issuer.rfc4514_string()

    # Serial
    info.serial_number = format(cert_obj.serial_number, "X")

    # Validity
    info.not_before = cert_obj.not_valid_before_utc
    info.not_after = cert_obj.not_valid_after_utc

    # Thumbprint (SHA-1, standard for Windows cert store)
    info.thumbprint = cert_obj.fingerprint(hashes.SHA1()).hex().upper()

    # SANs
    try:
        san_ext = cert_obj.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        info.sans = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        info.sans = []

    # Basic Constraints - is this a CA cert?
    try:
        bc_ext = cert_obj.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        )
        info.is_ca = bc_ext.value.ca
    except x509.ExtensionNotFound:
        info.is_ca = False

    # PEM data
    info.pem_data = cert_obj.public_bytes(Encoding.PEM)

    return info


def _classify_certs(certs: list[CertInfo]) -> tuple[Optional[CertInfo], list[CertInfo], Optional[CertInfo]]:
    """
    Classify certs into server cert, intermediates, and root CA.

    Server cert = non-CA cert (leaf).
    Root CA = self-signed CA cert (subject == issuer).
    Intermediates = everything else (CA certs that aren't self-signed).
    """
    server = None
    intermediates = []
    root = None

    for cert in certs:
        if not cert.is_ca and server is None:
            server = cert
        elif cert.subject == cert.issuer and cert.is_ca:
            root = cert
        else:
            intermediates.append(cert)

    # If no non-CA cert found, treat the first cert as server cert
    if server is None and intermediates:
        server = intermediates.pop(0)

    return server, intermediates, root


def parse_pem_bundle(pem_data: bytes, key_data: bytes = b"") -> ParsedCertBundle:
    """
    Parse a PEM bundle containing one or more certificates and optionally a private key.

    Args:
        pem_data: PEM-encoded certificate data (may contain multiple certs).
        key_data: Optional separate PEM-encoded private key data.

    Returns:
        ParsedCertBundle with parsed certificate details.
    """
    result = ParsedCertBundle()

    # Normalize line endings and strip BOM
    pem_data = _normalize_pem(pem_data)
    if key_data:
        key_data = _normalize_pem(key_data)

    # Extract all certificates from PEM data
    cert_pems = PEM_CERT_PATTERN.findall(pem_data)
    if not cert_pems:
        result.errors.append(
            "No certificates found in PEM data. "
            f"File starts with: {pem_data[:80]!r}"
        )
        return result

    certs = []
    for pem_block in cert_pems:
        try:
            cert_obj = x509.load_pem_x509_certificate(pem_block)
            certs.append(parse_x509_cert(cert_obj))
        except Exception as e:
            result.errors.append(f"Failed to parse certificate: {e}")

    # Classify
    result.server_cert, result.intermediates, result.root_ca = _classify_certs(certs)

    # Look for private key in pem_data first, then in key_data
    combined = pem_data + b"\n" + key_data if key_data else pem_data
    key_matches = PEM_KEY_PATTERN.findall(combined)
    if key_matches:
        result.private_key = key_matches[0]
        result.has_private_key = True

    return result


def parse_pfx(pfx_data: bytes, password: Optional[str] = None) -> ParsedCertBundle:
    """
    Parse a PFX/PKCS12 file.

    Args:
        pfx_data: Raw PFX file bytes.
        password: Optional password for the PFX file.

    Returns:
        ParsedCertBundle with parsed certificate details.
    """
    result = ParsedCertBundle()
    pwd = password.encode("utf-8") if password else None

    try:
        private_key, cert, additional_certs = pkcs12.load_key_and_certificates(
            pfx_data, pwd
        )
    except Exception as e:
        result.errors.append(f"Failed to parse PFX file: {e}")
        return result

    # Server certificate
    if cert:
        result.server_cert = parse_x509_cert(cert)

    # Chain certs
    all_chain = []
    if additional_certs:
        for c in additional_certs:
            all_chain.append(parse_x509_cert(c))

    # Classify chain certs
    _, result.intermediates, result.root_ca = _classify_certs(
        [CertInfo(is_ca=True)] + all_chain  # dummy to skip server slot
    )
    # Re-classify properly - just separate chain certs
    intermediates = []
    root = None
    for ci in all_chain:
        if ci.subject == ci.issuer and ci.is_ca:
            root = ci
        else:
            intermediates.append(ci)
    result.intermediates = intermediates
    result.root_ca = root

    # Private key
    if private_key:
        result.private_key = private_key.private_bytes(
            Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()
        )
        result.has_private_key = True

    return result


def load_cert_file(file_path: str) -> bytes:
    """Read a certificate file from disk and normalize it."""
    with open(file_path, "rb") as f:
        data = f.read()
    return _normalize_pem(data)


def build_pfx(
    server_cert_pem: bytes,
    private_key_pem: bytes,
    chain_pems: list[bytes],
    friendly_name: str = "SSL Certificate",
    password: Optional[str] = None,
) -> bytes:
    """
    Build a PFX/PKCS12 archive from PEM components.

    Args:
        server_cert_pem: PEM-encoded server certificate.
        private_key_pem: PEM-encoded private key.
        chain_pems: List of PEM-encoded CA chain certificates.
        friendly_name: Friendly name for the PFX entry.
        password: Optional password to protect the PFX.

    Returns:
        PFX file bytes.
    """
    cert = x509.load_pem_x509_certificate(server_cert_pem)
    key = serialization.load_pem_private_key(private_key_pem, password=None)

    cas = []
    for pem in chain_pems:
        cas.append(x509.load_pem_x509_certificate(pem))

    pwd = password.encode("utf-8") if password else None
    encryption = BestAvailableEncryption(pwd) if pwd else NoEncryption()

    pfx_data = pkcs12.serialize_key_and_certificates(
        name=friendly_name.encode("utf-8"),
        key=key,
        cert=cert,
        cas=cas if cas else None,
        encryption_algorithm=encryption,
    )

    return pfx_data


def export_components(bundle: ParsedCertBundle, output_dir: str) -> dict[str, str]:
    """
    Export all certificate components to individual files.

    Returns a dict mapping component name to file path.
    """
    os.makedirs(output_dir, exist_ok=True)
    exported = {}

    # Server certificate
    if bundle.server_cert:
        path = os.path.join(output_dir, "server.crt")
        with open(path, "wb") as f:
            f.write(bundle.server_cert.pem_data)
        exported["server_cert"] = path

    # Private key
    if bundle.private_key:
        path = os.path.join(output_dir, "server.key")
        with open(path, "wb") as f:
            f.write(bundle.private_key)
        exported["private_key"] = path

    # CA bundle (intermediates + root)
    chain_certs = bundle.chain_certs
    if chain_certs:
        path = os.path.join(output_dir, "ca-bundle.crt")
        with open(path, "wb") as f:
            for cert in chain_certs:
                f.write(cert.pem_data)
        exported["ca_bundle"] = path

    # Full chain (server cert + intermediates + root)
    if bundle.server_cert:
        path = os.path.join(output_dir, "fullchain.pem")
        with open(path, "wb") as f:
            f.write(bundle.server_cert.pem_data)
            for cert in chain_certs:
                f.write(cert.pem_data)
        exported["fullchain"] = path

    # PFX (if we have both cert and key)
    if bundle.server_cert and bundle.private_key:
        try:
            chain_pems = [c.pem_data for c in chain_certs]
            pfx = build_pfx(
                bundle.server_cert.pem_data,
                bundle.private_key,
                chain_pems,
                friendly_name=bundle.server_cert.common_name or "SSL Certificate",
            )
            path = os.path.join(output_dir, "certificate.pfx")
            with open(path, "wb") as f:
                f.write(pfx)
            exported["pfx"] = path
        except Exception as e:
            pass  # PFX generation is optional

    return exported


def generate_csr(
    common_name: str,
    sans: list[str] = None,
    organization: str = "",
    country: str = "",
    state: str = "",
    city: str = "",
    key_size: int = 2048,
) -> tuple[bytes, bytes]:
    """
    Generate a private key and Certificate Signing Request (CSR).

    Args:
        common_name: The CN for the certificate (e.g., *.grazr.market).
        sans: List of Subject Alternative Names.
        organization: Organization name (optional).
        country: 2-letter country code (optional).
        state: State or province (optional).
        city: City or locality (optional).
        key_size: RSA key size in bits (2048 or 4096).

    Returns:
        (private_key_pem, csr_pem) as bytes.
    """
    # Generate RSA private key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )

    key_pem = key.private_bytes(
        Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()
    )

    # Build subject name attributes
    name_attrs = [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    if organization:
        name_attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
    if country:
        name_attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))
    if state:
        name_attrs.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state))
    if city:
        name_attrs.append(x509.NameAttribute(NameOID.LOCALITY_NAME, city))

    subject = x509.Name(name_attrs)

    # Build CSR
    builder = x509.CertificateSigningRequestBuilder().subject_name(subject)

    # Add SANs
    all_sans = []
    if common_name:
        all_sans.append(x509.DNSName(common_name))
        # For wildcard certs, also add the base domain
        if common_name.startswith("*."):
            base_domain = common_name[2:]
            all_sans.append(x509.DNSName(base_domain))
    if sans:
        for san in sans:
            san = san.strip()
            if san and san not in [common_name, common_name[2:] if common_name.startswith("*.") else ""]:
                all_sans.append(x509.DNSName(san))

    if all_sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(all_sans),
            critical=False,
        )

    csr = builder.sign(key, hashes.SHA256())
    csr_pem = csr.public_bytes(Encoding.PEM)

    return key_pem, csr_pem


def save_key_and_csr(
    output_dir: str,
    common_name: str,
    key_pem: bytes,
    csr_pem: bytes,
) -> tuple[str, str]:
    """
    Save private key and CSR to files.

    Args:
        output_dir: Directory to save files.
        common_name: CN used for filenames.
        key_pem: PEM-encoded private key.
        csr_pem: PEM-encoded CSR.

    Returns:
        (key_path, csr_path)
    """
    os.makedirs(output_dir, exist_ok=True)

    # Sanitize CN for filename (replace * and . for Windows compatibility)
    safe_name = common_name.replace("*", "STAR").replace(" ", "_")

    key_path = os.path.join(output_dir, f"{safe_name}.key")
    csr_path = os.path.join(output_dir, f"{safe_name}.csr")

    with open(key_path, "wb") as f:
        f.write(key_pem)

    with open(csr_path, "wb") as f:
        f.write(csr_pem)

    return key_path, csr_path
