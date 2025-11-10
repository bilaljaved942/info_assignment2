"""X.509 certificate validation helpers.

This module provides functions to validate X.509 certificates:
- load_certificate(): Load a PEM certificate file
- load_private_key(): Load a PEM private key file
- validate_certificate(): Check if cert is valid and signed by CA
- get_common_name(): Extract CN from cert subject

The validation checks:
1. Certificate is signed by the given CA
2. Current time falls within cert's validity window
3. Common Name matches expected value (if provided)
"""

from datetime import datetime
from pathlib import Path
from typing import Optional, Union

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature


def load_certificate(path: Union[str, Path]) -> x509.Certificate:
    """Load an X.509 certificate from a PEM file."""
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def load_private_key(path: Union[str, Path]) -> rsa.RSAPrivateKey:
    """Load an RSA private key from a PEM file."""
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def get_common_name(cert: x509.Certificate) -> str:
    """Extract Common Name from certificate subject."""
    return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value


def validate_certificate(
    cert: x509.Certificate,
    ca_cert: x509.Certificate,
    expected_cn: Optional[str] = None,
    check_time: Optional[datetime] = None,
) -> bool:
    """Validate that a certificate is signed by CA and currently valid.
    
    Args:
        cert: The certificate to validate
        ca_cert: The CA certificate that should have signed it
        expected_cn: If provided, validate cert's CN matches this
        check_time: Time to check validity for (default: current time)
    
    Returns:
        True if certificate is valid, False otherwise
    
    Raises:
        ValueError: If cert or CA cert is malformed
    """
    if check_time is None:
        check_time = datetime.utcnow()

    # Check validity period
    if check_time < cert.not_valid_before or check_time > cert.not_valid_after:
        return False

    # Verify CA signature
    try:
        # Explicitly specify the hash algorithm since it's required
        ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm or hashes.SHA256(),
        )
    except InvalidSignature:
        return False

    # Check CN if requested
    if expected_cn is not None:
        cn = get_common_name(cert)
        if cn != expected_cn:
            return False

    return True


if __name__ == "__main__":
    # Test validation using the certs we generated
    ca = load_certificate("certs/ca/ca.crt")
    server = load_certificate("certs/server/server.crt")
    client = load_certificate("certs/client/client.crt")

    print("Testing certificate validation...")
    print(f"CA CN: {get_common_name(ca)}")
    print(f"Server cert CN: {get_common_name(server)}")
    print(f"Client cert CN: {get_common_name(client)}")

    # Validate server cert
    valid = validate_certificate(server, ca, expected_cn="server.local")
    print(f"Server cert valid: {valid}")

    # Validate client cert
    valid = validate_certificate(client, ca, expected_cn="client.local")
    print(f"Client cert valid: {valid}")
