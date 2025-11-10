"""RSA PKCS#1 v1.5 signing with SHA-256.

This module provides functions for signing and verifying messages:
- sign_message(): Sign data with RSA private key (PKCS#1, SHA256)
- verify_signature(): Verify signature with RSA public key
- load_private_key(): Load RSA key from PEM file
- load_public_key(): Load RSA public key from cert

All functions handle both string and bytes input. Signatures are
returned/accepted as raw bytes, use b64 helpers for wire format.
"""

from pathlib import Path
from typing import Union

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from ..common.utils import sha256_hex


def load_private_key(path: Union[str, Path]) -> rsa.RSAPrivateKey:
    """Load an RSA private key from a PEM file."""
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_public_key(cert_path: Union[str, Path]) -> rsa.RSAPublicKey:
    """Load the RSA public key from an X.509 certificate file."""
    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
        return cert.public_key()


def sign_message(key: rsa.RSAPrivateKey, message: Union[str, bytes]) -> bytes:
    """Sign a message using RSA PKCS#1 v1.5 with SHA-256.
    
    Args:
        key: RSA private key for signing
        message: The message to sign (str or bytes)
    
    Returns:
        Raw signature bytes (use b64encode for wire format)
    """
    if isinstance(message, str):
        message = message.encode("utf-8")

    return key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256()
    )


def verify_signature(
    key: rsa.RSAPublicKey,
    message: Union[str, bytes],
    signature: bytes,
) -> bool:
    """Verify an RSA PKCS#1 v1.5 SHA-256 signature.
    
    Args:
        key: RSA public key that should verify the signature
        message: The message that was signed (str or bytes)
        signature: Raw signature bytes (from sign_message)
    
    Returns:
        True if signature is valid, False otherwise
    """
    if isinstance(message, str):
        message = message.encode("utf-8")

    try:
        key.verify(
            signature,
            message,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False


if __name__ == "__main__":
    # Test signing/verification using our generated keys
    print("Testing RSA signing...")
    
    # Load keys
    private_key = load_private_key("certs/server/server.key")
    public_key = load_public_key("certs/server/server.crt")
    
    # Test with string message
    message = "Hello, this is a test message"
    sig = sign_message(private_key, message)
    valid = verify_signature(public_key, message, sig)
    print(f"Original signature valid: {valid}")
    
    # Test with modified message
    valid = verify_signature(public_key, message + "!", sig)
    print(f"Modified message verifies: {valid}")  # should be False
    
    # Test with binary data
    binary = b"\x00\x01\x02\x03\x04"
    sig2 = sign_message(private_key, binary)
    valid = verify_signature(public_key, binary, sig2)
    print(f"Binary data signature valid: {valid}")
