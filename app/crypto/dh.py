"""Classic Diffie-Hellman key exchange with RFC 3526 Group 14 (2048-bit).

This module provides helpers for DH key exchange:
- gen_private_key(): Generate a random private key
- get_public_value(): Calculate g^x mod p
- get_shared_secret(): Calculate (g^y)^x mod p
- derive_key(): Trunc16(SHA256(shared_secret))

The assignment uses the standard 2048-bit MODP Group (Group 14)
from RFC 3526 to ensure a secure key exchange.
"""

import os
from typing import Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from ..common.utils import sha256_hex

# RFC 3526 MODP Group 14 parameters (2048-bit)
P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    + "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    + "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    + "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    + "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    + "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    + "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    + "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    + "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    + "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    + "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
G = 2

# Parameter object for Group 14
PARAMETERS = dh.DHParameterNumbers(P, G).parameters()


def gen_private_key() -> int:
    """Generate a random DH private key value."""
    # The range is [2, p-2] as per DH requirements
    private_key = PARAMETERS.generate_private_key()
    return private_key.private_numbers().x


def get_public_value(private_key: int) -> int:
    """Calculate g^private_key mod p (the public DH value)."""
    # Create a private key object with our parameters
    key = dh.DHPrivateNumbers(
        private_key,
        dh.DHPublicNumbers(pow(G, private_key, P), PARAMETERS.parameter_numbers())
    ).private_key()
    return key.public_key().public_numbers().y


def get_shared_secret(my_private: int, other_public: int) -> bytes:
    """Calculate the shared secret (other_public)^my_private mod p."""
    # Recreate my private key and the peer's public key
    priv = dh.DHPrivateNumbers(
        my_private,
        dh.DHPublicNumbers(pow(G, my_private, P), PARAMETERS.parameter_numbers())
    ).private_key()
    
    pub = dh.DHPublicNumbers(
        other_public, PARAMETERS.parameter_numbers()
    ).public_key()

    # Get shared secret as bytes
    return priv.exchange(pub)


def derive_key(shared_secret: bytes) -> bytes:
    """Derive an AES-128 key from the DH shared secret using SHA-256."""
    # Take first 16 bytes (128 bits) of the SHA-256 hash
    return bytes.fromhex(sha256_hex(shared_secret))[:16]


if __name__ == "__main__":
    # Example key exchange between Alice and Bob
    print("Testing DH key exchange...")
    
    # Alice generates her keypair
    a_priv = gen_private_key()
    a_pub = get_public_value(a_priv)
    print(f"Alice pub: {a_pub:x}")
    
    # Bob generates his keypair
    b_priv = gen_private_key()
    b_pub = get_public_value(b_priv)
    print(f"Bob pub: {b_pub:x}")
    
    # Both derive the shared secret
    secret1 = get_shared_secret(a_priv, b_pub)
    secret2 = get_shared_secret(b_priv, a_pub)
    print("Shared secrets match:", secret1 == secret2)
    
    # Derive AES keys
    key1 = derive_key(secret1)
    key2 = derive_key(secret2)
    print("Derived keys match:", key1 == key2)
    print("Key (hex):", key1.hex())
