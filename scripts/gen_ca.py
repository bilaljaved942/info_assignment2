"""Create a Root CA (RSA private key + self-signed X.509 certificate).

Generates a 4096-bit RSA key and a self-signed certificate and writes
them as PEM files under the `certs/ca` directory by default.

Example:
	python scripts/gen_ca.py --name "FAST-NU Root CA"
"""

import argparse
import os
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def main():
	parser = argparse.ArgumentParser(description="Generate a Root CA (self-signed)")
	parser.add_argument("--name", required=True, help="Common Name for the Root CA")
	parser.add_argument("--outdir", default="certs/ca", help="Output directory for CA files")
	parser.add_argument("--days", type=int, default=3650, help="Validity period in days (default 10 years)")
	args = parser.parse_args()

	outdir = args.outdir
	os.makedirs(outdir, exist_ok=True)

	# generate RSA private key
	key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

	subject = issuer = x509.Name([
		x509.NameAttribute(NameOID.COMMON_NAME, args.name),
	])

	now = datetime.utcnow()
	cert = (
		x509.CertificateBuilder()
		.subject_name(subject)
		.issuer_name(issuer)
		.public_key(key.public_key())
		.serial_number(x509.random_serial_number())
		.not_valid_before(now)
		.not_valid_after(now + timedelta(days=args.days))
		.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
		.add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
		.add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=False, key_cert_sign=True, key_agreement=False, content_commitment=False, data_encipherment=False, crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
		.sign(key, hashes.SHA256())
	)

	key_path = os.path.join(outdir, "ca.key")
	cert_path = os.path.join(outdir, "ca.crt")

	# write private key
	with open(key_path, "wb") as f:
		f.write(
			key.private_bytes(
				encoding=serialization.Encoding.PEM,
				format=serialization.PrivateFormat.TraditionalOpenSSL,
				encryption_algorithm=serialization.NoEncryption(),
			)
		)

	# write certificate
	with open(cert_path, "wb") as f:
		f.write(cert.public_bytes(serialization.Encoding.PEM))

	print(f"Wrote CA key: {key_path}")
	print(f"Wrote CA cert: {cert_path}")


if __name__ == "__main__":
	main()
