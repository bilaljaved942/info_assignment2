"""Issue a certificate signed by the provided Root CA.

Creates a private key and a certificate for the provided `--cn` (Common Name).
By default it writes `{out}.key` and `{out}.crt` where `out` is the path
prefix supplied via `--out` (example: `--out certs/server` -> `certs/server.key`, `certs/server.crt`).

Example:
	python scripts/gen_cert.py --cn server.local --out certs/server
"""

import argparse
import os
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def load_pem_private_key(path: str):
	with open(path, "rb") as f:
		return serialization.load_pem_private_key(f.read(), password=None)


def load_pem_cert(path: str):
	with open(path, "rb") as f:
		return x509.load_pem_x509_certificate(f.read())


def main():
	parser = argparse.ArgumentParser(description="Issue a certificate signed by a Root CA")
	parser.add_argument("--cn", required=True, help="Common Name (CN) for the certificate")
	parser.add_argument("--out", required=True, help="Output path prefix (e.g. certs/server)")
	parser.add_argument("--ca-cert", default="certs/ca/ca.crt", help="Path to CA certificate PEM")
	parser.add_argument("--ca-key", default="certs/ca/ca.key", help="Path to CA private key PEM")
	parser.add_argument("--days", type=int, default=825, help="Validity period in days (default ~2 years)")
	args = parser.parse_args()

	# load CA
	ca_cert = load_pem_cert(args.ca_cert)
	ca_key = load_pem_private_key(args.ca_key)

	# ensure output dir exists
	outdir = os.path.dirname(args.out)
	if outdir:
		os.makedirs(outdir, exist_ok=True)

	# generate key for leaf
	key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

	subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, args.cn)])

	now = datetime.utcnow()
	cert_builder = (
		x509.CertificateBuilder()
		.subject_name(subject)
		.issuer_name(ca_cert.subject)
		.public_key(key.public_key())
		.serial_number(x509.random_serial_number())
		.not_valid_before(now)
		.not_valid_after(now + timedelta(days=args.days))
		.add_extension(x509.SubjectAlternativeName([x509.DNSName(args.cn)]), critical=False)
	)

	cert = cert_builder.sign(private_key=ca_key, algorithm=hashes.SHA256())

	key_path = f"{args.out}.key"
	cert_path = f"{args.out}.crt"

	with open(key_path, "wb") as f:
		f.write(
			key.private_bytes(
				encoding=serialization.Encoding.PEM,
				format=serialization.PrivateFormat.TraditionalOpenSSL,
				encryption_algorithm=serialization.NoEncryption(),
			)
		)

	with open(cert_path, "wb") as f:
		f.write(cert.public_bytes(serialization.Encoding.PEM))

	print(f"Wrote key: {key_path}")
	print(f"Wrote cert: {cert_path}")


if __name__ == "__main__":
	main()
