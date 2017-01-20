#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""Check the remaining days for the expiration of a domain's SSL certificate."""

from datetime import datetime
import argparse
import socket
import ssl

CA_CERTS = './cacert.pem'


def exit_error(errcode, errtext):
    """Return error code and text"""
    print(errtext)
    exit(errcode)


def pyssl_check_hostname(cert, hostname):
    """Return True if valid. False is invalid"""
    if 'subjectAltName' in cert:
        for typ, val in cert['subjectAltName']:
            # Wilcard
            if typ == 'DNS' and val.startswith('*'):
                if val[2:] == hostname.split('.', 1)[1]:
                    return True
            # Normal hostnames
            elif typ == 'DNS' and val == hostname:
                return True
    else:
        return False


def pyssl_check_expiration(cert):
    """Return the numbers of day before expiration. False if expired."""
    if 'notAfter' in cert:
        try:
            expire_date = datetime.strptime(cert['notAfter'],
                                            "%b %d %H:%M:%S %Y %Z")
        except ValueError:
            exit_error(1, "Certificate date format unknown.")

        expire_in = expire_date - datetime.now()
        if expire_in.days > 0:
            return expire_in.days
        else:
            return False


def main():
    """Main function"""
    parser = argparse.ArgumentParser()
    parser.add_argument('host', help='specify an host to connect to')
    parser.add_argument('-p', '--port', help='specify a port to connect to',
                        type=int, default=443)
    args = parser.parse_args()

    host = args.host
    port = args.port

    # Check the DNS name
    try:
        socket.getaddrinfo(host, port)[0][4][0]
    except socket.gaierror as err:
        exit_error(1, err)

    # Connect to the host and get the certificate
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))

    try:
        ssl_sock = ssl.wrap_socket(sock, cert_reqs=ssl.CERT_REQUIRED,
                                   ca_certs=CA_CERTS,
                                   ciphers=("HIGH:-aNULL:-eNULL:"
                                            "-PSK:RC4-SHA:RC4-MD5"))

        cert = ssl_sock.getpeercert()
        if not pyssl_check_hostname(cert, host):
            print("Error: Hostname does not match!")

        print(pyssl_check_expiration(cert))

        ssl_sock.shutdown(socket.SHUT_RDWR)

    except ssl.SSLError as err:
        exit_error(1, err)


if __name__ == "__main__":
    main()

 