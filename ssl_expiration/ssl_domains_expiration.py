#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""Check the remaining days for the expiration of a domain's SSL certificate."""

from datetime import datetime
import argparse
import socket
import ssl

CA_CERTS = './cacert.pem'

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
            return "Certificate date format unknown."

        expire_in = expire_date - datetime.now()
        if expire_in.days > 0:
            return expire_in.days
        else:
            return "Expired!"


def main():
    """Main function"""
    parser = argparse.ArgumentParser()
    parser.add_argument('hosts', help='specify a list of hosts to connect to')
    parser.add_argument('-d', '--days', help='days remaining to alert', type=int, default=30)
    args = parser.parse_args()

    alert_buffer = []

    print("Hosts list:\n")

    with open(args.hosts) as hosts:
        for host in hosts:
            host = host.strip()

            if host == '' or host.startswith('#') or host.startswith('['):
                continue

            result = '+ ' + host.strip() + ' '

            # Check the DNS name
            try:
                socket.getaddrinfo(host, 443)[0][4][0]
            except socket.gaierror as err:
                result += str(err)
                alert_buffer.append(result)
                print(result)
                continue

            try:
                context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                context.verify_mode = ssl.CERT_OPTIONAL
                context.check_hostname = True
                context.load_verify_locations(cafile=CA_CERTS)
                context.load_default_certs()

                socket.setdefaulttimeout(60)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                ssl_sock = context.wrap_socket(sock, server_hostname=host)
                ssl_sock.connect((host, 443))

                cert = ssl_sock.getpeercert()

                if not pyssl_check_hostname(cert, host):
                    result += '[Error: Hostname does not match!]'
                    alert_buffer.append(result)
                    print(result)
                    continue

                days_to_expire = pyssl_check_expiration(cert)
                result += str(pyssl_check_expiration(cert))
                if days_to_expire < int(args.days):
                    alert_buffer.append(result)

                ssl_sock.shutdown(socket.SHUT_RDWR)

            except ssl.SSLError as err:
                result += '[' + str(err) + ']'
                alert_buffer.append(result)
                print(result)
                continue
            except ssl.CertificateError:
                result += "[SSL Certificate Error]"
                alert_buffer.append(result)
                print(result)
                continue
            except socket.timeout:
                result += "[Socket timeout]"
                alert_buffer.append(result)
                print(result)
                continue
            except ConnectionRefusedError:
                result += "[Connection refused]"
                alert_buffer.append(result)
                print(result)
                continue


            print(result)


    if len(alert_buffer) > 0:
        print("\n\nHost lists to take care about:\n")

        for host in alert_buffer:
            print(host)

        exit(1)
    else:
        print("\nAll hosts are OK!")
        exit(0)


if __name__ == "__main__":
    main()

 