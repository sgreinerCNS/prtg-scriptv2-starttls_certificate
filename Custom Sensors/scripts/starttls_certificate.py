#!/usr/bin/env python
"""Monitor certificates of services that require STARTTLS and return a JSON formatted sensor result.

This custom Python script sensor is used to monitor certificates of services that require STARTTLS
to initiate a secure transport. It takes the same parameter as the PRTG built-in sensor
`SSL Certificate` but additionally requires the protocol the sensor must use to communicate with
the remote endpoint.
The list of protocols is currently limited to `SMTP`, `LMTP`, and `LDAP`.

The sensor result in JSON contains the same channels as the `SSL Certificate` sensor except
channel `Revoked`. All channel IDs added the offset value of 10 (as required by the JSON schema)

The script requires the positional arguments host, port, and protocol. Options --sni-domain specifies
the common name as defined in the certificate, --name-validation <CN | CN/SAN> enables name validation,
and --ca-trust <path to file with trusted CA certs in PEM format> allows to add own signing CA certs
extending the certifi provided list of trusted CAs.

See https://stackoverflow.com/questions/16899247/how-can-i-decode-a-ssl-certificate-using-python,
See https://stackoverflow.com/questions/5108681/use-python-to-get-an-smtp-server-certificate
See https://stackoverflow.com/questions/71114085/how-can-i-retrieve-openldap-servers-starttls-certificate-with-pythons-ssl-libr
See Paessler KB 91900-how-can-i-make-my-python-scripts-work-with-the-script-v2-sensor
"""

import argparse
import datetime
import ipaddress
import json
import os
import shlex
import socket
import ssl
import sys
import certifi
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa

__version__ = '1.0.0'

def setup() -> argparse.Namespace:
    """Parses commandline arguments in tty-mode and via stdin stream

    :return: The parsed arguments from stdin.
    :rtype: argparse.Namespace
    """
    parser = argparse.ArgumentParser(
        prog='starttls_certificate',
        description='Monitors the certificate of services requiring STARTTLS TLS security.',
        exit_on_error=False
    )
    # Positional arguments
    parser.add_argument('device',
        help='Enter the IPv4 address or DNS name of the device.')
    parser.add_argument('port',
        type=int,
        help='Enter the port for the connection to the target endpoint.')
    parser.add_argument('protocol',
        choices=['smtp', 'lmtp', 'ldap'],
        help='Use the appropriate STARTTLS command before starting TLS.')

    # Options
    _help = 'Enter the host name that the sensor tries to query if your server'
    _help += ' has multiple certificates on the same IP address and port combination.'
    parser.add_argument('--sni-domain',
        nargs=1,
        help=_help)
    _help = 'Select if you want to validate the certificate by comparing the Common Name (CN)'
    _help += ' and optionally Subject Alternative Names (SAN) of the certificate subject'
    _help += ' with the parent device address or SNI.'
    parser.add_argument('--name-validation',
        nargs=1,
        choices=['CN', 'CN/SAN'],
        help=_help
    )
    parser.add_argument('--ca-trust',
        nargs=1,
        type=argparse.FileType('rb'),
        help='A file containing intermediate and trusted CAs in PEM format.'
    )
    parser.add_argument('--system-ca-trust',
        action='store_true',
        help='Use the system CA trust store instead of any other stores.')
    parser.add_argument('--version', '-V', action='version', version=f'%(prog)s {__version__}')
    try:
        if sys.stdin.isatty():
            args = parser.parse_args()
        else:
            pipestring = sys.stdin.read().rstrip()
            pipedargs = shlex.split(pipestring)
            args = parser.parse_args(pipedargs)
    except ValueError as err:
        fail(str(err))
    except argparse.ArgumentError as err:
        fail(str(err))

    # Perform some basic arg requirement checks
    # If device is a valid IP Address sni_domain is required
    try:
        if ipaddress.ip_address(args.device) and args.sni_domain is None:
            fail('Device specified by IP address requires --sni-domain set.')
    except ValueError:
        pass
    return args

def fail(message: str) -> None:
    """Converts any error message to a PRTG readable sensor data (JSON)

    The script prints the output as required by PRTG and exits the script immediately
    with exit code 0.
    See Paessler KB 91900-how-can-i-make-my-python-scripts-work-with-the-script-v2-sensor

    :param message: The message to show in the PRTG sensor error output.
    :type message: str
    """

    print(json.dumps(
        {
            "version": 2,
            "status": "error",
            "message": message
        }
    ))
    sys.exit(0)

def work(args: argparse.Namespace) -> dict:
    """Returns the sensor data as JSON parsable version 2 object.

    :param args: Parsed sys.stdin arguments.
    :type args: argparse.Namespace
    :return: A dictionary containing the required PRTG sensor properties.
    :rtype: dict
    """

    result = {
        'version': 2,
        'status': 'ok',
        'message': 'OK.',
        'channels': []
    }
    conn = connect(args.device, args.port, args.protocol)
    try:
        server_hostname = args.device
        if args.sni_domain:
            server_hostname = args.sni_domain[0]

        cert, conn = load_der_x509_certificate(conn, server_hostname)
        disconnect(conn, args.protocol)

        if cert is None:
            raise ValueError(f'ssl: Host did not offer certificate: {server_hostname}')

        if isinstance(args.name_validation, list):
            name_validation = args.name_validation[0]
        else:
            name_validation = args.name_validation
        # ca_trust contains an io.bufferedReader instance
        if isinstance(args.ca_trust, list):
            ca_trust= args.ca_trust[0].name
        else:
            # None
            ca_trust = args.ca_trust

        _message_parts = [
            f'OK. Certificate Common Name: {read_x509_certificate_common_name(cert)}',
            f'Certificate Thumbprint: {read_x509_certificate_fingerprint(cert)}',
            f'STARTTLS Protocol: {args.protocol.upper().strip()}'
        ]
        result['message'] = ' - '.join(_message_parts)
        channels = validate_certificate(cert,
                                        server_hostname,
                                        name_validation=name_validation,
                                        ca_trust=ca_trust,
                                        system_ca_trust=args.system_ca_trust)
        result['channels'] = channels

    except ValueError as err:
        fail(str(err))
    return result

def connect(host: str, port: int, protocol: str) -> socket.socket:
    """Connects to a device and performs the proper protocol greeting.

    :param host: IP address or hostname of the device.
    :type host: str
    :param port: Port the service is listening on the device.
    :type port: int
    :param protocol: Protocol that uses STARTTLS to secure the channel.
    :type protocol: str
    :return: Connection ready to communicate encrypted.
    :rtype: socket.socket"""

    match protocol:
        case 'lmtp':
            greeting_message = bytes(f'LHLO {socket.gethostname()}\n', 'ascii')
        case 'ldap':
            # Protocol.LDAP sends a LDAP_START_TLS_OID - gathered with Wireshark
            greeting_message = b'\x30\x1d\x02\x01\x01\x77\x18\x80\x16\x31\x2e\x33\x2e\x36\x2e\x31'
            greeting_message += b'\x2e\x34\x2e\x31\x2e\x31\x34\x36\x36\x2e\x32\x30\x30\x33\x37'
        case _:
            greeting_message = bytes(f'EHLO {socket.gethostname()}\n', 'ascii')

    addr = (host, port)
    msglen = 4096
    try:
        s = socket.create_connection(addr, timeout=2.0)
        match protocol:
            case 'lmtp' | 'smtp':
                _commands = [greeting_message, b'STARTTLS\n']
                # Read the servers SMTP greetings
                s.recv(msglen)
                # Execute commands
                for _cmd in _commands:
                    s.send(_cmd)
                    s.recv(msglen)

            case 'ldap':
                s.send(greeting_message)
                # Parse response - look for \x0a\x01 (result code introduced with
                # \x01 after \n (\x0a) - \x00 means ok, any other value an error)
                # and find \x04\x00\x04\x00 if the second \x04 is not followed by
                # \x00 then it seems that the server supports STARTTLS but has
                # no cert installed.
                # If the extended operation requested with the greeting message
                # succeeds the server returns a result code 0.
                _response = s.recv(msglen)
                _ldap_rc = _response.find(b'\n\x01\x00')
                if _ldap_rc == -1 or (_ldap_rc >= 0 and
                        _response.find(b'\x04\x00\x04\x00', _ldap_rc) == -1):
                    s.close()
                    raise OSError('LDAP unsupported extended operation')

    except OSError as err:
        fail(str(err))

    return s

def load_der_x509_certificate(connection: socket.socket,
                              sni_domain: str) -> tuple[x509.Certificate | None, ssl.SSLSocket]:
    """Reads the peer's binary certificate data and returns certificate and SSLSocket.

    :param connection: Connection with STARTTLS prepared and ready to communicate encrypted.
    :type connection: ssl.SSLSocket
    :param sni_domain: Server hostname if the device has multiple certificates on the same IP address.
    :type sni_domain: str
    :return: Tuple of certificate or None and the prepared SSL socket.
    :rtype: tuple[x509.Certificate | None, ssl.SSLSocket]
    """

    # Create a custom context based on TLS_CLIENT
    # disable hostname checking and verification
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        sslsocket = ctx.wrap_socket(connection, server_hostname=sni_domain)
        cert_der_data = sslsocket.getpeercert(binary_form=True)
        if cert_der_data is None:
            raise ValueError(f'Host "{sni_domain}" did not provide certificate.')
        cert = x509.load_der_x509_certificate(cert_der_data)
    except ssl.SSLError | ValueError:
        cert = None
    return cert, sslsocket

def disconnect(connection: ssl.SSLSocket, protocol: str) -> None:
    """Closes an established connection (socket) with the proper protocol commands.

    :param connection: Connection with STARTTLS prepared and ready to communicate encrypted.
    :type connection: ssl.SSLSocket
    :param protocol: Protocol that uses STARTTLS to secure the channel.
    :type protocol: str
    """

    msglen = 4096
    try:
        if protocol in ['smtp', 'lmtp']:
            connection.send(b'QUIT\n')
            connection.recv(msglen)
    finally:
        connection.close()

def validate_certificate(cert: x509.Certificate,
                         sni_domain: str,
                         name_validation: str | None=None,
                         ca_trust: str | None=None,
                         system_ca_trust: bool=False) -> list:
    """
    Validates the certificate data and generates a list of PRTG sensor channels.

    PRTG Custom Sensor channel IDs start with 10 or higher. This sensor uses the
    same IDs as the default SSL Certificate sensor but incremented by 10.

    :param cert: The certificate of the peer.
    :type cert: x509.Certificate
    :param sni_domain: Server hostname.
    :type sni_domain: str
    :param name_validation: Method how to validate the server hostname (CN, CN/SAN)
    :type name_validation: str, optional
    :param ca_trust: File of trusted CA certs in PEM format.
    :type ca_trust: str, optional
    :param system_ca_trust: Use the CA certificates of the system's certificate store.
    :type system_ca_trust: bool, optional
    :return: List of dicts with PRTG sensor channel properties.
    :rtype: list
    """

    channels = []
    # Channel 12 (2): Days to Expiration
    _check_value = cert.not_valid_after_utc - datetime.datetime.now(datetime.timezone.utc)
    channels.append({
        'id': 12,
        'name': 'Days to Expiration',
        'type': 'integer',
        'value': _check_value.days,
        'kind': 'count'
    })
    # Channel 13 (3): Root Authority Trusted
    # 0 - trusted, 1 - not trusted
    _check_value = validate_certificate_path(cert, sni_domain,
                                             ca_trust=ca_trust,
                                             system_ca_trust=system_ca_trust)
    channels.append({
        'id': 13,
        'name': 'Root Authority Trusted',
        'type': 'lookup',
        'value': _check_value,
        'lookup_name': 'prtg.standardlookups.sslcertificatesensor.trustedroot'
    })
    # Channel 15 (5): Public Key Length
    _check_value, _lookup_name = validate_certificate_public_key_length(cert)
    channels.append({
        'id': 15,
        'name': 'Public Key Length',
        'type': 'lookup',
        'value': _check_value,
        'lookup_name': _lookup_name
    })
    # Channel 16 (6): Self-Signed
    _check_value = cert.subject.rfc4514_string() == cert.issuer.rfc4514_string()
    channels.append({
        'id': 16,
        'name': 'Self-Signed',
        'type': 'lookup',
        'value': int(_check_value),
        'lookup_name': 'prtg.standardlookups.sslcertificatesensor.selfsigned'
    })
    # Channel 17 (7): Common Name Check
    _check_value = validate_certificate_common_name(cert,
                                                    sni_domain,
                                                    validation_method=name_validation)
    channels.append({
        'id': 17,
        'name': 'Common Name Check',
        'type': 'lookup',
        'value': _check_value,
        'lookup_name': 'prtg.standardlookups.sslcertificatesensor.cncheck'
    })
    return channels

def load_ca_trust_certificates(ca_trust_file: str | None=None) -> list:
    """Loads trusted CA certs from file or with certifi.

    Loading the certs in batch with cryptography emits a warning to stderr
    when loading certs with invalid `serial_number` value and warns that future
    versions will raise an exception.

    :param ca_trust_file: Path to a file of trusted intermediate CA certificates in PEM format.
    :type ca_trust_file: str, optional
    :return: A list with x509.Certificates.
    :rtype: list
    """

    ca_certs = []
    if ca_trust_file:
        _pem_file = ca_trust_file
    else:
        _pem_file = certifi.where()

    with open(_pem_file, 'rb') as ca_pems:
        _pem_data = ca_pems.read()
    # Split data into separate pems
    _ca_pems = _pem_data.split(b'-----END CERTIFICATE-----\n')[:-1]
    _ca_pems = list(map(lambda p: p + b'-----END CERTIFICATE-----\n',
                        _ca_pems))

    # Redirect stderr to devnull to prevent x509 deprecation warnings when loading
    # CA trust certs
    _stderr = sys.stderr
    sys.stderr = open(os.devnull, 'w')

    for _pem in _ca_pems:
        try:
            _cert = x509.load_pem_x509_certificate(_pem)
            if _cert.serial_number and _cert.serial_number > 0:
                ca_certs.append(_cert)
        except Exception:
            # Skip invalid certificates
            # This exception will be replaced with the proper x509 exception
            # when implemented with the cryptography module
            pass
    sys.stderr = _stderr
    return ca_certs

def load_system_ca_trust_certificates() -> list:
    """Loads trusted CA certs from the system's CA trust store.

    Loading the certs in batch with cryptography emits a warning to stderr
    when loading certs with invalid `serial_number` value and warns that future
    versions will raise an exception.

    :return: A list with x509.Certificates.
    :rtype: list
    """

    ca_certs = []
    _ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    _ca_ders = _ctx.get_ca_certs(binary_form=True)
    # Redirect stderr to devnull to prevent x509 deprecation warnings when loading
    # CA trust certs
    _stderr = sys.stderr
    sys.stderr = open(os.devnull, 'w')

    for _der in _ca_ders:
        try:
            _cert = x509.load_der_x509_certificate(_der)
            if _cert.serial_number and _cert.serial_number > 0:
                ca_certs.append(_cert)
        except Exception:
            # Skip invalid certificates
            # This exception will be replaced with the proper x509 exception
            # when implemented with the cryptography module
            pass
    sys.stderr = _stderr
    return ca_certs

def read_x509_certificate_san_extension_dnsnames(cert: x509.Certificate) -> list:
    """Reads the DNSName values of the cert's subjectAltName extension.

    :param cert: The certificate to read the extension's DNSName values.
    :type cert: x509.Certificate
    :return: A list with DNSName values or an empty list if the extension is not
             present
    :rtype: list
    """

    values = []
    try:
        extension = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        values = extension.value.get_values_for_type(x509.DNSName)  # pyrefly: ignore
        # Convert to lower case
        values = [x.lower().strip() for x in values]
    except x509.ExtensionNotFound:
        pass
    return values

def read_x509_certificate_common_name(cert: x509.Certificate) -> str:
    """Reads the certificate's subject CN value.

    :param cert: The certificate to read the subject's CN value.
    :type cert: x509.Certificate
    :return: The common name of the certificate.
    :rtype: str
    """

    cn_attributes = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if cn_attributes:
        return cn_attributes[0].value.lower().strip()
    return ''

def read_x509_certificate_fingerprint(cert: x509.Certificate) -> str:
    """Reads the certificate's SHA1 fingerprint.

    :param cert: The certificate to read the fingerprint from.
    :type cert: x509.Certificate
    :return: The certificate's SHA1 fingerprint in all caps letters.
    :rtype: str
    """

    fingerprint = cert.fingerprint(hashes.SHA1()).hex().upper()
    return fingerprint

def validate_certificate_public_key_length(cert: x509.Certificate) -> tuple[int, str]:
    """Validates the public key length of the certificate.

    :param cert: The certificate to validate.
    :type cert: x509.Certificate
    :return: The public key length and the lookup name.
    :rtype: tuple[int, str]
    """

    public_key = cert.public_key()
    lookup_name = 'prtg.standardlookups.sslcertificatesensor.publickeycc'
    if isinstance(public_key, rsa.RSAPublicKey):
        lookup_name = 'prtg.standardlookups.sslcertificatesensor.publickey'

    return public_key.key_size, lookup_name  # pyrefly: ignore

def validate_certificate_common_name(cert: x509.Certificate,
                                     sni_hostname: str,
                                     validation_method: str | None=None) -> int:
    """Validates the common name and optionally the SANs against the provided hostname.

    The return value matches the expected result specified in the lookup table
    `prtg.standardlookups.sslcertificatesensor.cncheck`.
    This script DOES NOT return all values since SNI check and common_name check
    are considered interchangeable.
    Expected return values based on method:
            Disable           : 2 (default)
            CN check ok       : 0
            CN check error    : 1
            CN/SAN check ok   : 5
            CN/SAN check error: 6

    :param cert: The certificate to validate.
    :type cert: x509.Certificate
    :param sni_hostname: SNI hostname
    :type sni_hostname: str
    :param validation_method: Type of name validation. CN or CN/SAN, default None
    :type validation_method: str | None
    :return: The validation result based on method or disabled.
    :rtype: int
    """

    check_result = 2
    sni_domain = sni_hostname.lower().strip()
    common_name = read_x509_certificate_common_name(cert)

    match validation_method:
        case 'CN':
            if common_name == sni_domain:
                check_result = 0
            else:
                check_result = 1
        case 'CN/SAN':
            # CN/SAN validation
            dns_names = read_x509_certificate_san_extension_dnsnames(cert)
            if common_name == sni_domain or sni_domain in dns_names:
                check_result = 5
            else:
                check_result = 6
    return check_result

def validate_certificate_path(cert: x509.Certificate,
                              sni_hostname: str,
                              ca_trust: str | None=None,
                              system_ca_trust: bool=False) -> int:
    """Validates the path of a certificate

    :param cert: The certificate to validate.
    :type cert: x509.Certificate
    :param sni_hostname: SNI hostname
    :type sni_hostname: str
    :param ca_trust: Path to file of trusted intermediate CA certificates in PEM format, default: None
    :type ca_trust: str, optional
    :param system_ca_trust: Use the CA certificates of the system's certificate store.
    :type system_ca_trust: bool, optional
    :return: The result of the path validation with 0 (trusted) and 1 not trusted).
    :rtype: int
    """

    validation_result = 1
    intermediate_ca_certs = []

    if system_ca_trust:
        root_ca_certs = load_system_ca_trust_certificates()
    else:
        root_ca_certs = load_ca_trust_certificates()
        intermediate_ca_certs = load_ca_trust_certificates(ca_trust_file=ca_trust)
    root_ca_store = x509.verification.Store(root_ca_certs)

    _verification_time = datetime.datetime.now(datetime.timezone.utc)
    x509_builder = x509.verification.PolicyBuilder().store(root_ca_store)
    x509_builder = x509_builder.time(_verification_time)
    x509_verifier = x509_builder.build_server_verifier(x509.DNSName(sni_hostname))
    try:
        x509_verifier.verify(cert, intermediate_ca_certs)
        validation_result = 0
    except x509.verification.VerificationError:
        pass
    return validation_result

def main():
    """
    starttls_certificate_sensor - Monitors the certificate of a STARTTLS-secured connection

    Monitors the SSL certificate of services that require the client to issue a STARTTLS command
    in order to start a secure connection.
    """
    args = setup()
    sensor_result = work(args)
    print(json.dumps(sensor_result))
    sys.exit(0)

if __name__ == "__main__":
    main()
