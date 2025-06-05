# prtg-scriptv2-starttls_certificate

This PRTG Script v2 sensor monitors SSL Certificates of connections which
require STARTTLS to initialize a secure channel.

## Sensor Summary

    Script Language: Python 3.13+
    Version: 1.0.0
    Author: Andreas Strobl <andreas.strobl@fh-salzburg.ac.at>
    Verified PRTG Version: 25.2.106
    Dependencies: cryptography >=45.0.2, certifi

## Sensor Description

This custom _Script v2_ sensor will monitor SSL certificates that require a
protocol handshake prior to reading certificate data, and exposes the collected
data in channels similar to PRTG's built-in _SSL Certificate_ sensor.

The following application layer protocols are supported:

* `SMTP`: Simple Mail Transfer Protocol,
          [RFC 5321](https://www.rfc-editor.org/rfc/rfc5321)
* `LMTP`: Local Mail Transfer Protocol,
          [RFC 2033](https://datatracker.ietf.org/doc/html/rfc2033)
* `LDAP`: Lightweight Directory Access Protocol,
          [RFC 4511](https://datatracker.ietf.org/doc/html/rfc4511)

The _LDAP_ protocol handshake has been tested against _Active Directory_,
_OpenLDAP_, and _Sun Enterprise Directory Server_ (formerly _Netscape iPlanet
Directory Server_) and is also expected to work with _RedHat DS 389_ directory
server.

## Sensor Channels

The following channels are implemented:

* `Days until Expiration` (id=12)
* `Root Authority Trusted` (id=13)
* `Public Key Size` (id=15) including support for ECC and RSA keys
* `Self-Signed` (id=16)
* `Common Name Check` (id=17)

### Common Name Check

PRTGs built-in _SSL Certificate_ sensor allows also to validate `SNI Domainname`
values. Since this is in essence a check of an user-specified domain name
against the _commonName_ and/or _subjectAltName_ attribute of the certificate,
this sensor ommits the result values _SNI Domainname matches_ and
_SNI Domainname does not match_.

If the device's network address is specified as domain name and is the same
as contained in the certificate, the parameter `--sni-domain` can be omitted.

### Root Authority Trusted

This check uses the verify methods of the `x509` cryptography module.
Certificates are loaded from the `certifi` module and optionally from a file
containing certificates of own CAs or intermediates certificates in _PEM_
format. This behaviour can be controlled with the options `--ca-trust` and
`--system-ca-trust`. The former parameter expects a file containing additional
CA certificates in PEM format the latter - a switch - uses only CA certificates
from the system's CA trust store to verify the certificate path (chain).

> **Note**
>
> Verifying the certificate path loads CA certificates from various locations.
> This is done with the `x509` module of the `cryptography` package.
> If any of the loaded certificates has an invalid serial number it emits a
> warning to STDERR and in future updates raises an exception. This is the
> reason why certificates with invalid serial numbers are excluded from the
> list of CA certificates used to verify the path of the peer certificate.

## Sensor Parameters

The sensor expects positional parameters `device`, `port`, and `protocol`.
If the device address is specified with the IP address of the device the
option `--sni-domain` is required.

Name checking is controlled with option `--name-validation` (`CN` and `CN/SAN`)
and works the same way as the built-in *SSL sensor*. Options `--ca-trust` and
`--system-ca-trust` affect the certificate path validation.

The help of the sensor can be shown with `--help` or `-h`.

### Examples

1. The following parameter string validates the certificate of a mail server
listening on port 7025 and expecting the _LMTP_ protocol. The certificate
contains multiple names in the _subjectAltName_ attribute, the device address
is specified as domain name and is contained in the _subjectAltName_ attribute:

    `starttls_certificate.py --name-validation CN/SAN --system-ca-trust
%host 7025 lmtp`

1. In this example the device address is specified as IP address, the server
is a mail server listening on port 25 with the _SMTP_ protocol:

    `starttls_certificate.py --sni-domain mta.example.com --name-validation CN
%host 25 smtp`
