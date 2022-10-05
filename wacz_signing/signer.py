import os
from dotenv import load_dotenv
import logging

import rfc3161ng
import base64
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.backends import default_backend
from pyasn1.codec.der import encoder
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
import binascii
import pem
import zipfile
import json
from ._version import __version__
from .material import ts_chain

load_dotenv()

logging.basicConfig(level=logging.DEBUG
                    if os.getenv('LOGLEVEL') == 'DEBUG'
                    else logging.INFO)

stamp_duration = timedelta(
    minutes=int(os.getenv('STAMP_DURATION', '10'))
)


def verify_wacz(wacz):
    """ Verify the signature in a WACZ file """

    with zipfile.ZipFile(wacz) as z:
        for filename in z.namelist():
            if filename != "datapackage-digest.json":
                continue

        file = z.open(filename)
        try:
            data = json.loads(file.read())
        except json.JSONDecodeError as e:
            raise VerificationException(f"digest is ill-formed: {e}")

        try:
            return verify(data["signedData"])
        except KeyError:
            raise VerificationException(f"{wacz} is unsigned")

    return VerificationException(f"{wacz} is missing datapackage-digest.json")


def sign(string, dt):
    """ Sign and timestamp a string """

    # get target domain
    domain = os.getenv('DOMAIN')
    if not domain:
        raise SigningException("You must specify a DOMAIN")

    # load cert and private key material
    keyfile = None
    private_key = None
    cert_pem = os.getenv('CERT')
    if not cert_pem:
        certfile = os.getenv('CERTFILE')
        if not certfile:
            certname = os.getenv('CERTNAME')
            if not certname:
                raise SigningException("You must specify a certificate "
                                       "with CERT, CERTFILE, or CERTNAME")
            certdir = f'/etc/letsencrypt/live/{certname}'
            certfile = f'{certdir}/fullchain.pem'
            keyfile = f'{certdir}/privkey.pem'
        with open(certfile, 'rb') as f:
            cert_pem = f.read()
    if not keyfile:
        if os.getenv('KEY'):
            private_key = load_pem_private_key(os.getenv('KEY'), password=None)
        else:
            keyfile = os.getenv('KEYFILE')
            if not keyfile:
                raise SigningException("You must specify a key "
                                       "with KEY or KEYFILE")
    if not private_key:
        with open(keyfile, 'rb') as f:
            try:
                private_key = load_pem_private_key(f.read(), password=None)
            except Exception as e:
                raise SigningException(f'Failed to load private key: {e}')

    # prepare timestamper; TS_CERTFILE trumps TS_CERT
    ts_cert = os.getenv('TS_CERT', ts_chain.encode("ascii"))
    ts_certfile = os.getenv('TS_CERTFILE')
    if ts_certfile:
        try:
            with open(ts_certfile, 'rb') as f:
                ts_cert = f.read()
        except FileNotFoundError:
            raise SigningException("{ts_certfile} not found: "
                                   "You must specify a timestamper cert "
                                   "with TS_CERT or TS_CERTFILE")

    ts_url = os.getenv('TS_URL', 'http://freetsa.org/tsr')

    try:
        timestamper = rfc3161ng.RemoteTimestamper(
            ts_url, certificate=ts_cert, hashname="sha256"
        )
    except Exception as e:
        raise SigningException(f'Failed to create timestamper: {e}')

    # create the signature
    signature = base64.b64encode(
        private_key.sign(
            string.encode("ascii"),
            algorithm=hashes.SHA256(),
            padding=padding.PKCS1v15()
        )
    ).decode("ascii")

    # create the time signature
    tsr = timestamper(signature.encode("ascii"), return_tsr=True)
    timestamp_token = tsr.time_stamp_token
    result = encoder.encode(tsr)
    time_signature = base64.b64encode(result)
    timestamp = rfc3161ng.get_timestamp(timestamp_token)

    check_range(dt, timestamp, stamp_duration, SigningException)

    return {
        'software': f"wacz-signing {__version__}",
        'hash': string,
        'created': dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        'signature': signature,
        'timeSignature': time_signature,
        'domain': domain,
        'domainCert': cert_pem,
        'timestampCert': ts_cert,
    }


def verify(signed_req):
    """ Verify a signed and timestamped string """

    # fingerprints (sha-256) of trusted domain and timestamp root certificates
    domain_cert_roots = [
        # Lets Encrypt Root CA X3
        '6d99fb265eb1c5b3744765fcbc648f3cd8e1bffafdc4c2f99b9d47cf7ff1c24f',
    ]

    # add comma-separated cert roots in an env var; this is useful for testing
    additional_cert_roots = os.getenv('CERT_ROOTS')
    if additional_cert_roots:
        domain_cert_roots += additional_cert_roots.split(',')

    timestamp_cert_roots = [
        # freetsa.org Root CA (self-signed)
        'a6379e7cecc05faa3cbf076013d745e327bbbaa38c0b9af22469d4701d18aabc'
    ]
    additional_timestamp_roots = os.getenv('TS_ROOTS')
    if additional_timestamp_roots:
        timestamp_cert_roots += additional_timestamp_roots.split(',')

    duration = timedelta(days=int(os.getenv('CERT_DURATION', '7')))

    logging.debug(f'Signing software: {signed_req["software"]}')

    certs = validate_cert_chain(ensure_bytes(signed_req["domainCert"]))

    cert = certs[0]

    if not get_fingerprint(certs[-1]) in domain_cert_roots:
        raise VerificationException("Cert fingerprint is not in chain")

    # mkcert does not provide common name or subject alternative name,
    # so we do without, for testing.
    try:
        mkcert = cert.subject.get_attributes_for_oid(
            NameOID.ORGANIZATION_NAME
        )[0].value == 'mkcert development certificate'
    except IndexError:
        mkcert = None
    if not mkcert:
        domain = cert.subject.get_attributes_for_oid(
            NameOID.COMMON_NAME
        )[0].value

        domains = [n.value
                   for n
                   in cert.extensions.get_extension_for_oid(
                       ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                   ).value]

        assert domain in domains
        assert signed_req["domain"] in domains

    created = ensure_dt(signed_req["created"])

    if cert.not_valid_before > created:
        raise VerificationFailure(
            "signature created before cert existence"
        )
    if created > cert.not_valid_before + duration:
        raise VerificationFailure(
            "signature created after claimed cert duration"
        )

    # verify timestamp
    resp = rfc3161ng.decode_timestamp_response(
        base64.b64decode(signed_req["timeSignature"])
    )
    timestamp_token = resp.time_stamp_token

    # verify timestamp was signed by the existing cert
    rfc3161ng.check_timestamp(
        timestamp_token,
        certificate=ensure_bytes(signed_req["timestampCert"]),
        data=signed_req["signature"].encode("ascii"),
        hashname="sha256",
    )
    timestamp = rfc3161ng.get_timestamp(timestamp_token)

    if not timestamp:
        raise VerificationFailure("unable to verify timestamp")

    check_range(created, timestamp, stamp_duration, VerificationFailure)

    timestamp_certs = validate_cert_chain(
        ensure_bytes(signed_req["timestampCert"])
    )

    if not timestamp_certs:
        raise VerificationException("unable to validate timestamper chain")

    if not get_fingerprint(timestamp_certs[-1]) in timestamp_cert_roots:
        raise VerificationException("timestamper cert is not in chain")

    return {
        'observer': ['mkcert'] if mkcert else domains,
        'software': signed_req['software'],
        'timestamp': timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    }


def ensure_bytes(cert):
    return bytes(cert, encoding='ascii') if isinstance(cert, str) else cert


def ensure_dt(ts):
    if isinstance(ts, datetime):
        return ts
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")


def get_fingerprint(cert):
    return binascii.b2a_hex(
        cert.fingerprint(hashes.SHA256())
    ).decode("ascii")


def validate_cert_chain(cert_pem):
    """Validate a cert chain stored in PEM file.
    Each cert is validated with key of next cert in PEM file
    Returns all parsed certs, last cert being the root
    """
    prev_cert = None
    certs = []
    for c in pem.parse(cert_pem):
        cert = x509.load_pem_x509_certificate(c.as_bytes(),
                                              backend=default_backend())
        certs.append(cert)
        if prev_cert:
            if not validate_cert(prev_cert, cert.public_key()):
                return None

        prev_cert = cert

    return certs


def validate_cert(cert, public_key):
    """Validation of cert with issuer cert public key (RSA or ECDSA only)
    Does not alone imply the cert is trusted.
    """
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm),
            )

        # only supported RSA and ECDSA certs
        else:
            return False

        return True
    except Exception:
        return False


def check_range(dt, timestamp, stamp_duration, exception):
    # dt must be older than timestamp
    # since dt can have fractional seconds and timestamp does not, we
    # offer a second's grace
    if dt - timedelta(seconds=1) > timestamp:
        raise exception(f"{dt} is later than timestamp {timestamp}")

    # dt must be no older than timestamp than stamp_duration
    if not dt > timestamp - stamp_duration:
        raise exception(f"{dt} is more than {stamp_duration} "
                        f"older than timestamp {timestamp}")


class SigningException(BaseException):
    """ Raise for errors in signing """


class VerificationException(BaseException):
    """ Raise for errors in verification """


class VerificationFailure(BaseException):
    """ Raise for errors in verification """
