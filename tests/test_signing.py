import pytest
import subprocess
import os
from wacz_signing import signer
from datetime import datetime, timedelta
from pathlib import Path
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import ec, rsa


t = Path('tests/test_files')


def test_happy_path_rsa(mkcert_rsa):
    result = signer.sign('hello, world', datetime.utcnow())
    check = signer.verify(result)
    assert check['observer'] == ['mkcert']


def test_late_signature_rsa(mkcert_rsa):
    with pytest.raises(signer.SigningException) as e:
        signer.sign('hello, world', datetime.utcnow() + timedelta(days=8))
        assert "is later than timestamp" in str(e.value)


def test_early_signature_rsa(mkcert_rsa):
    with pytest.raises(signer.SigningException) as e:
        signer.sign('hello, world', datetime.utcnow() - timedelta(hours=1))
        assert "older than timestamp" in str(e.value)


def test_happy_path_ecdsa(mkcert_ecdsa):
    result = signer.sign('hello, world', datetime.utcnow())
    check = signer.verify(result)
    assert check['observer'] == ['mkcert']


def test_late_signature_ecdsa(mkcert_ecdsa):
    with pytest.raises(signer.SigningException) as e:
        signer.sign('hello, world', datetime.utcnow() + timedelta(days=8))
        assert "is later than timestamp" in str(e.value)


def test_early_signature_ecdsa(mkcert_ecdsa):
    with pytest.raises(signer.SigningException) as e:
        signer.sign('hello, world', datetime.utcnow() - timedelta(hours=1))
        assert "older than timestamp" in str(e.value)


def test_file_verification():
    result = signer.verify_wacz(t / 'valid_signed_example_1.wacz')
    assert result == {
        'observer': ['btrix-sign-test.webrecorder.net'],
        'software': 'authsigner 0.3.0',
        'timestamp': '2022-01-18T19:00:12Z'
    }


def test_invalid_file_verification():
    with pytest.raises(signer.VerificationException) as e:
        signer.verify_wacz(t / 'invalid_signed_example_1.wacz')
        assert "Cert fingerprint is not in chain" in str(e.value)


def test_unsigned_file():
    with pytest.raises(signer.VerificationException) as e:
        signer.verify_wacz(t / 'not-signed.wacz')
        assert "is unsigned" in str(e.value)


def test_file_illformed_digest():
    with pytest.raises(signer.VerificationException) as e:
        signer.verify_wacz(t / 'ill-digest.wacz')
        assert "digest is ill-formed" in str(e.value)


@pytest.mark.xfail(reason="We're still looking for a WACZ with no digest")
def test_file_no_digest():
    with pytest.raises(signer.VerificationException) as e:
        signer.verify_wacz(t / 'no-digest.wacz')
        assert "is missing datapackage-digest.json" in str(e.value)


@pytest.fixture
def mkcert_rsa(tmp_path):
    # set up cert and environment
    cmd = 'echo "$(mkcert -CAROOT)/rootCA.pem"'
    root_ca = subprocess.check_output(cmd, shell=True).decode("ascii").strip()

    cmd = f'cp "{root_ca}" .'
    subprocess.call(cmd, shell=True, cwd=tmp_path)

    cmd = 'mkcert -cert-file cert.pem -key-file key.pem example.org && ' \
        'cp cert.pem fullchain.pem && cat rootCA.pem >> fullchain.pem'
    subprocess.call(cmd, cwd=tmp_path, shell=True)
    assert (tmp_path / 'fullchain.pem').exists()

    os.environ['CERTFILE'] = str(tmp_path / "fullchain.pem")
    os.environ['KEYFILE'] = str(tmp_path / "key.pem")

    # confirm we have an RSA private key
    with open(os.environ['KEYFILE'], 'rb') as f:
        private_key = load_pem_private_key(f.read(), password=None)
        assert isinstance(private_key, rsa.RSAPrivateKey)

    cmd = 'openssl x509 -noout -in rootCA.pem -fingerprint -sha256'
    fingerprint = subprocess.check_output(
        cmd, shell=True, cwd=tmp_path
    ).decode("ascii").strip().split('=')[1].replace(':', '').lower()
    os.environ['CERT_ROOTS'] = f"{fingerprint}"

    yield


@pytest.fixture
def mkcert_ecdsa(tmp_path):
    # set up cert and environment
    cmd = 'echo "$(mkcert -CAROOT)/rootCA.pem"'
    root_ca = subprocess.check_output(cmd, shell=True).decode("ascii").strip()

    cmd = f'cp "{root_ca}" .'
    subprocess.call(cmd, shell=True, cwd=tmp_path)

    cmd = 'mkcert -ecdsa -cert-file cert.pem -key-file key.pem example.org && ' \
        'cp cert.pem fullchain.pem && cat rootCA.pem >> fullchain.pem'
    subprocess.call(cmd, cwd=tmp_path, shell=True)
    assert (tmp_path / 'fullchain.pem').exists()

    os.environ['CERTFILE'] = str(tmp_path / "fullchain.pem")
    os.environ['KEYFILE'] = str(tmp_path / "key.pem")

    # confirm we have an ECDSA private key
    with open(os.environ['KEYFILE'], 'rb') as f:
        private_key = load_pem_private_key(f.read(), password=None)
        assert isinstance(private_key, ec.EllipticCurvePrivateKey)

    cmd = 'openssl x509 -noout -in rootCA.pem -fingerprint -sha256'
    fingerprint = subprocess.check_output(
        cmd, shell=True, cwd=tmp_path
    ).decode("ascii").strip().split('=')[1].replace(':', '').lower()
    os.environ['CERT_ROOTS'] = f"{fingerprint}"

    yield
