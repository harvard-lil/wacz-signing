import pytest
import subprocess
import os
from wacz_signing import signer
from datetime import datetime, timedelta


def test_happy_path(mkcert):
    result = signer.sign('hello, world', datetime.utcnow())
    check = signer.verify(result)
    assert check['observer'] == ['mkcert']


def test_late_signature(mkcert):
    with pytest.raises(signer.SigningException) as e:
        signer.sign('hello, world', datetime.utcnow() + timedelta(days=8))
        assert "is later than timestamp" in str(e.value)


def test_early_signature(mkcert):
    with pytest.raises(signer.SigningException) as e:
        signer.sign('hello, world', datetime.utcnow() - timedelta(hours=1))
        assert "older than timestamp" in str(e.value)


def test_file_verification():
    result = signer.verify_wacz('valid_signed_example_1.wacz')
    assert result == {
        'observer': ['btrix-sign-test.webrecorder.net'],
        'software': 'authsigner 0.3.0',
        'timestamp': '2022-01-18T19:00:12Z'
    }


def test_invalid_file_verification():
    with pytest.raises(signer.VerificationException) as e:
        signer.verify_wacz('invalid_signed_example_1.wacz')
        assert "Cert fingerprint is not in chain" in str(e.value)


@pytest.fixture
def mkcert(tmp_path):
    # set up cert and environment
    cmd = 'echo "$(mkcert -CAROOT)/rootCA.pem"'
    root_ca = subprocess.check_output(cmd, shell=True).decode('utf-8').strip()

    cmd = f'cp "{root_ca}" .'
    subprocess.call(cmd, shell=True, cwd=tmp_path)

    cmd = 'mkcert -cert-file cert.pem -key-file key.pem example.org && ' \
        'cp cert.pem fullchain.pem && cat rootCA.pem >> fullchain.pem'
    subprocess.call(cmd, cwd=tmp_path, shell=True)
    assert (tmp_path / 'fullchain.pem').exists()

    os.environ['CERTFILE'] = str(tmp_path / "fullchain.pem")
    os.environ['KEYFILE'] = str(tmp_path / "key.pem")

    cmd = 'openssl x509 -noout -in rootCA.pem -fingerprint -sha256'
    fingerprint = subprocess.check_output(
        cmd, shell=True, cwd=tmp_path
    ).decode('utf-8').strip().split('=')[1].replace(':', '').lower()
    os.environ['CERT_ROOTS'] = f"{fingerprint}"

    yield
