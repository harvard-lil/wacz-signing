import pytest
import subprocess
import os
from signing.signer import sign, verify, SigningException
from datetime import datetime, timedelta


def test_happy_path(mkcert):
    result = sign('hello, world', datetime.utcnow())
    check = verify(result)
    assert check['observer'] == ['mkcert']


def test_late_signature(mkcert):
    with pytest.raises(SigningException) as e:
        sign('hello, world', datetime.utcnow() + timedelta(days=8))
        assert "is later than timestamp" in str(e.value)


def test_early_signature(mkcert):
    with pytest.raises(SigningException) as e:
        sign('hello, world', datetime.utcnow() - timedelta(hours=1))
        assert "older than timestamp" in str(e.value)


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
