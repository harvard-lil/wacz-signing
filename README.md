wacz-signing
============

This package builds on work by Ilya Kreymer and Webrecorder in
[authsign](https://github.com/webrecorder/authsign). It is intended
for use in WACZ signing (and to a lesser extent, verification), as set
forth in the Webrecorder Recommendation [WACZ Signing and
Verification](https://specs.webrecorder.net/wacz-auth/0.1.0/). It is
an attempt to reduce authsign's footprint, and decouple signing from
any specific web API, authentication, and the process of obtaining key
material. It also omits the optional cross-signing mechanism specified
in the recommendation and provided by authsign.

Installation
------------

For regular use, start a virtual environment and install this package
and its requirements, something like this:

```
python3 -m venv env
. env/bin/activate
pip install wacz-signing
```

Use
---

The simplest way to use this system is to provide the environment
variables `DOMAIN` and `CERTNAME`, possibly in a `.env` file; the
package will then use the key material in
`/etc/letsencrypt/live/<CERTNAME>/`. (The provision of `DOMAIN` is to
accommodate the possibility that the domain name we care about is not
the one that was originally used to create the cert.) Then, you can

```
>>> from wacz_signing import signer
>>> result = signer.sign('hello world!', datetime.utcnow())
>>> signer.verify(result)
{'observer': ['mkcert'], 'software': 'wacz-signing 0.2.0', 'timestamp': '2022-10-05T19:03:25Z'}
```

or

```
>>> signer.verify_wacz('valid_signed_example_1.wacz')
{'observer': ['btrix-sign-test.webrecorder.net'], 'software': 'authsigner 0.3.0', 'timestamp': '2022-01-18T19:00:12Z'}
```


You can also provide cert, key, and timestamper material directly, or
in alternate files, using environment variables: you MUST provide
`DOMAIN`; you MUST provide either `CERTNAME` or one of `CERT` and
`CERTFILE`; if you have set `CERTNAME`, you MUST provide one of `KEY`
and `KEYFILE`. If you're not using Letsencrypt certs, you'll need to
set `CERT_ROOTS`. You may also configure the timestamper with `TS_CERT`
or `TS_CERTFILE` and `TS_URL` and `TS_ROOTS`. You may additionally
change the `CERT_DURATION` from its default of 7 days, and the
`STAMP_DURATION` from its default of 10 minutes.

You may want to catch `signer.SigningException`,
`signer.VerificationException`, and `signer.VerificationFailure`.

For local development and testing, you'll need to install
[mkcert](https://github.com/FiloSottile/mkcert). To generate certs,
you might run

```
mkcert -cert-file cert.pem -key-file key.pem example.org
cp cert.pem fullchain.pem
cat "$(mkcert -CAROOT)/rootCA.pem" >> fullchain.pem
```

and then set up `.env` like this:

```
DOMAIN=example.org
CERTFILE=fullchain.pem
KEYFILE=key.pem
CERT_ROOTS=<root CA fingerprint>
```

where you get the value for `CERT_ROOTS` by running

```
openssl x509 -noout -in "`mkcert -CAROOT`"/rootCA.pem -fingerprint -sha256 | cut -f 2 -d '=' | sed 's/://g' | awk '{print tolower($0)}'
```

Certificate management
----------------------

If you're using Letsencrypt certs, and you want them to be valid for a
short duration, say the default of seven days, you would need to force
a renewal after a week, then manually revoke the previous week's cert,
something like

```
certbot renew --force-renewal --deploy-hook /path/to/deploy-hook-script
```

(or just put the script in `/etc/letsencrypt/renewal-hooks/deploy/`

where the script runs something like

```
certbot revoke --cert-path `ls -t /etc/letsencrypt/archive/${CERTNAME}/cert*.pem | head -n 2 | tail -n 1` --reason expiration
```

(But triple-check this before attempting it in earnest; a correct
example may follow.)

Use cases
---------

This package could be used in a tiny API, of course; it could also be
integrated into a producer of WACZ files, like a future version of
Perma, which would sign archives internally; it could also be run in a
lambda, which is why it's possible to provide key material directly in
environment variables.

Stay tuned for examples of these uses in a later commit.
