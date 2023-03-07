In this directory are code and requirements for running a simple web
API for WACZ signing. Leaving aside the management of certificates,
you can run it like this, for development or CI purposes:

```
python3 -m venv .venv
source .venv/bin/activate
pip install flask wacz-signing
flask --app app run
```

or like this, in a more production-like way:

```
python3 -m venv .venv
source .venv/bin/activate
pip install flask wacz-signing gunicorn
gunicorn -b localhost:8000 -w 4 app:app
```

though you'd probably want to run with a systemd service something
like

```
[Unit]
Description=WACZ signing web application
After=network.target

[Service]
WorkingDirectory=<install_dir>
Environment=DOMAIN=domain.example.com
Environment=CERTNAME=domain-01.example.com
ExecStart=<virtual_env>/bin/gunicorn -b localhost:8000 -w 4 app:app
Restart=always

[Install]
WantedBy=multi-user.target
```

and behind `nginx` with a location stanza something like

```
      location '/' {
          proxy_pass http://127.0.0.1:8000;
          proxy_set_header Host $http_host;
          proxy_set_header X-Real-IP $remote_addr;
          proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
          proxy_set_header X-Forwarded-Proto $scheme;
          proxy_buffering off;
          proxy_request_buffering off;
      }
```
