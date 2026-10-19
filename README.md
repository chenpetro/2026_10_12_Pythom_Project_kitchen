# Food Shop

A Flask app with SQLite-backed user registration, login, and logout.

## Run locally (PowerShell)

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
$env:SECRET_KEY = 'replace-with-a-long-random-secret'
.\.venv\Scripts\python.exe main.py
```

Open http://127.0.0.1:5000/register to create an account, then log in.
Tables are created automatically in `foodshop.db` in the working directory.
Passwords are stored as Werkzeug scrypt hashes, never as plain text.

Usernames are case-sensitive and must contain 3 to 100 characters after trimming
surrounding whitespace. Passwords must contain 8 to 128 characters and match the
confirmation field. Authentication forms and POST-only logout use CSRF tokens.
The navigation shows the current username and logout button after login.
The existing home, menu, and cart pages remain public.

Set `SECRET_KEY` to a stable, randomly generated secret outside source control.
Without it, the app generates a temporary key and warns that sessions expire on
restart. For production, use HTTPS, enable `app.config['SESSION_COOKIE_SECURE']`,
disable debug mode, and use a production WSGI server rather than the development
server.

## Tests

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Authentication tests use a separate temporary database, not real user accounts.
