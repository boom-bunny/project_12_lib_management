# Library Management System

A small web app for running a library: a catalogue of books, members, issuing and
returning books, overdue fines, and staff accounts behind a login page.
Built with Python, Flask and SQLite.

## Run it

```bash
pip install -r requirements.txt
```

```bash
python app.py
```

Open http://127.0.0.1:5000. On the first run you are asked to create the admin
account; after that the same address shows the login page.

## What it does

- **Login** – staff accounts with hashed passwords, sign-out, change password,
  and a 5-minute lockout after 5 wrong passwords.
- **Books** – add, edit, delete and search; tracks how many copies are available.
- **Members** – add, edit, deactivate, delete and search.
- **Loans** – issue a book with a due date, return it, see what is overdue and
  the fine owed.
- **Staff** (admins only) – create librarian or admin accounts.

## Settings

At the top of `app.py`: loan period (`LOAN_DAYS`), fine per day (`FINE_PER_DAY`),
currency symbol, and the per-member loan limit.

## Files

- `app.py` – all routes and database logic
- `templates/` – the pages
- `static/style.css` – styling (light and dark)
- `data/` – created on first run; holds `library.db` and the session secret key.
  Delete this folder to reset everything. Do not share it.

This runs on Flask's built-in server, which is meant for use on your own
computer. To put it on a network, run it behind a production server such as
`waitress` and HTTPS.
