"""Library Management System - Flask + SQLite.

Run with:  python app.py   then open http://127.0.0.1:5000
"""
import os
import re
import secrets
import sqlite3
import time
from datetime import date, timedelta
from functools import wraps

from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

# ---------------------------------------------------------------- settings
LOAN_DAYS = 14          # default loan period
FINE_PER_DAY = 5        # fine per overdue day
CURRENCY = "₹"
MAX_LOANS_PER_MEMBER = 5
MIN_PASSWORD_LENGTH = 8
MAX_LOGIN_ATTEMPTS = 5  # then the username is locked for LOCKOUT_SECONDS
LOCKOUT_SECONDS = 300

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("LIBRARY_DATA_DIR") or os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "library.db")
SECRET_PATH = os.path.join(DATA_DIR, "secret_key")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
    full_name     TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('admin', 'librarian')),
    created_on    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS books (
    id           INTEGER PRIMARY KEY,
    title        TEXT NOT NULL,
    author       TEXT NOT NULL,
    isbn         TEXT,
    category     TEXT,
    year         INTEGER,
    total_copies INTEGER NOT NULL CHECK (total_copies >= 1)
);
CREATE TABLE IF NOT EXISTS members (
    id        INTEGER PRIMARY KEY,
    name      TEXT NOT NULL,
    email     TEXT,
    phone     TEXT,
    joined_on TEXT NOT NULL,
    active    INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS loans (
    id          INTEGER PRIMARY KEY,
    book_id     INTEGER NOT NULL REFERENCES books(id) ON DELETE CASCADE,
    member_id   INTEGER NOT NULL REFERENCES members(id) ON DELETE CASCADE,
    issued_by   INTEGER REFERENCES users(id) ON DELETE SET NULL,
    issued_on   TEXT NOT NULL,
    due_on      TEXT NOT NULL,
    returned_on TEXT
);
CREATE INDEX IF NOT EXISTS idx_loans_open ON loans(book_id) WHERE returned_on IS NULL;
"""

SAMPLE_BOOKS = [
    ("Introduction to Algorithms", "Cormen, Leiserson, Rivest, Stein", "9780262033848", "Computer Science", 2009, 4),
    ("Clean Code", "Robert C. Martin", "9780132350884", "Computer Science", 2008, 3),
    ("The Pragmatic Programmer", "Andrew Hunt, David Thomas", "9780135957059", "Computer Science", 2019, 2),
    ("Sapiens", "Yuval Noah Harari", "9780062316097", "History", 2014, 3),
    ("A Brief History of Time", "Stephen Hawking", "9780553380163", "Science", 1988, 2),
    ("To Kill a Mockingbird", "Harper Lee", "9780061120084", "Fiction", 1960, 3),
    ("1984", "George Orwell", "9780451524935", "Fiction", 1949, 4),
    ("The God of Small Things", "Arundhati Roy", "9780812979657", "Fiction", 1997, 2),
    ("Thinking, Fast and Slow", "Daniel Kahneman", "9780374533557", "Psychology", 2011, 2),
    ("Wings of Fire", "A. P. J. Abdul Kalam", "9788173711466", "Biography", 1999, 3),
]

# --------------------------------------------------------------------- app
os.makedirs(DATA_DIR, exist_ok=True)


def _load_secret_key():
    """A random key generated once and kept out of the source code."""
    if not os.path.exists(SECRET_PATH):
        with open(SECRET_PATH, "w") as fh:
            fh.write(secrets.token_hex(32))
    with open(SECRET_PATH) as fh:
        return fh.read().strip()


app = Flask(__name__)
app.config.update(
    SECRET_KEY=_load_secret_key(),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


with sqlite3.connect(DB_PATH) as _conn:
    _conn.executescript(SCHEMA)
_conn.close()


# ---------------------------------------------------------------- security
def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


app.jinja_env.globals.update(csrf_token=csrf_token, currency=CURRENCY)


@app.before_request
def check_csrf():
    if request.method == "POST":
        expected = session.get("csrf_token", "")
        sent = request.form.get("csrf_token", "")
        if not expected or not secrets.compare_digest(expected, sent):
            abort(400, "Your session expired or the form was invalid. Go back, refresh and try again.")


@app.before_request
def load_user():
    g.user = None
    user_id = session.get("user_id")
    if user_id is not None:
        g.user = get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if g.user is None:
            session.clear()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("login", next=request.full_path.rstrip("?")))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if g.user["role"] != "admin":
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def safe_next(target):
    """Only allow redirects to paths on this site."""
    if target and target.startswith("/") and not target.startswith(("//", "/\\")):
        return target
    return url_for("dashboard")


_failed_logins = {}  # username -> [failure count, locked-until timestamp]
_DUMMY_HASH = generate_password_hash("not-a-real-password")
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")


def validate_new_user(username, full_name, password, confirm):
    errors = []
    if not USERNAME_RE.match(username):
        errors.append("Username must be 3-32 characters: letters, digits, dot, dash or underscore.")
    if not full_name:
        errors.append("Full name is required.")
    errors += validate_password(password, confirm)
    return errors


def validate_password(password, confirm):
    errors = []
    if len(password) < MIN_PASSWORD_LENGTH:
        errors.append(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
    if password != confirm:
        errors.append("The two passwords do not match.")
    return errors


def flash_errors(errors):
    for message in errors:
        flash(message, "error")


# -------------------------------------------------------------------- auth
@app.route("/setup", methods=["GET", "POST"])
def setup():
    """First run only: create the administrator account."""
    db = get_db()
    if db.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
        return redirect(url_for("login"))
    form = {"username": "", "full_name": ""}
    if request.method == "POST":
        form["username"] = request.form.get("username", "").strip()
        form["full_name"] = request.form.get("full_name", "").strip()
        password = request.form.get("password", "")
        errors = validate_new_user(form["username"], form["full_name"], password,
                                   request.form.get("confirm", ""))
        if not errors:
            cur = db.execute(
                "INSERT INTO users (username, full_name, password_hash, role, created_on) VALUES (?, ?, ?, 'admin', ?)",
                (form["username"], form["full_name"], generate_password_hash(password), date.today().isoformat()))
            if request.form.get("sample"):
                db.executemany(
                    "INSERT INTO books (title, author, isbn, category, year, total_copies) VALUES (?, ?, ?, ?, ?, ?)",
                    SAMPLE_BOOKS)
            db.commit()
            session.clear()
            session.permanent = True
            session["user_id"] = cur.lastrowid
            flash("Welcome! Your administrator account is ready.", "success")
            return redirect(url_for("dashboard"))
        flash_errors(errors)
    return render_template("setup.html", form=form, min_length=MIN_PASSWORD_LENGTH)


@app.route("/login", methods=["GET", "POST"])
def login():
    db = get_db()
    if not db.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
        return redirect(url_for("setup"))
    if g.user:
        return redirect(url_for("dashboard"))
    username = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        key = username.lower()
        record = _failed_logins.setdefault(key, [0, 0.0])
        if time.time() < record[1]:
            minutes = int((record[1] - time.time()) // 60) + 1
            flash(f"Too many failed attempts. Try again in {minutes} minute(s).", "error")
        else:
            user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            # Always run a hash check so response time doesn't reveal valid usernames.
            valid = check_password_hash(user["password_hash"] if user else _DUMMY_HASH, password)
            if user and valid:
                _failed_logins.pop(key, None)
                session.clear()
                session.permanent = True
                session["user_id"] = user["id"]
                return redirect(safe_next(request.args.get("next")))
            record[0] += 1
            if record[0] >= MAX_LOGIN_ATTEMPTS:
                _failed_logins[key] = [0, time.time() + LOCKOUT_SECONDS]
            flash("Incorrect username or password.", "error")
    return render_template("login.html", username=username)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been signed out.", "success")
    return redirect(url_for("login"))


@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    if request.method == "POST":
        new = request.form.get("password", "")
        errors = validate_password(new, request.form.get("confirm", ""))
        if not check_password_hash(g.user["password_hash"], request.form.get("current", "")):
            errors.insert(0, "Your current password is incorrect.")
        if not errors:
            db = get_db()
            db.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                       (generate_password_hash(new), g.user["id"]))
            db.commit()
            flash("Password changed.", "success")
            return redirect(url_for("account"))
        flash_errors(errors)
    return render_template("account.html", min_length=MIN_PASSWORD_LENGTH)


# --------------------------------------------------------------- dashboard
def loan_view(row):
    """Add status, days late and fine to a loan row."""
    loan = dict(row)
    end = date.fromisoformat(loan["returned_on"]) if loan["returned_on"] else date.today()
    late = max(0, (end - date.fromisoformat(loan["due_on"])).days)
    loan["late_days"] = late
    loan["fine"] = late * FINE_PER_DAY
    loan["status"] = "returned" if loan["returned_on"] else ("overdue" if late else "on loan")
    return loan


LOAN_SELECT = """
    SELECT l.*, b.title AS book_title, m.name AS member_name
    FROM loans l JOIN books b ON b.id = l.book_id JOIN members m ON m.id = l.member_id
"""


@app.route("/")
@login_required
def dashboard():
    db = get_db()
    today = date.today().isoformat()
    one = lambda sql, *args: db.execute(sql, args).fetchone()[0]
    copies = one("SELECT COALESCE(SUM(total_copies), 0) FROM books")
    on_loan = one("SELECT COUNT(*) FROM loans WHERE returned_on IS NULL")
    stats = {
        "titles": one("SELECT COUNT(*) FROM books"),
        "copies": copies,
        "available": copies - on_loan,
        "members": one("SELECT COUNT(*) FROM members WHERE active = 1"),
        "on_loan": on_loan,
        "overdue": one("SELECT COUNT(*) FROM loans WHERE returned_on IS NULL AND due_on < ?", today),
    }
    overdue = [loan_view(r) for r in db.execute(
        LOAN_SELECT + " WHERE l.returned_on IS NULL AND l.due_on < ? ORDER BY l.due_on LIMIT 8", (today,))]
    recent = [loan_view(r) for r in db.execute(LOAN_SELECT + " ORDER BY l.id DESC LIMIT 8")]
    return render_template("dashboard.html", stats=stats, overdue=overdue, recent=recent)


# ------------------------------------------------------------------- books
def read_book_form():
    f = request.form
    book = {k: f.get(k, "").strip() for k in ("title", "author", "isbn", "category", "year", "total_copies")}
    errors = []
    if not book["title"]:
        errors.append("Title is required.")
    if not book["author"]:
        errors.append("Author is required.")
    year = None
    if book["year"]:
        if book["year"].isdigit() and 0 < int(book["year"]) <= date.today().year + 1:
            year = int(book["year"])
        else:
            errors.append("Year must be a valid year.")
    copies = 0
    if book["total_copies"].isdigit() and 1 <= int(book["total_copies"]) <= 9999:
        copies = int(book["total_copies"])
    else:
        errors.append("Copies must be a number between 1 and 9999.")
    values = (book["title"], book["author"], book["isbn"] or None, book["category"] or None, year, copies)
    return book, values, errors


@app.route("/books")
@login_required
def books():
    q = request.args.get("q", "").strip()
    sql = """SELECT b.*, (SELECT COUNT(*) FROM loans l
                          WHERE l.book_id = b.id AND l.returned_on IS NULL) AS on_loan
             FROM books b"""
    args = ()
    if q:
        sql += " WHERE b.title LIKE ? OR b.author LIKE ? OR b.isbn LIKE ? OR b.category LIKE ?"
        args = (f"%{q}%",) * 4
    rows = get_db().execute(sql + " ORDER BY b.title COLLATE NOCASE", args).fetchall()
    return render_template("books.html", books=rows, q=q)


@app.route("/books/new", methods=["GET", "POST"])
@login_required
def book_new():
    book = {"total_copies": "1"}
    if request.method == "POST":
        book, values, errors = read_book_form()
        if not errors:
            db = get_db()
            db.execute("INSERT INTO books (title, author, isbn, category, year, total_copies) VALUES (?, ?, ?, ?, ?, ?)", values)
            db.commit()
            flash(f"Added “{book['title']}”.", "success")
            return redirect(url_for("books"))
        flash_errors(errors)
    return render_template("book_form.html", book=book, editing=False)


@app.route("/books/<int:book_id>/edit", methods=["GET", "POST"])
@login_required
def book_edit(book_id):
    db = get_db()
    row = db.execute("SELECT * FROM books WHERE id = ?", (book_id,)).fetchone()
    if row is None:
        abort(404)
    book = dict(row)
    if request.method == "POST":
        book, values, errors = read_book_form()
        on_loan = db.execute("SELECT COUNT(*) FROM loans WHERE book_id = ? AND returned_on IS NULL",
                             (book_id,)).fetchone()[0]
        if not errors and values[5] < on_loan:
            errors.append(f"{on_loan} copies are currently on loan, so copies cannot be fewer than that.")
        if not errors:
            db.execute("UPDATE books SET title = ?, author = ?, isbn = ?, category = ?, year = ?, total_copies = ? WHERE id = ?",
                       values + (book_id,))
            db.commit()
            flash("Book updated.", "success")
            return redirect(url_for("books"))
        flash_errors(errors)
    return render_template("book_form.html", book=book, editing=True)


@app.route("/books/<int:book_id>/delete", methods=["POST"])
@login_required
def book_delete(book_id):
    db = get_db()
    if db.execute("SELECT 1 FROM loans WHERE book_id = ? AND returned_on IS NULL", (book_id,)).fetchone():
        flash("This book has copies on loan. Return them before deleting it.", "error")
    else:
        db.execute("DELETE FROM books WHERE id = ?", (book_id,))
        db.commit()
        flash("Book deleted.", "success")
    return redirect(url_for("books"))


# ----------------------------------------------------------------- members
def read_member_form():
    f = request.form
    member = {k: f.get(k, "").strip() for k in ("name", "email", "phone")}
    member["active"] = 1 if f.get("active") else 0
    errors = []
    if not member["name"]:
        errors.append("Name is required.")
    if member["email"] and not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", member["email"]):
        errors.append("Email address does not look valid.")
    return member, errors


@app.route("/members")
@login_required
def members():
    q = request.args.get("q", "").strip()
    sql = """SELECT m.*, (SELECT COUNT(*) FROM loans l
                          WHERE l.member_id = m.id AND l.returned_on IS NULL) AS on_loan
             FROM members m"""
    args = ()
    if q:
        sql += " WHERE m.name LIKE ? OR m.email LIKE ? OR m.phone LIKE ?"
        args = (f"%{q}%",) * 3
    rows = get_db().execute(sql + " ORDER BY m.name COLLATE NOCASE", args).fetchall()
    return render_template("members.html", members=rows, q=q)


@app.route("/members/new", methods=["GET", "POST"])
@login_required
def member_new():
    member = {"active": 1}
    if request.method == "POST":
        member, errors = read_member_form()
        if not errors:
            db = get_db()
            db.execute("INSERT INTO members (name, email, phone, joined_on, active) VALUES (?, ?, ?, ?, 1)",
                       (member["name"], member["email"] or None, member["phone"] or None, date.today().isoformat()))
            db.commit()
            flash(f"Added member {member['name']}.", "success")
            return redirect(url_for("members"))
        flash_errors(errors)
    return render_template("member_form.html", member=member, editing=False)


@app.route("/members/<int:member_id>/edit", methods=["GET", "POST"])
@login_required
def member_edit(member_id):
    db = get_db()
    row = db.execute("SELECT * FROM members WHERE id = ?", (member_id,)).fetchone()
    if row is None:
        abort(404)
    member = dict(row)
    if request.method == "POST":
        member, errors = read_member_form()
        if not errors:
            db.execute("UPDATE members SET name = ?, email = ?, phone = ?, active = ? WHERE id = ?",
                       (member["name"], member["email"] or None, member["phone"] or None,
                        member["active"], member_id))
            db.commit()
            flash("Member updated.", "success")
            return redirect(url_for("members"))
        flash_errors(errors)
    return render_template("member_form.html", member=member, editing=True)


@app.route("/members/<int:member_id>/delete", methods=["POST"])
@login_required
def member_delete(member_id):
    db = get_db()
    if db.execute("SELECT 1 FROM loans WHERE member_id = ? AND returned_on IS NULL", (member_id,)).fetchone():
        flash("This member still has books on loan.", "error")
    else:
        db.execute("DELETE FROM members WHERE id = ?", (member_id,))
        db.commit()
        flash("Member deleted.", "success")
    return redirect(url_for("members"))


# ------------------------------------------------------------------- loans
@app.route("/loans")
@login_required
def loans():
    status = request.args.get("status", "open")
    where = {
        "open": " WHERE l.returned_on IS NULL",
        "overdue": " WHERE l.returned_on IS NULL AND l.due_on < :today",
        "returned": " WHERE l.returned_on IS NOT NULL",
        "all": "",
    }
    if status not in where:
        status = "open"
    rows = get_db().execute(LOAN_SELECT + where[status] + " ORDER BY l.returned_on IS NOT NULL, l.due_on, l.id DESC",
                            {"today": date.today().isoformat()} if status == "overdue" else {})
    return render_template("loans.html", loans=[loan_view(r) for r in rows], status=status)


@app.route("/loans/issue", methods=["GET", "POST"])
@login_required
def loan_issue():
    db = get_db()
    today = date.today()
    form = {"book_id": request.values.get("book_id", ""),
            "member_id": request.values.get("member_id", ""),
            "due_on": request.form.get("due_on") or (today + timedelta(days=LOAN_DAYS)).isoformat()}
    if request.method == "POST":
        errors = []
        book = db.execute("SELECT * FROM books WHERE id = ?", (form["book_id"],)).fetchone()
        member = db.execute("SELECT * FROM members WHERE id = ?", (form["member_id"],)).fetchone()
        try:
            due = date.fromisoformat(form["due_on"])
        except ValueError:
            due = None
        if book is None:
            errors.append("Choose a book.")
        if member is None:
            errors.append("Choose a member.")
        elif not member["active"]:
            errors.append("This member is inactive.")
        if due is None or due < today:
            errors.append("Due date must be today or later.")
        if book and member and not errors:
            open_for_book = db.execute("SELECT COUNT(*) FROM loans WHERE book_id = ? AND returned_on IS NULL",
                                       (book["id"],)).fetchone()[0]
            open_for_member = db.execute("SELECT book_id FROM loans WHERE member_id = ? AND returned_on IS NULL",
                                         (member["id"],)).fetchall()
            if open_for_book >= book["total_copies"]:
                errors.append("No copies of this book are available right now.")
            if len(open_for_member) >= MAX_LOANS_PER_MEMBER:
                errors.append(f"This member already has {MAX_LOANS_PER_MEMBER} books on loan.")
            if any(r["book_id"] == book["id"] for r in open_for_member):
                errors.append("This member already has a copy of this book.")
        if not errors:
            db.execute("INSERT INTO loans (book_id, member_id, issued_by, issued_on, due_on) VALUES (?, ?, ?, ?, ?)",
                       (book["id"], member["id"], g.user["id"], today.isoformat(), due.isoformat()))
            db.commit()
            flash(f"Issued “{book['title']}” to {member['name']}, due {due.isoformat()}.", "success")
            return redirect(url_for("loans"))
        flash_errors(errors)
    available = db.execute("""
        SELECT b.id, b.title, b.author,
               b.total_copies - (SELECT COUNT(*) FROM loans l WHERE l.book_id = b.id AND l.returned_on IS NULL) AS free
        FROM books b WHERE free > 0 ORDER BY b.title COLLATE NOCASE""").fetchall()
    active_members = db.execute("SELECT id, name FROM members WHERE active = 1 ORDER BY name COLLATE NOCASE").fetchall()
    return render_template("loan_issue.html", form=form, books=available, members=active_members,
                           today=today.isoformat())


@app.route("/loans/<int:loan_id>/return", methods=["POST"])
@login_required
def loan_return(loan_id):
    db = get_db()
    row = db.execute(LOAN_SELECT + " WHERE l.id = ? AND l.returned_on IS NULL", (loan_id,)).fetchone()
    if row is None:
        abort(404)
    db.execute("UPDATE loans SET returned_on = ? WHERE id = ?", (date.today().isoformat(), loan_id))
    db.commit()
    loan = loan_view(row)
    message = f"Returned “{loan['book_title']}” from {loan['member_name']}."
    if loan["fine"]:
        message += f" It was {loan['late_days']} day(s) late: collect a fine of {CURRENCY}{loan['fine']}."
    flash(message, "success")
    back = request.form.get("back")
    return redirect(safe_next(back) if back else url_for("loans"))


# ------------------------------------------------------------------- staff
@app.route("/staff", methods=["GET", "POST"])
@admin_required
def staff():
    db = get_db()
    form = {"username": "", "full_name": "", "role": "librarian"}
    if request.method == "POST":
        form["username"] = request.form.get("username", "").strip()
        form["full_name"] = request.form.get("full_name", "").strip()
        form["role"] = "admin" if request.form.get("role") == "admin" else "librarian"
        password = request.form.get("password", "")
        errors = validate_new_user(form["username"], form["full_name"], password, request.form.get("confirm", ""))
        if not errors and db.execute("SELECT 1 FROM users WHERE username = ?", (form["username"],)).fetchone():
            errors.append("That username is already taken.")
        if not errors:
            db.execute("INSERT INTO users (username, full_name, password_hash, role, created_on) VALUES (?, ?, ?, ?, ?)",
                       (form["username"], form["full_name"], generate_password_hash(password),
                        form["role"], date.today().isoformat()))
            db.commit()
            flash(f"Created account for {form['full_name']}.", "success")
            return redirect(url_for("staff"))
        flash_errors(errors)
    users = db.execute("SELECT * FROM users ORDER BY username").fetchall()
    return render_template("staff.html", users=users, form=form, min_length=MIN_PASSWORD_LENGTH)


@app.route("/staff/<int:user_id>/delete", methods=["POST"])
@admin_required
def staff_delete(user_id):
    if user_id == g.user["id"]:
        flash("You cannot delete your own account.", "error")
    else:
        db = get_db()
        db.execute("DELETE FROM users WHERE id = ?", (user_id,))
        db.commit()
        flash("Account deleted.", "success")
    return redirect(url_for("staff"))


@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
def error_page(err):
    return render_template("error.html", err=err), err.code


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5000)), debug=False)
