import base64
import hashlib
import hmac
import os
import secrets
import shutil
import sqlite3
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Any

from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for

APP_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(APP_DIR, "secure_blog.db")
KEYS_DIR = os.path.join(APP_DIR, "keys")
PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "post_signing_private.pem")
PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, "post_signing_public.pem")


def create_app() -> Flask:
    app = Flask(__name__)
    has_tls_files = bool(os.environ.get("SSL_CERT") and os.environ.get("SSL_KEY"))
    enforce_https = env_flag("ENFORCE_HTTPS", default=has_tls_files)
    session_idle_minutes = int(os.environ.get("SESSION_IDLE_MINUTES", "30"))
    session_absolute_minutes = int(os.environ.get("SESSION_ABSOLUTE_MINUTES", "240"))
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
    app.config["MAX_CONTENT_LENGTH"] = 1_000_000
    app.config["ENFORCE_HTTPS"] = enforce_https
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = enforce_https
    app.config["SESSION_IDLE_MINUTES"] = session_idle_minutes
    app.config["SESSION_ABSOLUTE_MINUTES"] = session_absolute_minutes

    @app.before_request
    def before_request() -> None:
        if app.config["ENFORCE_HTTPS"]:
            forwarded_proto = request.headers.get("X-Forwarded-Proto", "").lower()
            if not request.is_secure and forwarded_proto != "https":
                return redirect(request.url.replace("http://", "https://", 1), code=301)
        get_db()
        ensure_csrf_token()
        if session.get("user_id"):
            if session_expired(
                app.config["SESSION_IDLE_MINUTES"],
                app.config["SESSION_ABSOLUTE_MINUTES"],
            ):
                expired_user = session.get("user_id")
                session.clear()
                rotate_csrf_token()
                log_event(expired_user, "user.session_expired", "user", expired_user, "timeout")
                flash("Your session expired. Please log in again.", "error")
                return redirect(url_for("login"))
            session["last_seen_at"] = now_utc()

    @app.teardown_appcontext
    def teardown_db(_exc: BaseException | None) -> None:
        db = g.pop("db", None)
        if db is not None:
            db.close()

    @app.after_request
    def apply_security_headers(response):
        csp = (
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; "
            "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'none'; "
            "form-action 'self'"
        )
        response.headers["Content-Security-Policy"] = csp
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), browsing-topics=()"
        )
        response.headers["Cache-Control"] = "no-store"
        if app.config["ENFORCE_HTTPS"]:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    @app.route("/")
    def index() -> str:
        return redirect(url_for("list_posts"))

    @app.route("/register", methods=["GET", "POST"])
    def register() -> str:
        if request.method == "POST":
            validate_csrf_or_400()
            username = (request.form.get("username") or "").strip().lower()
            password = request.form.get("password") or ""
            role = "user"

            if not (3 <= len(username) <= 30) or not username.replace("_", "").isalnum():
                flash("Username must be 3-30 chars and alphanumeric/underscore.", "error")
                return render_template("register.html")
            if len(password) < 10:
                flash("Password must be at least 10 characters.", "error")
                return render_template("register.html")

            db = get_db()
            exists = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
            if exists:
                flash("Username already exists.", "error")
                return render_template("register.html")

            hashed = hash_password(password)
            cur = db.execute(
                "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                (username, hashed, role, now_utc()),
            )
            db.commit()
            log_event(cur.lastrowid, "user.register", "user", cur.lastrowid, f"role={role}")
            flash("Account created. Please log in.", "success")
            return redirect(url_for("login"))

        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login() -> str:
        if request.method == "POST":
            validate_csrf_or_400()
            username = (request.form.get("username") or "").strip().lower()
            password = request.form.get("password") or ""
            ip = request.remote_addr or "unknown"
            session["login_last_username"] = username
            challenge_required = needs_login_challenge(username, ip)

            if challenge_required:
                if not validate_login_challenge(request.form.get("challenge_answer")):
                    ensure_login_challenge(force=True)
                    record_failed_attempt(username, ip)
                    flash("Challenge verification failed.", "error")
                    return render_template("login.html", challenge_question=session.get("login_challenge_question"))

            if is_ip_locked_out(ip) or is_username_locked_out(username):
                flash("Too many failed attempts. Try again in 15 minutes.", "error")
                ensure_login_challenge(force=True)
                return render_template("login.html", challenge_question=session.get("login_challenge_question"))

            db = get_db()
            user = db.execute(
                "SELECT id, username, password_hash, role FROM users WHERE username = ?", (username,)
            ).fetchone()

            if not user or not verify_password(password, user["password_hash"]):
                record_failed_attempt(username, ip)
                if needs_login_challenge(username, ip):
                    ensure_login_challenge(force=True)
                flash("Invalid credentials.", "error")
                return render_template("login.html", challenge_question=session.get("login_challenge_question"))

            clear_failed_attempts(ip, username)
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            session["logged_in_at"] = now_utc()
            session["last_seen_at"] = now_utc()
            rotate_csrf_token()
            clear_login_challenge()
            log_event(user["id"], "user.login", "user", user["id"], "success")
            flash("Logged in successfully.", "success")
            return redirect(url_for("list_posts"))

        ip = request.remote_addr or "unknown"
        if session.get("login_last_username"):
            if needs_login_challenge(session["login_last_username"], ip):
                ensure_login_challenge()
        return render_template("login.html", challenge_question=session.get("login_challenge_question"))

    @app.route("/logout", methods=["POST"])
    @login_required
    def logout() -> str:
        validate_csrf_or_400()
        user_id = session.get("user_id")
        if user_id:
            log_event(user_id, "user.logout", "user", user_id, "success")
        session.clear()
        rotate_csrf_token()
        flash("Logged out.", "success")
        return redirect(url_for("login"))

    @app.route("/posts")
    @login_required
    def list_posts() -> str:
        db = get_db()
        user_id = int(session["user_id"])
        role = session["role"]

        if role == "admin":
            posts = db.execute(
                """
                SELECT p.id, p.title, p.content, p.visibility, p.created_at, p.updated_at, u.username AS author
                FROM posts p
                JOIN users u ON u.id = p.author_id
                ORDER BY p.updated_at DESC
                """
            ).fetchall()
        else:
            posts = db.execute(
                """
                SELECT DISTINCT p.id, p.title, p.content, p.visibility, p.created_at, p.updated_at, u.username AS author
                FROM posts p
                JOIN users u ON u.id = p.author_id
                LEFT JOIN post_access pa ON pa.post_id = p.id
                WHERE p.visibility = 'public' 
                   OR p.author_id = ? 
                   OR pa.user_id = ?
                ORDER BY p.updated_at DESC
                """,
                (user_id, user_id),
            ).fetchall()

        return render_template("posts.html", posts=posts)

    @app.route("/posts/new", methods=["GET", "POST"])
    @role_required("user", "admin")
    def new_post() -> str:
        db = get_db()
        if request.method == "POST":
            validate_csrf_or_400()
            title = clean_text(request.form.get("title"), 150)
            content = clean_text(request.form.get("content"), 20_000)
            visibility = (request.form.get("visibility") or "public").lower()

            if visibility not in {"public", "private"}:
                flash("Invalid visibility.", "error")
                return render_template("post_form.html", post=None)
            if not title or not content:
                flash("Title and content are required.", "error")
                return render_template("post_form.html", post=None)

            digest = sha256_text(content)
            signature = sign_text(content)
            cur = db.execute(
                """
                INSERT INTO posts (
                    author_id, title, content, visibility, content_hash, content_signature, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (session["user_id"], title, content, visibility, digest, signature, now_utc(), now_utc()),
            )
            post_id = int(cur.lastrowid)

            if visibility == "private":
                allowed_users = request.form.getlist("allowed_users")
                for uid in allowed_users:
                    db.execute("INSERT INTO post_access (post_id, user_id) VALUES (?, ?)", (post_id, int(uid)))

            db.execute(
                """
                INSERT INTO post_versions (
                    post_id, editor_id, title, content, content_hash, content_signature, version_no, edited_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (post_id, session["user_id"], title, content, digest, signature, 1, now_utc()),
            )
            db.commit()
            log_event(session["user_id"], "post.create", "post", post_id, f"visibility={visibility}")
            flash("Post created.", "success")
            return redirect(url_for("view_post", post_id=post_id))

        users = db.execute("SELECT id, username FROM users WHERE id != ?", (session["user_id"],)).fetchall()
        return render_template("post_form.html", post=None, users=users, allowed_user_ids=[])

    @app.route("/posts/<int:post_id>")
    @login_required
    def view_post(post_id: int) -> str:
        post = fetch_post_or_404(post_id)
        require_post_read_access(post)

        computed_hash = sha256_text(post["content"])
        integrity_ok = hmac.compare_digest(computed_hash, post["content_hash"])
        signature_ok = verify_text_signature(post["content"], post["content_signature"])
        if not integrity_ok:
            log_event(session["user_id"], "post.integrity_violation", "post", post_id, "hash_mismatch")
        if not signature_ok:
            log_event(session["user_id"], "post.signature_violation", "post", post_id, "signature_invalid")

        return render_template(
            "post_detail.html",
            post=post,
            integrity_ok=integrity_ok,
            signature_ok=signature_ok,
        )

    @app.route("/posts/<int:post_id>/edit", methods=["GET", "POST"])
    @login_required
    def edit_post(post_id: int) -> str:
        post = fetch_post_or_404(post_id)
        require_post_edit_access(post)
        db = get_db()

        if request.method == "POST":
            validate_csrf_or_400()
            title = clean_text(request.form.get("title"), 150)
            content = clean_text(request.form.get("content"), 20_000)
            visibility = (request.form.get("visibility") or "public").lower()
            if visibility not in {"public", "private"} or not title or not content:
                flash("Invalid input.", "error")
                return render_template("post_form.html", post=post)

            digest = sha256_text(content)
            signature = sign_text(content)
            
            db.execute("DELETE FROM post_access WHERE post_id = ?", (post_id,))
            if visibility == "private":
                allowed_users = request.form.getlist("allowed_users")
                for uid in allowed_users:
                    db.execute("INSERT INTO post_access (post_id, user_id) VALUES (?, ?)", (post_id, int(uid)))

            current_version = db.execute(
                "SELECT COALESCE(MAX(version_no), 0) AS max_v FROM post_versions WHERE post_id = ?",
                (post_id,),
            ).fetchone()["max_v"]
            db.execute(
                """
                UPDATE posts
                SET title = ?, content = ?, visibility = ?, content_hash = ?, content_signature = ?, updated_at = ?
                WHERE id = ?
                """,
                (title, content, visibility, digest, signature, now_utc(), post_id),
            )
            db.execute(
                """
                INSERT INTO post_versions (
                    post_id, editor_id, title, content, content_hash, content_signature, version_no, edited_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (post_id, session["user_id"], title, content, digest, signature, int(current_version) + 1, now_utc()),
            )
            db.commit()
            log_event(session["user_id"], "post.edit", "post", post_id, f"visibility={visibility}")
            flash("Post updated.", "success")
            return redirect(url_for("view_post", post_id=post_id))

        users = db.execute("SELECT id, username FROM users WHERE id != ?", (session["user_id"],)).fetchall()
        access_rows = db.execute("SELECT user_id FROM post_access WHERE post_id = ?", (post_id,)).fetchall()
        allowed_user_ids = [row["user_id"] for row in access_rows]
        return render_template("post_form.html", post=post, users=users, allowed_user_ids=allowed_user_ids)

    @app.route("/posts/<int:post_id>/delete", methods=["POST"])
    @login_required
    def delete_post(post_id: int) -> str:
        validate_csrf_or_400()
        post = fetch_post_or_404(post_id)
        require_post_delete_access(post)

        db = get_db()
        db.execute("DELETE FROM posts WHERE id = ?", (post_id,))
        db.commit()
        log_event(session["user_id"], "post.delete", "post", post_id, "deleted")
        flash("Post deleted.", "success")
        return redirect(url_for("list_posts"))

    @app.route("/posts/<int:post_id>/history")
    @login_required
    def post_history(post_id: int) -> str:
        post = fetch_post_or_404(post_id)
        require_post_edit_access(post)

        versions = get_db().execute(
            """
            SELECT pv.version_no, pv.title, pv.content_hash, pv.content_signature, pv.edited_at, u.username AS editor
            FROM post_versions pv
            JOIN users u ON u.id = pv.editor_id
            WHERE pv.post_id = ?
            ORDER BY pv.version_no DESC
            """,
            (post_id,),
        ).fetchall()

        return render_template("history.html", post=post, versions=versions)

    @app.route("/admin/audit")
    @role_required("admin")
    def audit_log() -> str:
        db = get_db()
        action_filter = request.args.get("action", "").strip()

        if action_filter:
            logs = db.execute(
                """
                SELECT a.id, a.action, a.target_type, a.target_id, a.details, a.created_at, a.ip,
                       u.username AS actor
                FROM audit_logs a
                LEFT JOIN users u ON u.id = a.user_id
                WHERE a.action = ?
                ORDER BY a.created_at DESC
                LIMIT 200
                """,
                (action_filter,),
            ).fetchall()
        else:
            logs = db.execute(
                """
                SELECT a.id, a.action, a.target_type, a.target_id, a.details, a.created_at, a.ip,
                       u.username AS actor
                FROM audit_logs a
                LEFT JOIN users u ON u.id = a.user_id
                ORDER BY a.created_at DESC
                LIMIT 200
                """
            ).fetchall()

        # Summary statistics for dashboard cards
        total_events = db.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0]
        failed_logins = db.execute(
            "SELECT COUNT(*) FROM login_attempts WHERE success = 0"
        ).fetchone()[0]
        unique_ips = db.execute(
            "SELECT COUNT(DISTINCT ip) FROM audit_logs WHERE ip IS NOT NULL"
        ).fetchone()[0]
        total_users = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]

        # Distinct action types for filter dropdown
        action_types = [
            r[0]
            for r in db.execute(
                "SELECT DISTINCT action FROM audit_logs ORDER BY action"
            ).fetchall()
        ]

        return render_template(
            "audit.html",
            logs=logs,
            total_events=total_events,
            failed_logins=failed_logins,
            unique_ips=unique_ips,
            total_users=total_users,
            action_types=action_types,
            current_filter=action_filter,
        )

    @app.route("/chat")
    @login_required
    def chat() -> str:
        db = get_db()
        users = db.execute("SELECT id, username FROM users WHERE id != ?", (session["user_id"],)).fetchall()
        
        # Pre-generate conversation keys for each user
        user_list = []
        for u in users:
            pair = sorted([int(session["user_id"]), int(u["id"])])
            pair_str = f"{pair[0]}:{pair[1]}"
            chat_key = hmac.new(
                app.config["SECRET_KEY"].encode(), 
                pair_str.encode(), 
                hashlib.sha256
            ).hexdigest()
            
            user_list.append({
                "id": u["id"],
                "username": u["username"],
                "chat_key": chat_key
            })
            
        return render_template("chat.html", users=user_list)

    @app.route("/api/messages/send", methods=["POST"])
    @login_required
    def api_send_message():
        validate_csrf_or_400()
        data = request.get_json()
        receiver_id = data.get("receiver_id")
        content = data.get("content")
        is_encrypted = data.get("is_encrypted", 1)

        if not receiver_id or not content:
            return {"error": "Missing data"}, 400

        db = get_db()
        db.execute(
            "INSERT INTO messages (sender_id, receiver_id, content, is_encrypted, created_at) VALUES (?, ?, ?, ?, ?)",
            (session["user_id"], receiver_id, content, is_encrypted, now_utc())
        )
        db.commit()
        return {"status": "success"}

    @app.route("/api/messages/<int:other_user_id>")
    @login_required
    def api_get_messages(other_user_id: int):
        db = get_db()
        messages = db.execute(
            """
            SELECT m.content, m.is_encrypted, m.created_at, u_sender.username as sender
            FROM messages m
            JOIN users u_sender ON m.sender_id = u_sender.id
            WHERE (m.sender_id = ? AND m.receiver_id = ?) 
               OR (m.sender_id = ? AND m.receiver_id = ?)
            ORDER BY m.created_at ASC
            """,
            (session["user_id"], other_user_id, other_user_id, session["user_id"])
        ).fetchall()
        
        return {"messages": [dict(m) for m in messages]}

    @app.context_processor
    def inject_user() -> dict[str, Any]:
        return {
            "current_user": {
                "id": session.get("user_id"),
                "username": session.get("username"),
                "role": session.get("role"),
            },
            "csrf_token": session.get("csrf_token"),
        }

    @app.template_filter("humantime")
    def humantime_filter(value: str) -> str:
        """Convert ISO timestamp to human-readable format."""
        if not value:
            return ""
        try:
            dt = datetime.fromisoformat(value)
            now = datetime.now(timezone.utc)
            diff = now - dt
            seconds = int(diff.total_seconds())
            if seconds < 60:
                return "just now"
            elif seconds < 3600:
                mins = seconds // 60
                return f"{mins}m ago"
            elif seconds < 86400:
                hours = seconds // 3600
                return f"{hours}h ago"
            elif seconds < 604800:
                days = seconds // 86400
                return f"{days}d ago"
            else:
                return dt.strftime("%b %d, %Y %I:%M %p")
        except (ValueError, TypeError):
            return str(value)

    @app.errorhandler(403)
    def forbidden(e):
        return render_template("error.html", error_code=403, error_title="Access Denied",
                               error_message="You don't have permission to access this resource. This incident has been logged."), 403

    @app.errorhandler(404)
    def not_found(e):
        return render_template("error.html", error_code=404, error_title="Not Found",
                               error_message="The requested resource could not be located on this server."), 404

    @app.errorhandler(400)
    def bad_request(e):
        return render_template("error.html", error_code=400, error_title="Bad Request",
                               error_message="The server could not process your request. Possible CSRF token violation."), 400

    init_db()
    return app


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH, timeout=20)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        g.db = conn
    return g.db


def init_db() -> None:
    ensure_signing_keys()
    db = sqlite3.connect(DB_PATH, timeout=20)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    db.execute("PRAGMA journal_mode = WAL")
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin', 'user')),
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            author_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            visibility TEXT NOT NULL CHECK(visibility IN ('public', 'private')),
            content_hash TEXT NOT NULL,
            content_signature TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS post_versions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
            editor_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            content_hash TEXT NOT NULL,
            content_signature TEXT,
            version_no INTEGER NOT NULL,
            edited_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            action TEXT NOT NULL,
            target_type TEXT NOT NULL,
            target_id INTEGER,
            details TEXT,
            created_at TEXT NOT NULL,
            ip TEXT
        );

        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            ip TEXT NOT NULL,
            attempted_at TEXT NOT NULL,
            success INTEGER NOT NULL DEFAULT 0
        );
        
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL REFERENCES users(id),
            receiver_id INTEGER NOT NULL REFERENCES users(id),
            content TEXT NOT NULL,
            is_encrypted INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS post_access (
            post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            PRIMARY KEY (post_id, user_id)
        );

        CREATE INDEX IF NOT EXISTS idx_posts_author ON posts(author_id);
        CREATE INDEX IF NOT EXISTS idx_attempts_ip_time ON login_attempts(ip, attempted_at);
        """
    )
    ensure_column(db, "posts", "content_signature", "TEXT")
    ensure_column(db, "post_versions", "content_signature", "TEXT")
    backfill_missing_signatures(db)

    try:
        admin_pass = hash_password("adminpassword")
        db.execute(
            "INSERT OR IGNORE INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            ("admin", admin_pass, "admin", now_utc()),
        )
    except Exception:
        pass

    db.commit()
    db.close()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def role_required(*roles: str):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not session.get("user_id"):
                flash("Please log in.", "error")
                return redirect(url_for("login"))
            if session.get("role") not in roles:
                abort(403)
            return view(*args, **kwargs)

        return wrapped

    return decorator


def fetch_post_or_404(post_id: int) -> sqlite3.Row:
    post = get_db().execute(
        """
        SELECT p.*, u.username AS author
        FROM posts p
        JOIN users u ON u.id = p.author_id
        WHERE p.id = ?
        """,
        (post_id,),
    ).fetchone()
    if not post:
        abort(404)
    return post


def require_post_read_access(post: sqlite3.Row) -> None:
    user_id = int(session["user_id"])
    role = session["role"]
    if role == "admin":
        return
    if post["visibility"] == "public":
        return
    if int(post["author_id"]) == user_id:
        return
        
    access = get_db().execute(
        "SELECT 1 FROM post_access WHERE post_id = ? AND user_id = ?", 
        (post["id"], user_id)
    ).fetchone()
    if access: return
    abort(403)


def require_post_edit_access(post: sqlite3.Row) -> None:
    user_id = int(session["user_id"])
    if int(post["author_id"]) == user_id:
        return
    abort(403)


def require_post_delete_access(post: sqlite3.Row) -> None:
    user_id = int(session["user_id"])
    role = session["role"]
    if role == "admin":
        return
    if int(post["author_id"]) == user_id:
        return
    abort(403)


def clean_text(value: str | None, max_len: int) -> str:
    text = (value or "").strip()
    return text[:max_len]


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def hash_password(password: str) -> str:
    iterations = 200_000
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters, salt_hex, hash_hex = stored.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iters)
        )
        return hmac.compare_digest(dk.hex(), hash_hex)
    except Exception:
        return False


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_utc(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts)
    except ValueError:
        return None


def session_expired(idle_minutes: int, absolute_minutes: int) -> bool:
    now = datetime.now(timezone.utc)
    last_seen = parse_utc(session.get("last_seen_at"))
    logged_in_at = parse_utc(session.get("logged_in_at"))

    if not last_seen or not logged_in_at:
        return True
    if now - last_seen > timedelta(minutes=idle_minutes):
        return True
    if now - logged_in_at > timedelta(minutes=absolute_minutes):
        return True
    return False


def ensure_csrf_token() -> None:
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(24)


def rotate_csrf_token() -> None:
    session["csrf_token"] = secrets.token_urlsafe(24)


def validate_csrf_or_400() -> None:
    token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    if not token or token != session.get("csrf_token"):
        abort(400, "Invalid CSRF token")


def count_recent_failures(ip: str, username: str, window_minutes: int = 15) -> tuple[int, int]:
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=window_minutes)).isoformat()
    db = get_db()
    by_ip = db.execute(
        """
        SELECT COUNT(*) AS failures
        FROM login_attempts
        WHERE ip = ? AND attempted_at >= ? AND success = 0
        """,
        (ip, cutoff),
    ).fetchone()
    by_user = db.execute(
        """
        SELECT COUNT(*) AS failures
        FROM login_attempts
        WHERE username = ? AND attempted_at >= ? AND success = 0
        """,
        (username, cutoff),
    ).fetchone()
    return int(by_ip["failures"]), int(by_user["failures"])


def is_ip_locked_out(ip: str, threshold: int = 5, window_minutes: int = 15) -> bool:
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=window_minutes)).isoformat()
    row = get_db().execute(
        """
        SELECT COUNT(*) AS failures
        FROM login_attempts
        WHERE ip = ? AND attempted_at >= ? AND success = 0
        """,
        (ip, cutoff),
    ).fetchone()
    return int(row["failures"]) >= threshold


def is_username_locked_out(username: str, threshold: int = 5, window_minutes: int = 15) -> bool:
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=window_minutes)).isoformat()
    row = get_db().execute(
        """
        SELECT COUNT(*) AS failures
        FROM login_attempts
        WHERE username = ? AND attempted_at >= ? AND success = 0
        """,
        (username, cutoff),
    ).fetchone()
    return int(row["failures"]) >= threshold


def needs_login_challenge(username: str, ip: str, threshold: int = 3) -> bool:
    if not username:
        return False
    by_ip, by_user = count_recent_failures(ip, username)
    return by_ip >= threshold or by_user >= threshold


def ensure_login_challenge(force: bool = False) -> None:
    if not force and session.get("login_challenge_question") and session.get("login_challenge_answer"):
        return
    a = secrets.randbelow(10) + 1
    b = secrets.randbelow(10) + 1
    session["login_challenge_question"] = f"What is {a} + {b}?"
    session["login_challenge_answer"] = str(a + b)
    session["login_challenge_expires"] = (
        datetime.now(timezone.utc) + timedelta(minutes=10)
    ).isoformat()


def validate_login_challenge(answer: str | None) -> bool:
    expected = session.get("login_challenge_answer")
    expires = session.get("login_challenge_expires")
    if not expected or not expires:
        return False
    if datetime.now(timezone.utc).isoformat() > str(expires):
        return False
    return hmac.compare_digest((answer or "").strip(), str(expected))


def clear_login_challenge() -> None:
    session.pop("login_challenge_question", None)
    session.pop("login_challenge_answer", None)
    session.pop("login_challenge_expires", None)


def record_failed_attempt(username: str, ip: str) -> None:
    db = get_db()
    db.execute(
        "INSERT INTO login_attempts (username, ip, attempted_at, success) VALUES (?, ?, ?, 0)",
        (username, ip, now_utc()),
    )
    db.commit()


def clear_failed_attempts(ip: str, username: str) -> None:
    db = get_db()
    db.execute("DELETE FROM login_attempts WHERE ip = ? AND success = 0", (ip,))
    db.execute("DELETE FROM login_attempts WHERE username = ? AND success = 0", (username,))
    db.execute(
        "INSERT INTO login_attempts (username, ip, attempted_at, success) VALUES (?, ?, ?, 1)",
        (username, ip, now_utc()),
    )
    db.commit()


def log_event(user_id: int | None, action: str, target_type: str, target_id: int | None, details: str) -> None:
    ip = request.remote_addr if request else None
    db = get_db()
    db.execute(
        """
        INSERT INTO audit_logs (user_id, action, target_type, target_id, details, created_at, ip)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (user_id, action, target_type, target_id, details, now_utc(), ip),
    )
    db.commit()


def env_flag(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def ensure_signing_keys() -> None:
    if shutil.which("openssl") is None:
        raise RuntimeError("OpenSSL is required for digital signatures.")
    os.makedirs(KEYS_DIR, exist_ok=True)

    if not os.path.exists(PRIVATE_KEY_PATH):
        subprocess.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
                PRIVATE_KEY_PATH,
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        os.chmod(PRIVATE_KEY_PATH, 0o600)

    if not os.path.exists(PUBLIC_KEY_PATH):
        subprocess.run(
            ["openssl", "rsa", "-pubout", "-in", PRIVATE_KEY_PATH, "-out", PUBLIC_KEY_PATH],
            check=True,
            capture_output=True,
            text=True,
        )


def sign_text(text: str) -> str:
    with tempfile.NamedTemporaryFile(delete=False) as text_file:
        text_file.write(text.encode("utf-8"))
        text_path = text_file.name
    try:
        proc = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", PRIVATE_KEY_PATH, "-binary", text_path],
            check=True,
            capture_output=True,
        )
        return base64.b64encode(proc.stdout).decode("ascii")
    finally:
        os.unlink(text_path)


def verify_text_signature(text: str, signature_b64: str | None) -> bool:
    if not signature_b64:
        return False
    try:
        signature = base64.b64decode(signature_b64)
    except Exception:
        return False

    with tempfile.NamedTemporaryFile(delete=False) as text_file:
        text_file.write(text.encode("utf-8"))
        text_path = text_file.name
    with tempfile.NamedTemporaryFile(delete=False) as sig_file:
        sig_file.write(signature)
        sig_path = sig_file.name

    try:
        proc = subprocess.run(
            [
                "openssl",
                "dgst",
                "-sha256",
                "-verify",
                PUBLIC_KEY_PATH,
                "-signature",
                sig_path,
                text_path,
            ],
            capture_output=True,
            text=True,
        )
        return proc.returncode == 0
    finally:
        os.unlink(text_path)
        os.unlink(sig_path)


def ensure_column(db: sqlite3.Connection, table: str, column: str, column_type: str) -> None:
    rows = db.execute(f"PRAGMA table_info({table})").fetchall()
    existing = {row["name"] for row in rows}
    if column not in existing:
        db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {column_type}")


def backfill_missing_signatures(db: sqlite3.Connection) -> None:
    posts = db.execute(
        "SELECT id, content FROM posts WHERE content_signature IS NULL OR content_signature = ''"
    ).fetchall()
    for row in posts:
        db.execute(
            "UPDATE posts SET content_signature = ? WHERE id = ?",
            (sign_text(row["content"]), row["id"]),
        )

    versions = db.execute(
        "SELECT id, content FROM post_versions WHERE content_signature IS NULL OR content_signature = ''"
    ).fetchall()
    for row in versions:
        db.execute(
            "UPDATE post_versions SET content_signature = ? WHERE id = ?",
            (sign_text(row["content"]), row["id"]),
        )


app = create_app()


if __name__ == "__main__":
    ssl_cert = os.environ.get("SSL_CERT")
    ssl_key = os.environ.get("SSL_KEY")
    ssl_context = (ssl_cert, ssl_key) if ssl_cert and ssl_key else None
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=True, ssl_context=ssl_context, threaded=True)
