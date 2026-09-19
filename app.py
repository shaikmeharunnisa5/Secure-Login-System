from flask import Flask, request, redirect, url_for, session
import sqlite3
import bcrypt
import re

app = Flask(__name__)

# Secret key for secure sessions
app.secret_key = "task4-secure-login-secret-key"


# -----------------------------
# Database setup
# -----------------------------
def init_db():
    conn = sqlite3.connect("users.db")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


# -----------------------------
# Input validation
# -----------------------------
def valid_username(username):
    return re.fullmatch(r"[A-Za-z0-9_]{3,30}", username) is not None


def valid_password(password):
    return len(password) >= 8


# -----------------------------
# Home page
# -----------------------------
@app.route("/")
def home():

    if "username" in session:
        return f"""
        <h1>Welcome, {session["username"]}!</h1>

        <p>You are successfully logged in.</p>

        <a href="/logout">Logout</a>
        """

    return """
    <h1>Secure Login System</h1>

    <a href="/register">Register</a>
    <br><br>

    <a href="/login">Login</a>
    """


# -----------------------------
# Register
# -----------------------------
@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Input validation
        if not valid_username(username):
            return """
            <h3>Invalid username.</h3>
            <p>Use 3-30 letters, numbers, or underscores.</p>
            <a href="/register">Try again</a>
            """

        if not valid_password(password):
            return """
            <h3>Password must contain at least 8 characters.</h3>
            <a href="/register">Try again</a>
            """

        # Hash password using bcrypt
        hashed_password = bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt()
        )

        conn = sqlite3.connect("users.db")

        try:

            # Parameterized query prevents SQL injection
            conn.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, hashed_password.decode("utf-8"))
            )

            conn.commit()
            conn.close()

            return """
            <h2>Registration successful!</h2>

            <p>Your password has been securely hashed.</p>

            <a href="/login">Go to Login</a>
            """

        except sqlite3.IntegrityError:

            conn.close()

            return """
            <h3>Username already exists.</h3>
            <a href="/register">Try another username</a>
            """

    return """
    <h1>Register</h1>

    <form method="POST">

        <label>Username:</label>
        <br>

        <input type="text" name="username" required>

        <br><br>

        <label>Password:</label>
        <br>

        <input type="password" name="password" required>

        <br><br>

        <button type="submit">Register</button>

    </form>

    <br>

    <a href="/">Home</a>
    """


# -----------------------------
# Login
# -----------------------------
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Basic validation
        if not username or not password:
            return """
            <h3>Username and password are required.</h3>
            <a href="/login">Try again</a>
            """

        conn = sqlite3.connect("users.db")

        # Parameterized query prevents SQL injection
        cursor = conn.execute(
            "SELECT username, password FROM users WHERE username = ?",
            (username,)
        )

        user = cursor.fetchone()

        conn.close()

        # Check user and password
        if user and bcrypt.checkpw(
            password.encode("utf-8"),
            user[1].encode("utf-8")
        ):

            # Create session
            session["username"] = user[0]

            return redirect(url_for("home"))

        else:

            return """
            <h3>Invalid username or password.</h3>

            <a href="/login">Try again</a>
            """

    return """
    <h1>Login</h1>

    <form method="POST">

        <label>Username:</label>
        <br>

        <input type="text" name="username" required>

        <br><br>

        <label>Password:</label>
        <br>

        <input type="password" name="password" required>

        <br><br>

        <button type="submit">Login</button>

    </form>

    <br>

    <a href="/">Home</a>
    """


# -----------------------------
# Logout
# -----------------------------
@app.route("/logout")
def logout():

    # Remove username from session
    session.pop("username", None)

    return redirect(url_for("home"))


# -----------------------------
# Start application
# -----------------------------
if __name__ == "__main__":

    init_db()

    app.run(debug=True)