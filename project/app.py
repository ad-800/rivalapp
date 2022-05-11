import os
import sqlite3
import traceback

from flask import Flask, render_template, redirect, request, session
from flask_session import Session

from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Configure Library to use SQLite database
db = sqlite3.connect('rival.db', check_same_thread=False)
c = db.cursor()

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        try:
            # Query database for username
            c = c = db.cursor()
            rows = c.execute("SELECT * FROM users WHERE username = ?", (request.form.get("username"), ))
            row = rows.fetchall()

            # Ensure username exists and password is correct
            if len(row) != 1 or not check_password_hash(row[0][2], (request.form.get("password"), )):
                return apology("invalid username and/or password", 403)

        except Exception as exception:
            print(traceback.format_exc())

        session['username'] = row[0][1]

        # Redirect user to home page
        return render_template("index.html")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        school = request.form.get("school")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username")

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password")

        # Ensure password was submitted
        elif not request.form.get("confirmation"):
            return apology("must provide confirmation")

        # Ensure password confirmation is correct
        if password != confirmation:
            return apology("confirmation must match password")

        hash = generate_password_hash(password)

        try:
            c = c = db.cursor()
            c.execute("INSERT INTO users (username, hash, school) VALUES (?, ?, ?)", (username, hash, school))
            db.commit()
            return redirect("/login")
        except:
            return apology("username is already registered")

    else:
        return render_template("register.html")

@app.route("/profile")
def profile():
    return render_template("profile.html", username=session['username'])

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/club", methods=["GET", "POST"])
def club():
    if request.method == "POST":
        name = request.form.get("clubname")
        description = request.form.get("clubdescription")
        goals = request.form.get("clubgoals")

        c = c = db.cursor()
        c.execute("INSERT INTO clubs (user_id, name, description, goals) VALUES (?, ?, ?, ?)", (session['username'], name, description, goals))
        db.commit()

        # Redirect user to home page
        return render_template("index.html")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("club.html")

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

if __name__ == "__main__":
    app.run(debug=True, port=8080, use_reloader=False)