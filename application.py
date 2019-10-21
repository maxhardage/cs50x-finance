import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    #sum transactions by symbol for user id
    user_id = session["user_id"]
    value_stock = 0
    rows = db.execute("SELECT symbol, SUM(shares) FROM transactions GROUP BY symbol HAVING user_id = :user_id", user_id=user_id)

    #lookup price of each stock, append rows with a price and value field

    for row in rows:
        quoted = lookup(row["symbol"])
        row["price"] = quoted["price"]
        row["value"] = row["price"] * row["SUM(shares)"]
        value_stock = value_stock + row["value"]

    rows2 = db.execute("SELECT * FROM users WHERE id = :user_id", user_id=user_id)
    cash = rows2[0]["cash"]

    #calculate total portfolio value
    value_total = value_stock + cash

    #re-format price and value
    for row in rows:
        row["price"] = usd(row["price"])
        row["value"] = usd(row["value"])

    return render_template("index.html", rows=rows, value_total=usd(value_total), cash=usd(cash))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    user_id = session["user_id"]

    # POST requests
    if request.method == "POST":

        # check shares
        shares = int(request.form.get("shares"))
        if not shares or shares < 1 or shares % 1 != 0:
            return apology("input number of shares", 400)

        # look up symbol
        quoted = lookup(request.form.get("symbol"))
        if not quoted or len(quoted) != 3:
            return apology("symbol not found", 400)

        # check if user has enough cash
        rows = db.execute("SELECT * FROM users WHERE id = :user_id", user_id=user_id)
        cash = rows[0]["cash"]
        transactioncost = shares * quoted["price"]
        if transactioncost > cash:
            return apology("not enough cash for this transaction", 400)
        else:
            # add to transactions
            db.execute("INSERT INTO transactions (user_id, symbol, shares, price) VALUES (:user_id, :symbol, :shares, :price)",
                        user_id=user_id, symbol=quoted["symbol"], shares=shares, price=quoted["price"])
            #modify cash
            cash = cash - transactioncost
            db.execute("UPDATE users SET cash = :cash WHERE id = :user_id", user_id=user_id, cash=cash)

        # redirect to homepage
        return redirect("/")

    # GET requests
    else:
        return render_template("buy.html")


@app.route("/check", methods=["GET"])
def check():
    """Return true if username available, else false, in JSON format"""

    username = request.args.get("username")
    #check if username exists, return True if not
    if len(username) > 0 and len(db.execute("SELECT * FROM users WHERE username = :username", username=username)) == 0:
        return jsonify(True)
    else:
        return jsonify(False)

@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    user_id = session["user_id"]
    # call transactions for user
    rows = db.execute("SELECT datetime, symbol, shares, price FROM transactions WHERE user_id = :user_id", user_id = user_id)
    # reformat prices
    for row in rows:
        row["price"] = usd(row["price"])
        if row["shares"] > 0:
            row["type"] = 'BUY'
        else:
            row["type"] = "SELL"

    # send to history.html to create browser table
    return render_template("history.html", rows=rows)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

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

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    # form submissions
    if request.method == "POST":

        # call lookup function
        quoted = lookup(request.form.get("symbol"))
        if not quoted or len(quoted) != 3:
            return apology("symbol not found", 400)

        return render_template("quoted.html", name=quoted["name"], price=usd(quoted["price"]), symbol=quoted["symbol"])

    # GET requests
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user."""

    # Forget any user_id
    session.clear()

    if request.method == "POST":

        # check for username submitted
        if not request.form.get("username"):
            return apology("Missing username!", 400)

        # check for password submitted
        elif not request.form.get("password") or not request.form.get("confirmation"):
            return apology("Missing password!", 400)

        #ccheck passwords match
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("Passwords do not match!", 400)

        # hash password
        pwd_hash = generate_password_hash(request.form.get("password"))

        # add user to database
        username = request.form.get("username")
        result = db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)",
                            hash=pwd_hash, username=username)
        if not result:
            return apology("Username is already taken!", 400)

        # Remember which user has logged in
        rows = db.execute("SELECT * FROM users WHERE username = :username", username=username)
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")

@app.route("/changepw", methods=["GET", "POST"])
@login_required
def changepw():
    """Change Password."""

    user_id = session["user_id"]

    # handles post requests
    if request.method == "POST":

        # check for fields submitted
        if not request.form.get("currentpw") or not request.form.get("newpw") or not request.form.get("newpw2"):
            return apology("All fields required", 400)

        # check if current password matches
        hash_current = db.execute("SELECT * FROM users WHERE id = :user_id", user_id=user_id)
        if not check_password_hash(hash_current[0]["hash"], request.form.get("currentpw")):
            return apology("Current password incorrect")

        #check passwords match
        elif request.form.get("newpw") != request.form.get("newpw2"):
            return apology("Passwords do not match!", 400)

        # hash password
        pwd_hash = generate_password_hash(request.form.get("newpw"))

        # add modifiy password in database
        db.execute("UPDATE users SET hash = :pwd_hash WHERE id = :user_id", user_id=user_id, pwd_hash=pwd_hash)

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("changepw.html")

@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    user_id = session["user_id"]

    # POST requests
    if request.method == "POST":

        # check shares
        shares = int(request.form.get("shares"))
        if not shares or shares < 1 or shares % 1 != 0:
            return apology("postive whole number of shares")

        # lookup symbol, check if symbol exists
        quoted = lookup(request.form.get("symbol"))
        if not quoted or len(quoted) != 3:
            return apology("Symbol not found")

        #check user has shares to sell
        rows = db.execute("SELECT symbol, SUM(shares) FROM transactions WHERE user_id = :user_id AND symbol = :symbol",
                            user_id=user_id, symbol=quoted["symbol"])
        if not rows[0]["SUM(shares)"]:
            return apology("you do not own this stock")

        elif rows[0]["SUM(shares)"] < shares:
            return apology("reduce number of shares")

        else:
            # add to transactions, ensuring shares is recorded as negative
            db.execute("INSERT INTO transactions (user_id, symbol, shares, price) VALUES (:user_id, :symbol, :shares, :price)",
                        user_id=user_id, symbol=quoted["symbol"], shares=-shares, price=quoted["price"])
            #modify cash
            rows2 = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=user_id)
            cash = rows2[0]["cash"]
            cash = cash + shares * quoted["price"]
            db.execute("UPDATE users SET cash = :cash WHERE id = :user_id", user_id=user_id, cash=cash)

        # redirect to homepage
        return redirect("/")

    # GET requests
    else:
        stocks = db.execute("SELECT symbol FROM transactions WHERE user_id = :user_id GROUP BY symbol", user_id=user_id)
        return render_template("sell.html", stocks=stocks)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
