import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
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
# if not os.environ.get("API_KEY"):
#     raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    cash = db.execute('select cash from users where id=?',
                      session['user_id'])[0]['cash']
    stocks = db.execute(
        'select symbol, name, shares from stocks join symbols on stocks.symbol_id=symbols.id where user_id=?', session['user_id'])

    for stock in stocks:
        updates = lookup(stock['symbol'])
        stock['price'] = updates['price']
        stock['total'] = updates['price']*stock['shares']
        stock['symbol']=updates['symbol']
    total = cash+sum([stock['total'] for stock in stocks])
    print(stocks)
    print(cash)

    return render_template('index.html', cash=cash, stocks=stocks, total=total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == 'POST':
        symbol = request.form.get('symbol').lower()
        if not symbol:
            return apology("enter symbol")
        shares = request.form.get('shares')
        try:
            if int(shares) == float(shares):
                shares = int(shares)
            else:
                return apology('number of shares must be integer greater than 0')
        except:
            return apology('number of shares must be integer greater than 0')

        if shares <= 0:
            return apology('number of shares must be greater than 0')
        symbol_price = lookup(symbol)
        if not symbol_price:
            return apology('invalid symbol')
        current_cash = db.execute(
            '''SELECT cash FROM users WHERE id = ?''', session['user_id'])[0]['cash']

        amount = symbol_price['price']*shares
        if amount <= current_cash:
            db.execute('''UPDATE users SET cash = ?''', current_cash-amount)
            symbol_id = db.execute(
                '''SELECT id from symbols where symbol = ?''', symbol)
            if not symbol_id:
                symbol_id = db.execute(
                    '''INSERT INTO symbols (symbol,name) VALUES(?, ?)''', symbol, symbol_price['name'])
            else:
                symbol_id = symbol_id[0]['id']

            symbol_in_stocks = db.execute(
                '''SELECT symbol_id FROM stocks WHERE user_id=? and symbol_id in (SELECT id FROM symbols WHERE symbol = ?)''', session['user_id'], symbol)
            if not symbol_in_stocks:
                db.execute('''INSERT INTO stocks (user_id,symbol_id,shares) VALUES(?,?,?)''',
                           session['user_id'], symbol_id, shares)
            else:
                db.execute('''UPDATE stocks SET shares = shares + ? where user_id=? and symbol_id=?''',
                           shares, session['user_id'], symbol_id)
            return redirect('/')

        else:
            return apology('insufficient cash')

    return render_template('buy.html')


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    return apology("TODO")


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
        rows = db.execute("SELECT * FROM users WHERE username = ?",
                          request.form.get("username").lower())

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
    if request.method == 'POST':
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("enter a symbol")
        res = lookup(symbol)
        if res:
            return render_template("quoted.html", name=res['name'], symbol=res['symbol'], price=res['price'])
        else:
            return apology("Error: symbol not found")
    return render_template('quote.html')


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get("username").lower()
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        if not username:
            return apology("enter username")
        if not password:
            return apology("enter password")
        if not confirmation:
            return apology("confirm password")
        if password != confirmation:
            return apology("password and confirm password don't match.")
        if len(db.execute('''SELECT username FROM users WHERE username = ?''', username)) != 0:
            return apology("username not available")
        password_hash = generate_password_hash(password)
        db.execute('''INSERT INTO users (username,hash) VALUES(?,?)''',
                   username, password_hash)
        return login()
    return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == 'POST':
        symbol = request.form.get('symbol')
        if not symbol:
            return apology("enter symbol")
        shares = request.form.get('shares')
        try:
            if int(shares) == float(shares):
                shares = int(shares)
            else:
                return apology('number of shares must be integer greater than 0')
        except:
            return apology('number of shares must be integer greater than 0')

        if shares <= 0:
            return apology('number of shares must be greater than 0')
        symbol_price = lookup(symbol)
        if not symbol_price:
            return apology('invalid symbol')
        symbol_id = db.execute(
            '''SELECT id FROM symbols WHERE symbol=?''', symbol)
        if not symbol_id:
            return apology("given symbol doesn't exist.")
        symbol_id=symbol_id[0]['id']
        current_shares = db.execute(
            '''SELECT shares FROM stocks WHERE user_id = ? and symbol_id=?''', session['user_id'], symbol_id)
        if not current_shares:
            return apology("you don't hold any shares of this symbol")
        current_shares = current_shares[0]['shares']

        amount = symbol_price['price']*shares
        if shares <= current_shares:
            db.execute('''UPDATE users SET cash = cash + ? where id= ?''',
                       amount, session['user_id'])

            db.execute('''UPDATE stocks SET shares = shares - ? where user_id=? and symbol_id=?''',
                       shares, session['user_id'], symbol_id)
            db.execute('''DELETE FROM stocks WHERE shares=0''')

            return redirect('/')

        else:
            return apology('insufficient shares')
    stocks=db.execute('''SELECT symbol FROM symbols JOIN stocks ON stocks.symbol_id=symbols.id''')
    return render_template('sell.html',stocks=stocks)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
