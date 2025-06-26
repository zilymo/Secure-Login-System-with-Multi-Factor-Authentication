from flask import Flask, render_template, request, redirect, url_for, session, flash
import mysql.connector
import bcrypt
import re

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# MySQL Connection
db = mysql.connector.connect(
    host="localhost",
    user="root",  # Change if needed
    password="Iam2sickforthis",  # Change if needed
    database="netflix_db"
)
cursor = db.cursor() #the connector

def check_password_strength(password):
    if len(password) < 8:
        return "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return "Password must include at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return "Password must include at least one lowercase letter."
    if not re.search(r"[0-9]", password):
        return "Password must include at least one number."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return "Password must include at least one special character."
    return None


# Home page gets you to the home page
@app.route('/')
def home():
    return render_template('index.html')

# Registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Check password strength
        error = check_password_strength(password)
        if error:
            flash(error)
            return redirect(url_for('register'))


        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        try:
            cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed_pw))
            db.commit()
            flash("Registration successful. Please log in.")
            return redirect(url_for('login'))
        except mysql.connector.errors.IntegrityError: #checks if the username exists
            flash("Username already exists.")
            return redirect(url_for('register'))

    return render_template('new.html')

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        cursor.execute("SELECT password FROM users WHERE username = %s", (username,))
        result = cursor.fetchone()

        if result and bcrypt.checkpw(password.encode('utf-8'), result[0].encode('utf-8')):
            session['username'] = username
            flash(f"Welcome {username}!")
            return redirect(url_for('welcome'))
        else:
            flash("Invalid credentials.")
            return redirect(url_for('login'))
    
    return render_template('login.html')

# Welcome / Plan selection
@app.route('/welcome')
def welcome():
    if 'username' not in session:
        flash("Please log in first.")
        return redirect(url_for('login'))
    return render_template('welcome.html', username=session['username'])

# Payment Page
@app.route('/pay', methods=['GET', 'POST'])
def pay():
    if 'username' not in session:
        flash("Please log in first.")
        return redirect(url_for('login'))

    prices = {
        'Mobile': 200,
        'Basic': 300,
        'Standard': 700,
        'Premium': 1100
    }

    if request.method == 'GET':
        plan = request.args.get('plan', 'Premium')
        price = prices.get(plan, 1100)
        return render_template('pay.html', username=session['username'], plan=plan, price=price)

    # Handle POST submission (payment form)
    plan = request.form['plan']
    price = request.form['price']
    card_number = request.form['card_number']
    expiration_date = request.form['expiration_date']
    cvv = request.form['cvv']
    name_on_card = request.form['name_on_card']

    # Insert into payments table
    cursor.execute("""
        INSERT INTO payments (username, plan, price, card_number, expiration_date, cvv, name_on_card)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """, (session['username'], plan, price, card_number, expiration_date, cvv, name_on_card))
    db.commit()

    flash("Payment successful!")
    return redirect(url_for('welcome'))

# Logout
@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out.")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
