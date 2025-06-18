from flask import Flask, render_template, request, redirect, url_for, session, flash
import mysql.connector
import bcrypt

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# MySQL Connection
db = mysql.connector.connect(
    host="localhost",
    user="root",           # Change if your mysql user is different
    password="@eugene19A",           # Add your mysql password here
    database="netflix_db"
)
cursor = db.cursor()

# Home page
@app.route('/')
def home():
    return render_template('index.html')

# Registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        try:
            cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed_pw))
            db.commit()
            flash("Registration successful. Please log in.")
            return redirect(url_for('login'))
        except mysql.connector.errors.IntegrityError:
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
            flash("Login successful.")
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
@app.route('/pay')
def pay():
    if 'username' not in session:
        flash("Please log in first.")
        return redirect(url_for('login'))

    plan = request.args.get('plan', 'Premium')
    prices = {
        'Mobile': 200,
        'Basic': 300,
        'Standard': 700,
        'Premium': 1100
    }
    price = prices.get(plan, 1100)

    return render_template('pay.html', username=session['username'], plan=plan, price=price)

# Logout
@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out.")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
