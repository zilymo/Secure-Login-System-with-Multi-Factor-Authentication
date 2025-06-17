from flask import Flask, render_template, request, redirect, flash, url_for, session
import mysql.connector
import bcrypt
import re

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# MySQL Configuration
db = mysql.connector.connect(
    host="localhost",   # or your mysql server host
    user="root",        # your mysql username
    password="your_mysql_password",  # your mysql password
    database="netflix_db"
)

# Password strength check
def check_password_strength(password):
    if len(password) < 8:
        return "Password should be at least 8 characters long."
    if not re.search(r'[A-Z]', password):
        return "Password should have at least 1 uppercase letter."
    if not re.search(r'[a-z]', password):
        return "Password should have at least 1 lowercase letter."
    if not re.search(r'\d', password):
        return "Password should have at least 1 number."
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>/?\\|~]', password):
        return "Password should have at least 1 special character."
    return "OK"

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        strength_check = check_password_strength(password)
        if strength_check != "OK":
            flash(strength_check)
            return redirect(url_for('register'))

        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            flash("Username already exists.")
            return redirect(url_for('register'))

        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed_pw.decode('utf-8')))
        db.commit()
        cursor.close()

        flash("Registration successful. Please sign in.")
        return redirect(url_for('login'))

    return render_template('new.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        cursor = db.cursor()
        cursor.execute("SELECT password FROM users WHERE username = %s", (username,))
        result = cursor.fetchone()

        if result:
            stored_hash = result[0]
            if bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
                session['username'] = username
                flash(f"Welcome {username}!")
                return redirect(url_for('welcome'))
            else:
                flash("Incorrect password.")
        else:
            flash("User not found.")

        cursor.close()
        return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/welcome')
def welcome():
    if 'username' not in session:
        flash("Please log in to access this page.")
        return redirect(url_for('login'))
    return render_template('welcome.html', username=session['username'])

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash("You have been logged out.")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
