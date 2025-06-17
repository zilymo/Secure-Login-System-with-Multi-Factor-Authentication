from flask import Flask, render_template, request, redirect, flash, url_for, session
import bcrypt
import re
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'
DATA_FILE = 'users.txt'

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

# Check if user exists
def user_exists(username):
    if not os.path.exists(DATA_FILE):
        return False
    with open(DATA_FILE, 'r') as file:
        for line in file:
            if line.split(',')[0] == username:
                return True
    return False

# Get stored hashed password
def get_hashed_password(username):
    with open(DATA_FILE, 'r') as file:
        for line in file:
            stored_username, stored_hash = line.strip().split(',')
            if stored_username == username:
                return stored_hash
    return None

@app.route('/')
def home():
    return render_template('index.html')

# Registration Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        strength_check = check_password_strength(password)
        if strength_check != "OK":
            flash(strength_check)
            return redirect(url_for('register'))

        if user_exists(username):
            flash("Username already exists.")
            return redirect(url_for('register'))

        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        with open(DATA_FILE, 'a') as f:
            f.write(f"{username},{hashed_pw.decode('utf-8')}\n")

        flash("Registration successful. Please sign in.")
        return redirect(url_for('login'))

    return render_template('new.html')

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not user_exists(username):
            flash("User not found.")
            return redirect(url_for('login'))

        stored_hash = get_hashed_password(username)
        if stored_hash and bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
            session['username'] = username  # Store user in session
            flash(f"Welcome {username}!")
            return redirect(url_for('welcome'))
        else:
            flash("Incorrect password.")
            return redirect(url_for('login'))

    return render_template('login.html')

# Welcome Route - protected
@app.route('/welcome')
def welcome():
    if 'username' not in session:
        flash("Please log in to access this page.")
        return redirect(url_for('login'))
    return render_template('welcome.html', username=session['username'])

# Logout Route
@app.route('/logout')
def logout():
    session.pop('username', None)
    flash("You have been logged out.")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
