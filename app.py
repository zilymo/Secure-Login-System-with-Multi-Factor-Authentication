from flask import Flask, render_template, request, redirect, flash, url_for
import bcrypt
import re
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'
DATA_FILE = 'users.txt'

def check_password_strength(password):
    if len(password) < 8:
        return "Password should be at least 8 characters long."
    if not re.search(r'[A-Z]', password):
        return "Password should have at least 1 uppercase letter."
    if not re.search(r'[a-z]', password):
        return "Password should have at least 1 lowercase letter."
    if not re.search(r'\d', password):
        return "Password should have at least 1 number."
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>/?\\|`~]', password):
        return "Password should have at least 1 special character."
    return "OK"

def user_exists(username):
    if not os.path.exists(DATA_FILE):
        return False
    with open(DATA_FILE, 'r') as file:
        for line in file:
            if line.split(',')[0] == username:
                return True
    return False

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

        if user_exists(username):
            flash("Username already exists.")
            return redirect(url_for('register'))

        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        with open(DATA_FILE, 'a') as f:
            f.write(f"{username},{hashed_pw.decode('utf-8')}\n")

        flash(f"Welcome {username}! Registration successful.")
        return redirect(url_for('register'))

    return render_template('new.html')

if __name__ == '__main__':
    app.run(debug=True)
