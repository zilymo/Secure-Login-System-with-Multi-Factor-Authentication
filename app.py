from flask import Flask, render_template, request, redirect, flash
import bcrypt
import re
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Needed for flashing messages
DATA_FILE = 'users.txt'  # File to store user data

# Password strength checker
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


@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        
        strength_check = check_password_strength(password)
        if strength_check != "OK":
            flash(strength_check)
            return redirect('/')

        
        if user_exists(username):
            flash("Username already exists. Please choose another one.")
            return redirect('/')

        # Hash password
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Store user data
        with open(DATA_FILE, 'a') as file:
            file.write(f"{username},{hashed.decode('utf-8')}\n")

        flash(f'Welcome {username}! Your password was securely hashed and stored.')
        return redirect('/')

    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
