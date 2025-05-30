from flask import Flask, render_template, request, redirect, flash
import bcrypt
import re

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Needed for flashing messages

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

# Routes
@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        strength_check = check_password_strength(password)
        if strength_check != "OK":
            flash(strength_check)
            return redirect('/')

        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        flash(f'Welcome {username}! Your password was securely hashed.')
        return redirect('/')

    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
