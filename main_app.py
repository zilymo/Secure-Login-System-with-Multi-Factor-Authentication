from flask import Flask, render_template, request, redirect, flash, url_for
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import re

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Configure SQLite database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

# Define User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# Password strength check function
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

# Home route
@app.route('/')
def home():
    return render_template('index.html')

# Register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()

        # Check password strength
        strength_check = check_password_strength(password)
        if strength_check != "OK":
            flash(strength_check)
            return redirect(url_for('register'))

        # Check if user already exists
        if User.query.filter_by(username=username).first():
            flash("Username already exists.")
            return redirect(url_for('register'))

        # Hash the password
        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Save user to database
        new_user = User(username=username, password=hashed_pw.decode('utf-8'))
        db.session.add(new_user)
        db.session.commit()

        flash(f"Welcome {username}! Registration successful.")
        return redirect(url_for('register'))

    return render_template('new.html')

if __name__ == '__main__':
    # Create the database tables if they don't exist
    with app.app_context():
        db.create_all()
    app.run(debug=True)
