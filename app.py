from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
import bcrypt

def hash_password(password):
    # Hash a password (string) and return the hashed bytes
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_password(password, hashed):
    # Check if the password matches the hashed value
    return bcrypt.checkpw(password.encode('utf-8'), hashed)

# Example usage
if __name__ == "__main__":
    password1 = "mysecretpassword"
    
    # Step 1: Hash the password
    hashed = hash_password(password)
    print("Hashed password:", hashed)

    # Step 2: Check if the password matches the hash
    if check_password(password, hashed):
        print("Password matches!")
    else:
        print("Password does NOT match.")
import re  

def check_password_strength(password):
    # Check minimum length
    if len(password) < 8:
        return "Password should be at least 8 characters long."

    # Check for uppercase letter
    if not re.search(r'[A-Z]', password):
        return "Password should have at least 1 uppercase letter."

    # Check for lowercase letter
    if not re.search(r'[a-z]', password):
        return "Password should have at least 1 lowercase letter."

    # Check for a number
    if not re.search(r'\d', password):  # \d matches any digit (0-9)
        return "Password should have at least 1 number."

    # Check for a special character
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>/?\\|`~]', password):
        return "Password should have at least 1 special character."

    return "It is a good password!"

# User input
password1 = input("Enter your password: ")
result = check_password_strength(user_password)
print(result)
