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
    password = "mysecretpassword"
    
    # Step 1: Hash the password
    hashed = hash_password(password)
    print("Hashed password:", hashed)

    # Step 2: Check if the password matches the hash
    if check_password(password, hashed):
        print("Password matches!")
    else:
        print("Password does NOT match.")
