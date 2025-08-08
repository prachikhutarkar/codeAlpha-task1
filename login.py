import bcrypt
import json

def load_users():
    with open("users.json", "r") as f:
        return json.load(f)

def login(username, password):
    users = load_users()
    if username in users:
        stored_hash = users[username].encode('utf-8')
        if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
            print("Login successful!")
            return True
    print("Login failed.")
    return False

# Take input
user = input("Enter username: ")
passwd = input("Enter password: ")

login(user, passwd)
