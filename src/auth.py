from flask import session

# Demo users with roles
USERS = {
    "admin": {
        "password": "admin123",
        "role": "admin"
    },
    "analyst": {
        "password": "analyst123",
        "role": "analyst"
    }
}


def login_user(username, password):
    user = USERS.get(username)
    if user and user["password"] == password:
        session["user"] = username
        session["role"] = user["role"]
        return True
    return False


def logout_user():
    session.clear()


def is_logged_in():
    return "user" in session


def is_admin():
    return session.get("role") == "admin"
