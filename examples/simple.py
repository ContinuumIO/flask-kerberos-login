from flask import Flask
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user
from flask_kerberos_login import KerberosLoginManager

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret'
app.config['DEBUG'] = True


login_manager = LoginManager(app)
kerberos_manager = KerberosLoginManager(app)

# Create a dictionary to store the users in when they authenticate
# This example stores users in memory.
users = {}

# Declare an Object Model for the user, and make it comply with the 
# flask-login UserMixin mixin.
class User(UserMixin):
    def __init__(self, email):
        self.email = email

    def __repr__(self):
        return self.email

    def get_id(self):
        return self.email

    def is_anonymous(self):
        return False

# Declare a User Loader for Flask-Login.
# Simply returns the User if it exists in our 'database', otherwise 
# returns None.
@login_manager.user_loader
def load_user(email):
    email = str(email)
    return users.get(email)


@kerberos_manager.save_user
def save_user(email):
    email = str(email)
    user = users[email] = User(email)
    # generate a cookie/session for this user the first time we see them.
    login_user(user)

@app.route('/')
@login_required
def home():
    return 'hello %s!' % current_user


if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    host = os.environ.get('HOST', '127.0.0.1')
    app.run(debug=True, port=port, host=host)
