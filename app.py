from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from flask_mail import Mail
import os

# ----------------- Flask App Config ----------------- #
app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///trustvote.db'
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'faces')
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 16MB max upload

# ----------------- Mail Config (Gmail SMTP) ----------------- #
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'nirajbista09@gmail.com'
app.config['MAIL_PASSWORD'] = 'xgaj cuvm snhs parz'  # App-specific password
app.config['MAIL_DEFAULT_SENDER'] = 'nirajbista09@gmail.com'

# ----------------- Extensions ----------------- #
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
mail = Mail(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ----------------- Route Registration ----------------- #
from routes import *

# ----------------- App Runner ----------------- #
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
