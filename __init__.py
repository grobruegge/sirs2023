from flask import Flask, render_template, __version__
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os, traceback
print(f"Using Flask-Version {__version__}")

basedir = os.path.abspath(os.path.dirname(__file__))

db = SQLAlchemy()
api = Api()
csrf = CSRFProtect()
limiter = Limiter(
    get_remote_address,
    default_limits=["5 per second"],
    storage_uri="memory://",
)
app = Flask(__name__)

@app.errorhandler(Exception)
def handle_error(e):
    if app.debug:
        print(traceback.format_exc())
        return {'syserror': repr(e)}, 500
    else:
        return {'syserror': 'It seems like something went wrong. Please contact the admin.'}, 500

@app.errorhandler(429)
def handle_error(e):
    return render_template('error.html', status_code=429, error="Too many requests"), 500

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    if app.debug:
        print(traceback.format_exc())
        return {'syserror': e.description}, 400
    else:
        return {'syserror': 'It seems like something went wrong. Please contact the admin.'}, 400   

def create_app():

    csrf.init_app(app)
    limiter.init_app(app)

    # The secret key is used to cryptographically sign (not encrypt!) cookies used for storing the session data
    app.config.update(
        FLASK_DEBUG=True,
        SECRET_KEY="gulli",
        PROPAGATE_EXCEPTIONS = True,
        #SESSION_COOKIE_HTTPONLY=True,
        #REMEMBER_COOKIE_HTTPONLY=True,
        #SESSION_COOKIE_SECURE=True,
        #REMEMBER_COOKIE_SECURE=True,
        #SESSION_COOKIE_SAMESITE="Strict",
        SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'database.db'),
        #SQLALCHEMY_DATABASE_URI = 'mysql://arne:pwdarne0!@192.168.2.15/TheCork',
        SQLALCHEMY_TRACK_MODIFICATIONS = True,
    )

    from . import models

    db.init_app(app)

    with app.app_context():
        db.drop_all()
        db.create_all()

    # blueprint for auth routes in our app
    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)

    # blueprint for non-auth parts of app
    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)
    
    api.init_app(app)

    from .fill_db import fill_database
    
    fill_database()

    return app

app = create_app()