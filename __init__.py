from flask import Flask, redirect, url_for, __version__
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy
import os, hashlib, base64, datetime, traceback, logging
print(f"Using Flask-Version {__version__}")

basedir = os.path.abspath(os.path.dirname(__file__))

db = SQLAlchemy()
api = Api()
app = Flask(__name__)

@app.errorhandler(Exception)
def handle_error(e):
    if app.debug:
        print(traceback.format_exc())
        return {'syserror': repr(e)}, 500
    else:
        return {'syserror': 'It seems like something went wrong. Please contact the admin.'}, 500

def create_app():

    #app.app_context().push()

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

    restaurants_example_1 = models.RestaurantModel(
        name='PizzaHut',
        category='Pizza',
        location='Lisbon',
        description='Mama Mia'
    )
    restaurants_example_2 = models.RestaurantModel(
        name='BurgerPlace',
        category='Burger',
        location='Porto',
        description='Very cozy place'
    )

    salt = os.urandom(8)

    pwd_digest = hashlib.pbkdf2_hmac(
        hash_name='sha256', 
        password="pwd".encode(),
        salt=salt,
        iterations=1000,
    )

    # Add examples to the database
    new_user = models.UserModel(
        username="arne", 
        password=base64.b64encode(hashlib.sha256(pwd_digest).digest()).decode('utf-8'),
        salt=base64.b64encode(salt).decode('utf-8'),
        #restaurant=restaurants_example_2,
    )

    table_ex_1 = models.TableModel(
        size=5,
        restaurant=restaurants_example_2,
    )
    table_ex_2 = models.TableModel(
        size=6,
        restaurant=restaurants_example_2,
    )

    booking_ex_1 = models.BookingModel(
        date=datetime.datetime.strptime("2023-01-05", "%Y-%m-%d"),
        table=table_ex_1,
        user=new_user,
    )

    #print(f'Restaurant: {table_ex_2.restaurant.name}')
    #print(f'Table from Restaurant: {restaurants_example_2.tables}')
    #print(f'Table Size: {table_ex_2.size}')

    with app.app_context():
        db.session.add(new_user)
        db.session.add(restaurants_example_1)
        db.session.add(restaurants_example_2)
        db.session.add(table_ex_1)
        db.session.add(table_ex_2)
        db.session.add(booking_ex_1)
        db.session.commit()

    return app

app = create_app()