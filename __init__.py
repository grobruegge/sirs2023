import flask
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy
import os
print(f"Using Flask-Version {flask.__version__}")

basedir = os.path.abspath(os.path.dirname(__file__))

db = SQLAlchemy()
api = Api()
app = flask.Flask(__name__)

@app.errorhandler(Exception)
def handle_error(e):
    if app.debug:
        return {'error': str(e)}, 500
    else:
        return {'error': 'It seems like something went wrong. Please contact the admin.'}, 500

def create_app():

    app.app_context().push()

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

    db.init_app(app)

    from . import models

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

    # Add examples to the database
    new_user = models.UserModel(
        username="arne", 
        password="any_pwd",
        salt="adsas123nf12"
    )

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
    table_ex_1 = models.TableModel(
        size=5,
        restaurant=restaurants_example_2,
    )
    table_ex_2 = models.TableModel(
        size=6,
        restaurant=restaurants_example_2,
    )

    #print(f'Restaurant: {table_ex_2.restaurant.name}')
    #print(f'Table from Restaurant: {restaurants_example_2.tables}')
    #print(f'Table Size: {table_ex_2.size}')

    #with app.app_context():
    db.session.add(new_user)
    db.session.add(restaurants_example_1)
    db.session.add(restaurants_example_2)
    db.session.add(table_ex_1)
    db.session.add(table_ex_2)
    db.session.commit()

    return app

app = create_app()