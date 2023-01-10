from flask import Blueprint, request, render_template, redirect, url_for, flash, make_response
from flask_restful import Resource, reqparse
from . import app, api, db, basedir
from .models import UserModel, SessionModel
import sys, os, requests, hashlib, json, base64, datetime, logging
from functools import wraps
from Crypto.Cipher import AES

auth = Blueprint('auth', __name__)

COOKIE_TOKEN = "TOKEN"
logging.basicConfig(filename=os.path.join(basedir, 'output.log'), level=logging.DEBUG)

# For Presentations
def log_request_response(response):
    request = response.request
    logging.debug("\n\nREQUEST")
    logging.debug(f"Method: {request.method}")
    logging.debug(f"URL: {request.url}")
    logging.debug(f"Headers: {json.dumps(dict(request.headers), indent=4)}")
    logging.debug(f"Data: {json.dumps(json.loads(request.body.decode('utf-8')), indent=4)}")
    logging.debug("\n\nRESPONSE")
    logging.debug(f"Status code: {response.status_code}")
    logging.debug(f"URL: {response.url}")
    logging.debug(f"Headers: {json.dumps(dict(response.headers), indent=4)}")
    logging.debug(f"Data: {response.text}")

def get_current_session(token=None):
    if not token:
        token = request.cookies.get(COOKIE_TOKEN)
        if not token:
            print("[WARNING] This should never happen")
            return None

    return SessionModel.query.filter_by(token=token).first()

@app.context_processor
def templates_utility():
    return dict(get_current_session=get_current_session)

# Runs before every request
@app.before_request
def setup_session():
    def add_session_and_redirect():
        new_session = SessionModel()
        db.session.add(new_session)
        db.session.commit()

        try:
            json_data = json.loads(request.get_data())
        except:
            json_data = {}

        req = requests.request(
            method=request.method, 
            url=request.url, 
            json=json_data,
            cookies={COOKIE_TOKEN:new_session.token},
            verify=os.path.join(basedir, 'certificates', 'cert1.pem'),
        )

        response = make_response(
            req.text, req.status_code
        )

        response.set_cookie(
            key=COOKIE_TOKEN, 
            value=new_session.token,
            httponly=True,
            secure=True
        )

        return response

    if COOKIE_TOKEN not in request.cookies:
        return add_session_and_redirect()

    current_session = get_current_session()

    if current_session is None:
        return add_session_and_redirect()

def login_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        current_session = get_current_session()
        if not current_session or current_session.user is None:
            flash("This action requires you to be logged in")
            return redirect(url_for('auth.login'), 302)
        else:
            return func(*args, **kwargs)
    return decorated_function

def restaurant_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        current_session = get_current_session()
        #user = UserModel.query.filter_by(username=current_session.username).first()
        if current_session.user.restaurant_id is None:
            flash("This action exeeds your priveleges")
            return redirect(url_for('auth.login'))
        else:
            return func(*args, **kwargs)
    return decorated_function

def clear_expired_challenges(model):
    # Get the current time
    current_time = datetime.datetime.now()

    # Query the database for rows where the expiry date is passed
    non_null_rows = model.query.filter(model.challenge_expire_time != None).all()

    expired_rows = [r for r in non_null_rows if r.challenge_expire_time < current_time]

    # Clear the value of the other column for each expired row
    for row in expired_rows:
        row.challenge = None
        row.challenge_expire_time = None

    db.session.commit()

class LoginRessource(Resource):
    def __init__(self):
        self.parser = {
            'get' : reqparse.RequestParser(),
            'put' : reqparse.RequestParser(),
        }
        self.init_parser()

    def init_parser(self):
        self.parser['get'].add_argument('username', required=True, help='Username', type=str)
        self.parser['put'].add_argument('username', required=True, help='Username', type=str)
        self.parser['put'].add_argument('cipher', required=True, help='Cipher', type=str)

    def get(self): # GET method for retrieving the challenge and the SALT 
        args = self.parser['get'].parse_args(strict=True)

        user = UserModel.query.filter_by(username=args["username"]).first()

        if not user:
            return {"error": "Username does not exist"}, 404

        current_session = get_current_session()

        current_session.challenge = base64.b64encode(os.urandom(16)).decode('utf-8')
        current_session.challenge_expire_time = datetime.datetime.now() + datetime.timedelta(minutes=1)
        db.session.commit()

        return {
            "challenge": current_session.challenge,
            "salt": user.salt,
        }, 200
    
    def put(self): # Update Session and Login User
        args = self.parser['put'].parse_args(strict=True)

        current_session = get_current_session()
        clear_expired_challenges(current_session)

        user = UserModel.query.filter_by(username=args["username"]).first()

        if not user:
            return {"error": "Username does not exist"}, 404

        if not current_session.challenge:
            return {"error": "No open login request registered"}, 404

        key = base64.b64decode(user.password)
        iv = base64.b64decode(current_session.challenge)

        cipher = AES.new(key, AES.MODE_CFB, iv)

        if key != hashlib.sha256(cipher.decrypt(base64.b64decode(args["cipher"]))).digest():
            return {"error": "Incorrect password"}, 401

        # Setup the session with the current user
        current_session.challenge = None
        current_session.challenge_expire_time = None
        current_session.user = user
        db.session.commit()

        return {"message": "Login successful"}, 200
    
    def delete(self): # Update Session and Login User
        current_session = get_current_session()
        current_session.user = None
        db.session.commit()

        return {"message": "Successfully logged out of the system"}, 200


api.add_resource(LoginRessource, '/api/login')


class SignupRessource(Resource):
    def __init__(self):
        self.parser = {
            'post' : reqparse.RequestParser(),
        }
        self.init_parser()

    def init_parser(self):
        self.parser['post'].add_argument('username', required=True, help='Username', type=str)
        self.parser['post'].add_argument('password_hash', required=True, help='Password Hash', type=str)
        self.parser['post'].add_argument('salt', required=True, help='Salt used for hashing password', type=str)

    def post(self):
        args = self.parser['post'].parse_args(strict=True)

        user = UserModel.query.filter_by(username=args["username"]).first()

        if user:
            return {"error": "Username already taken"}, 409

        db.session.add(
            UserModel(
                username=args["username"],
                password=base64.b64encode(hashlib.sha256(base64.b64decode(args["password_hash"])).digest()).decode('utf-8'),
                salt=args["salt"]
            )
        )
        db.session.commit()

        return {"message": "User created successfully"}, 201

api.add_resource(SignupRessource, '/api/signup')

@auth.route('/login', methods=['GET'])
def login():
    return render_template('login.html')

@auth.route('/login', methods=['POST'])
def login_post():

    username = request.form.get('username')

    login_post_response = requests.get(
        url = request.url_root + 'api/login',
        json = {
            "username":username
        },
        cookies = request.cookies,
        verify = os.path.join(basedir, 'certificates', 'cert1.pem'),
    )

    if login_post_response.status_code != 200:
        if "error" in login_post_response.json():
            flash(login_post_response.json()["error"])
            return redirect(url_for('auth.login'))
        else:
            return render_template('error.html', status_code=login_post_response.status_code, error=login_post_response.json().get("syserror", "Weird error")), 500
    
    # For presentation
    log_request_response(login_post_response)

    password = request.form.get('password')

    pwd_digest = hashlib.pbkdf2_hmac(
        hash_name='sha256', 
        password=password.encode(),
        salt=base64.b64decode(login_post_response.json()["salt"]),
        iterations=1000
    )

    key = hashlib.sha256(pwd_digest).digest()
    iv = base64.b64decode(login_post_response.json()["challenge"])

    cipher = AES.new(key, AES.MODE_CFB, iv)

    login_put_response = requests.put(
        url = request.url_root + 'api/login',
        json = {
            "username": username,
            "cipher": base64.b64encode(cipher.encrypt(pwd_digest)).decode('utf-8')
        },
        cookies = request.cookies,
        verify = os.path.join(basedir, 'certificates', 'cert1.pem'),
    )

    if login_put_response.status_code != 200:
        if "error" in login_put_response.json():
            flash(login_put_response.json()['error'])
            return redirect(url_for('auth.login'))
        else:
            return render_template('error.html', status_code=login_put_response.status_code, error=login_put_response.json().get("syserror", "Weird error")), 500

    # For presentation
    log_request_response(login_put_response)

    return redirect(url_for('main.index'))

@auth.route('/signup', methods=['GET'])
def signup():
    return render_template('signup.html')

@auth.route('/signup', methods=['POST'])
def signup_post():

    username = request.form.get('username')
    password = request.form.get('password')

    salt = os.urandom(8)

    pwd_digest = hashlib.pbkdf2_hmac(
        hash_name='sha256', 
        password=password.encode(),
        salt=salt,
        iterations=1000,
    )

    signup_post_response = requests.post(
        url = request.url_root + 'api/signup',
        json = {
            "username":username,
            "password_hash":base64.b64encode(pwd_digest).decode('utf-8'),
            "salt":base64.b64encode(salt).decode('utf-8'),
        },
        cookies=request.cookies,
        verify=os.path.join(basedir, 'certificates', 'cert1.pem'),
    )

    if signup_post_response.status_code != 201:
        if "error" in signup_post_response.json():
            flash(signup_post_response.json()['error'])
            return redirect(url_for('auth.signup'))
        else:
            return render_template('error.html', status_code=signup_post_response.status_code, error=signup_post_response.json().get("syserror", "Weird error")), 500
    
    # For presentation
    log_request_response(signup_post_response)

    return redirect(url_for('auth.login'))