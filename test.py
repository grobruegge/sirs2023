import requests
from collections import OrderedDict

SERVER = '127.0.0.1'
PORT=5000
ENDPOINT='api/auth'

link = 'http://127.0.0.1:5000/api/auth'

def pretty_print_POST(req):
    """
    At this point it is completely built and ready
    to be fired; it is "prepared".

    However pay attention at the formatting used in 
    this function because it is programmed to be pretty 
    printed and may differ from the actual request.
    """
    print('{}\n{}\r\n{}\r\n\r\n{}'.format(
        '-----------START-----------',
        req.method + ' ' + req.url,
        '\r\n'.join('{}: {}'.format(k, v) for k, v in req.headers.items()),
        req.body,
    ))

#response = requests.Request('post', link, json={"username":"arne"}, headers={'Content-Type': 'application/json'})
#prepared = response.prepare()
#pretty_print_POST(prepared)

#response = requests.post(link, json={"username":"arne"})

#print(response.text)

salt = os.urandom(8)

pwd_digest = hashlib.pbkdf2_hmac(
    hash_name='sha256', 
    password="pwd".encode(),
    salt=salt,
    iterations=1000,
)

requests.post(
    url=request.base_url+'api/signup', #FIXME: dynamic call?
    json={
        "username":"arne",
        "password_hash":base64.b64encode(pwd_digest).decode('utf-8'),
        "salt":base64.b64encode(salt).decode('utf-8'),
    },
)

signup_post_response = requests.post(
    url='http://127.0.0.1:5000/api/bookings', #FIXME: dynamic call?
    json={
        "tableID": 2,
        "date": "2023-01-02"
    }
)

print(signup_post_response.text)
"""

session = requests.session()

params = {'field1' : 'value1', 'field2' : 'value2'}

## Similar for other methods

#r = session.post('http://127.0.0.1:5000/api/signup') 
r = session.post('http://127.0.0.1:5000/api/signup', json={
        "username":"malte",
        "password_hash":"21213123",
        "salt":"213adsd"
    },
    verify='certificates/cert1.pem') 
all_cookies = requests.utils.dict_from_cookiejar(session.cookies)
print(r.text)
print(all_cookies)
# update and resend cookies
#session.cookies.set('field', 'new_value', domain='domain_of_cookie', path='path_of_cookie')

## Similar for other methods
#r = session.get(SERVER, params=params)
"""