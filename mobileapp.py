import click, requests, os, hashlib, base64

OPTION_TEXT = "What do you want to do? \n \
    0: Show all restaurants close to your location \n \
    1: Login \n \
    2: Signup \n"
BASE_URL = "http://127.0.0.1:5000/"

@click.command()
@click.option('--action', prompt=OPTION_TEXT, help='Action you want to do', type=int)
def main(action):

    session = requests.Session()
    session.get(url=BASE_URL)

    while True:
        while action not in (0,1,2):
            action = click.prompt(OPTION_TEXT, type=int)
        
        if action == 0:
            pass
        elif action == 1:
            pass
        elif action == 2:
            
            username = click.prompt("Username", type=str)
            password = click.prompt("Password", hide_input=True, confirmation_prompt=True)

            salt = os.urandom(8)

            pwd_digest = hashlib.pbkdf2_hmac(
                hash_name='sha256', 
                password=password.encode(),
                salt=salt,
                iterations=1000,
            )

            signup_post_response = session.post(
                url=BASE_URL+"api/signup",
                json={
                    "username":username,
                    "password_hash":base64.b64encode(pwd_digest).decode('utf-8'),
                    "salt":base64.b64encode(salt).decode('utf-8'),
                }
            ).json()

            if "error" in signup_post_response.keys():
                click.echo(signup_post_response['error'])

        if click.confirm('Do you want to continue?'):
            click.echo('Continuing...')
            action=''
        else:
            click.echo('Exiting...')
            break
        
if __name__ == '__main__':
    main()