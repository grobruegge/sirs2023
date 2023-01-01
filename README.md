# TheCork

## How to get it running

Run the following commands in your terminal:

- `export FLASK_APP=TheCork`
- `export FLASK_DEBUG=True`

Then (within the terminal) change to the directory containing *TheCork* and run:

- `flask run`

Be aware that the authentication endpoints are not yet integrated in the frontend. For testing purposes it is necessary to call the following endpoints manually:

- /signup
- /login

## Useful commands

Check whether the Web Server Gateway Interface (WSGI) file which Apache uses to communicate with Flask has syntax errors:
- sudo apache2ctl configtest

Enable or disable Apache web application (thecork) which has a .conf file within /etc/apache2/sites-available
- sudo a2ensite thecork.conf
- sudo a2dissite thecork.conf

Restart Apache Service
- sudo systemctl reload apache2

Activate SSH Engine:
- sudo a2enmod ssl

If you change anything in the Apache configuration, RESET your browser cookies!