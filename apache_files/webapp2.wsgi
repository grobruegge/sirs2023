#!/usr/bin/python3

import sys
import logging

logging.basicConfig(level=logging.DEBUG, filename='/var/www/webapp2/logs/webapp2.log', format='%(asctime)s %(message)s')
sys.path.insert(0,"/var/www/webapp2/")
sys.path.insert(0,"/home/seed/Documents/TheCork/env/lib/python3.8/site-packages")

from webapp2 import app as application
#application.secret_key = 'arne'