import mysql.connector

"""
Script to test database connection
"""

mydb = mysql.connector.connect(
    host="192.168.2.15",
    user="arne",
    passwd="pwdarne0!",
)

my_cursor = mydb.cursor()
my_cursor.execute("SHOW DATABASES")
print(my_cursor.fetchall())
