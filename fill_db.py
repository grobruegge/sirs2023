import os, hashlib, base64, datetime
from . import db, app, models

def fill_database():

    ##########################
    # RESTAURANTS AND TABLES #
    ##########################

    restaurants_example_1 = models.RestaurantModel(
        name='Pizza Hut',
        category='Pizza',
        location='Lisbon',
        description='Delicious Pizza of all kinds. Nothing which we cannot server you.'
    )
    table_ex_1 = models.TableModel(
        size=2,
        restaurant=restaurants_example_1,
    )    
    table_ex_2 = models.TableModel(
        size=2,
        restaurant=restaurants_example_1,
    )
    table_ex_3 = models.TableModel(
        size=5,
        restaurant=restaurants_example_1,
    )
    table_ex_4 = models.TableModel(
        size=6,
        restaurant=restaurants_example_1,
    )

    restaurants_example_2 = models.RestaurantModel(
        name='Burger Place',
        category='Burger',
        location='Lisbon',
        description='The best burgers in town! No scam. Just burgers. For sure.'
    )

    table_ex_5 = models.TableModel(
        size=2,
        restaurant=restaurants_example_2,
    )    
    table_ex_6 = models.TableModel(
        size=2,
        restaurant=restaurants_example_2,
    )
    table_ex_7 = models.TableModel(
        size=5,
        restaurant=restaurants_example_2,
    )
    table_ex_8 = models.TableModel(
        size=6,
        restaurant=restaurants_example_2,
    )

    restaurants_example_3 = models.RestaurantModel(
        name='Sushi Palace',
        category='Burger',
        location='Porto',
        description='A wide offer of all kinds of Sushi. Many vegetarian options available'
    )

    table_ex_9 = models.TableModel(
        size=2,
        restaurant=restaurants_example_3,
    )    
    table_ex_10 = models.TableModel(
        size=2,
        restaurant=restaurants_example_3,
    )
    table_ex_11 = models.TableModel(
        size=5,
        restaurant=restaurants_example_3,
    )
    table_ex_12 = models.TableModel(
        size=6,
        restaurant=restaurants_example_3,
    )

    restaurants_example_4 = models.RestaurantModel(
        name='Gourmet Corner',
        category='Traiditional french food',
        location='Porto',
        description='We have everything you can possible desire!'
    )

    table_ex_13 = models.TableModel(
        size=10,
        restaurant=restaurants_example_4,
    )
    table_ex_14 = models.TableModel(
        size=12,
        restaurant=restaurants_example_4,
    )

    restaurants_example_5 = models.RestaurantModel(
        name='Sample Story',
        category='Samples',
        location='Porto',
        description='We offer samples of all kind. We are ourself an example, so we should know!'
    )

    table_ex_14 = models.TableModel(
        size=4,
        restaurant=restaurants_example_5,
    )

    #########
    # USERS #
    #########

    salt1 = os.urandom(8)

    pwd_digest1 = hashlib.pbkdf2_hmac(
        hash_name='sha256', 
        password="pwd".encode(),
        salt=salt1,
        iterations=1000,
    )

    # Add examples to the database
    new_user1 = models.UserModel(
        username="arne", 
        password=base64.b64encode(hashlib.sha256(pwd_digest1).digest()).decode('utf-8'),
        salt=base64.b64encode(salt1).decode('utf-8')
    )

    salt2 = os.urandom(8)

    pwd_digest2 = hashlib.pbkdf2_hmac(
        hash_name='sha256', 
        password="pwd".encode(),
        salt=salt2,
        iterations=1000,
    )

    # Add examples to the database
    new_user2 = models.UserModel(
        username="restaurant", 
        password=base64.b64encode(hashlib.sha256(pwd_digest2).digest()).decode('utf-8'),
        salt=base64.b64encode(salt2).decode('utf-8'),
        restaurant=restaurants_example_1,
    )

    ############
    # BOOKINGS #
    ############

    booking_ex_1 = models.BookingModel(
        date=datetime.datetime.strptime("2023-01-10", "%Y-%m-%d"),
        table=table_ex_1,
        user=new_user1,
    )

    booking_ex_2 = models.BookingModel(
        date=datetime.datetime.strptime("2023-01-12", "%Y-%m-%d"),
        table=table_ex_10,
        user=new_user1,
    )


    #print(f'Restaurant: {table_ex_2.restaurant.name}')
    #print(f'Table from Restaurant: {restaurants_example_2.tables}')
    #print(f'Table Size: {table_ex_2.size}')

    with app.app_context():
        db.session.add(new_user1)
        db.session.add(new_user2)

        db.session.add(booking_ex_1)
        db.session.add(booking_ex_2)

        db.session.add(restaurants_example_1)
        db.session.add(restaurants_example_2)
        db.session.add(restaurants_example_3)
        db.session.add(restaurants_example_4)
        db.session.add(restaurants_example_5)

        db.session.add(table_ex_1)
        db.session.add(table_ex_2)
        db.session.add(table_ex_3)
        db.session.add(table_ex_4)
        db.session.add(table_ex_5)
        db.session.add(table_ex_6)
        db.session.add(table_ex_7)
        db.session.add(table_ex_8)
        db.session.add(table_ex_9)
        db.session.add(table_ex_10)
        db.session.add(table_ex_11)
        db.session.add(table_ex_12)
        db.session.add(table_ex_13)
        db.session.add(table_ex_14)

        db.session.commit()
