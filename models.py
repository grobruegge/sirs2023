from . import db
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from sqlalchemy import false
import os

class RestaurantModel(db.Model):
    __tablename__ = 'restaurants'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    location = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())
    description = db.Column(db.String(500), nullable=True)

    def __repr__(self):
        return f"Restaurant<{self.id}>(name = {self.name}, \
            category = {self.category}, \
            location = {self.location}) created at {self.created_at}"

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'category': self.category,
            'location': self.location,
            'description': self.description,
        }

class TableModel(db.Model):
    __tablename__ = 'tables'
    id = db.Column(db.Integer, primary_key=True)
    restaurant_id = db.Column(db.Integer, db.ForeignKey('restaurants.id'), nullable=False)
    restaurant = relationship('RestaurantModel', backref='tables')
    size = db.Column(db.Integer)
    #nextto_window = db.Column(db.Boolean)
    
    def __repr__(self):
        return f"Table<{self.id}>(size={self.size},restaurant={self.restaurant.name}"

    def to_dict(self):
        return {
            'id': self.id,
            'restaurant_id': self.restaurant_id,
            'size': self.size
        }

class BookingModel(db.Model):
    __tablename__ = 'bookings'
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime) # only bookable once a day
    table_id = db.Column(db.Integer, db.ForeignKey('tables.id'))
    table = relationship('TableModel', backref='bookings')
    user_id =  db.Column(db.Integer, db.ForeignKey('users.id'))
    user = relationship('UserModel', backref='bookings')
    status = db.Column(db.String(20), default="pendning")


class UserModel(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    salt = db.Column(db.String(100), nullable=False)
    restaurant_id = db.Column(db.Integer, db.ForeignKey('restaurants.id'))
    restaurant = relationship('RestaurantModel', backref='users')

    def __repr__(self):
        return f"User(id={self.id}, username={self.username}, password={self.password})"

class SessionModel(db.Model):
    __tablename__ = 'sessions'
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.Text(), unique=True)
    challenge = db.Column(db.Text())
    #username = db.Column(db.String(100)) 
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    user = relationship('UserModel', backref='sessions')

    def __init__(self, username=None, challenge=""):
        self.token = os.urandom(64).hex()
        self.challenge = challenge
        self.username = username

    def __repr__(self):
        return '<Session(id=%s, token=%s, challenge=%s, user=%s)>' % (self.id, self.token, self.challenge, self.username)

