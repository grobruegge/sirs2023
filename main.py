from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_restful import Resource, reqparse
from .models import RestaurantModel, BookingModel, TableModel
from .auth import get_current_session, login_required
from . import db, api, basedir
import datetime, requests, os

main = Blueprint('main', __name__)

@main.route('/error')
def error():
    return render_template('error.html', status_code = request.args.get("status_code"), error=request.args.get("error"))

class RestaurantRessource(Resource):
    def __init__(self):
        self.parser = {
            'get' : reqparse.RequestParser(),
        }
        self.init_parser()

    def init_parser(self):
        self.parser['get'].add_argument('id', help='ID', type=str)
        self.parser['get'].add_argument('name', help='Name', type=str)
        self.parser['get'].add_argument('location', help='Location', type=str)
        self.parser['get'].add_argument('category', help='Category', type=str)

    def get(self):
        args = self.parser['get'].parse_args(strict=True)

        # Create a new dictionary with only the non-None values
        kwargs = {k: v for k, v in args.items() if v is not None}

        restaurants = RestaurantModel.query.filter_by(**kwargs).all()

        if not restaurants:
            return {"message": "No restaurants match these filter settings"}, 404

        return [restaurant.to_dict() for restaurant in restaurants]

api.add_resource(RestaurantRessource, '/api/restaurants')

def validate_date(date: str) -> datetime.date:
    if date is None:
        return datetime.datetime.now().date()
    else:
        try:
            return datetime.datetime.strptime(date, '%Y-%m-%d')
        except ValueError:
            raise ValueError("Incorrect date format, should be YYYY-MM-DD")

def get_free_tableIDs(date: datetime.date) -> list:
    # Get all the bookings on that date
    bookings = BookingModel.query.filter_by(date=date).all()

    # Query the database for all tables that are not booked on the specified date
    freeTables = TableModel.query.filter(~TableModel.id.in_([booking.table_id for booking in bookings])).all()

    return [table.id for table in freeTables]

class BookingRessource(Resource):
    def __init__(self):
        self.parser = {
            'get' : reqparse.RequestParser(),
            'post': reqparse.RequestParser(),
            'put': reqparse.RequestParser(),
        }
        self.init_parser()

    def init_parser(self):
        self.parser['get'].add_argument('restaurantID', required=True, help='RestaurantID', type=int)
        self.parser['get'].add_argument('date', help='Please provide a date in this format: YYYY-MM-DD', type=str)
        self.parser['post'].add_argument('date', help='Please provide a date in this format: YYYY-MM-DD', type=str)
        self.parser['post'].add_argument('tableID', help='Table-ID of the reservation', type=int)
        self.parser['put'].add_argument('bookingID', help='Booking-ID', type=int)
        self.parser['put'].add_argument('updatedStatus', help='New Status of the booking', type=str)

    def get(self): # get all free tables
        args = self.parser['get'].parse_args(strict=True)

        restaurants = RestaurantModel.query.filter_by(id=args["restaurantID"]).all()

        if not restaurants:
            return {"error": "No restaurant matches this ID"}, 404

        date = validate_date(args["date"])
    
        #bookings = BookingModel.query.join(TableModel).filter(BookingModel.date==date).all()
    
        # Get the IDs of all the tables that are booked on the specified date
        #booked_table_ids = [booking.table_id for booking in bookings]

        # Query the database for all tables that are not booked on the specified date
        #tables = TableModel.query.filter(~TableModel.id.in_(booked_table_ids), TableModel.restaurant_id.like(args["restaurantID"])).all()
        tables = TableModel.query.filter(TableModel.id.in_(get_free_tableIDs(date)), TableModel.restaurant_id.like(args["restaurantID"])).all()

        return [table.to_dict() for table in tables], 200

    #@login_required
    def post(self): # Add new booking
        args = self.parser['post'].parse_args(strict=True)

        current_session = get_current_session()

        if current_session.user is None:
            return {"error": "Unauthorized access"}, 401

        table = TableModel.query.filter_by(id=args["tableID"]).first()

        if not table:
            return {"error": "Table unknown"}, 404

        date = validate_date(args["date"])

        if table.id not in get_free_tableIDs(date):
            return {"error": "Table not available"}, 404

        db.session.add(
            BookingModel(
                date=date,
                table=table,
                user=current_session.user, 
            )
        )
        db.session.commit()

        return {"message": "Booking successful"}, 201

    #@login_required
    #@restaurant_required
    def put(self): # Update Booking status
        args = self.parser['put'].parse_args(strict=True)

        current_session = get_current_session()

        if current_session.user is None:
            return {"error": "Unauthorized access"}, 401

        if current_session.user.restaurant is None:
            return {"error": "Unauthorized access"}, 401

        if args["updatedStatus"] not in ("confirmed", "declined"):
            return {"error": "Status unknown"}, 404

        booking = BookingModel.query.filter_by(id=args["bookingID"]).first()

        if not booking:
            return {"error": "Booking unknown"}, 404
        
        booking.status = args["updatedStatus"]
        db.session.commit()

        return {"message": "Booking status updated successfully"}, 200

    #@login_required
    def delete(self): # Update Booking status
        args = self.parser['put'].parse_args(strict=True)

        current_session = get_current_session()

        if current_session.user is None:
            return {"error": "Unauthorized access"}, 401

        booking = BookingModel.query.filter_by(id=args["bookingID"]).first()

        if not booking:
            return {"error": "Booking unknown"}, 404
        
        if booking.user != current_session.user:
            return {"error": "This action exeeds your priveleges"}, 404

        db.session.delete(booking)
        db.session.commit()

        return {"message": "Booking deleted successfully"}, 204

api.add_resource(BookingRessource, '/api/bookings')

@main.route('/')
def index():
    location = request.args.get('location')
    if location:
        restaurants = RestaurantModel.query.filter_by(location=location).all()
    else:
        restaurants = RestaurantModel.query.all()
    return render_template('index.html', restaurants=restaurants)


@main.route('/<int:restaurant_id>/')
def show_restaurant(restaurant_id):
    restaurant = RestaurantModel.query.filter_by(id=restaurant_id).first()

    date = request.args.get('date')

    if not date:
        date = datetime.datetime.now().strftime('%Y-%m-%d')

    get_response = requests.get(
        url=request.url_root+'api/bookings',
        json={
            "restaurantID": restaurant.id,
            "date": date,
        },
        cookies=request.cookies,
        verify=os.path.join(basedir, 'certificates', 'cert1.pem'),
    )

    if get_response.status_code != 200:
        return render_template('error.html', status_code=get_response.status_code, error=get_response.json().get("error", get_response.json().get("syserror"))), 500

    tables = TableModel.query.filter(TableModel.id.in_([available_tables["id"] for available_tables in get_response.json()])).all()

    return render_template('restaurant.html', restaurant=restaurant, tables=tables, date=date)

@main.route('/<int:restaurant_id>/', methods=['POST'])
@login_required
def book_table(restaurant_id):
    tableID = request.form.get('table_id')
    date = request.form.get('date')

    post_response = requests.post(
        url=request.url_root+'api/bookings',
        json={
            "tableID": tableID,
            "date": date,
        },
        cookies=request.cookies,
        verify=os.path.join(basedir, 'certificates', 'cert1.pem'),
    )

    if post_response.status_code != 201:
        return render_template('error.html', status_code=post_response.status_code, error=post_response.json().get("error", post_response.json().get("syserror"))), 500

    return redirect(url_for('main.index'))

@main.route('/manage')
@login_required
def show_bookings():
    current_session = get_current_session()
    #user = UserModel.query.filter_by(username=current_session.username).first()

    if current_session.user.restaurant != None:
        bookings = (
            BookingModel.query
                .join(TableModel)
                .filter(TableModel.restaurant == current_session.user.restaurant)
                .order_by(BookingModel.date)
                .all()
        )
        
        return render_template('bookings_restaurants.html', bookings=bookings)
    else:
        bookings = (
            BookingModel.query
                .join(TableModel)
                .filter(BookingModel.user == current_session.user)
                .order_by(BookingModel.date)
                .all()
        )
        
        return render_template('bookings_users.html', bookings=bookings)

@main.route('/manage', methods=['POST'])
@login_required
def update_booking():
    method = request.form['_method']
    bookingID = request.form['booking_id']

    if method == 'post':
        updatedStatus = request.form['updated_status']

        put_response = requests.put(
            url=request.url_root+'api/bookings',
            json={
                "bookingID": bookingID,
                "updatedStatus": updatedStatus,
            },
            cookies=request.cookies,
            verify=os.path.join(basedir, 'certificates', 'cert1.pem'),
        )

        if put_response.status_code != 200:
            return render_template('error.html', status_code=put_response.status_code, error=put_response.json().get("error", put_response.json().get("syserror"))), 500

        flash(f"Status of Booking {bookingID} successfully changed to {updatedStatus}")

    elif method == 'delete':
        put_response = requests.delete(
            url=request.url_root+'api/bookings',
            json={
                "bookingID": bookingID,
            },
            cookies=request.cookies,
            verify=os.path.join(basedir, 'certificates', 'cert1.pem'),
        )

        if put_response.status_code != 204:
            return render_template('error.html', status_code=put_response.status_code, error=put_response.json().get("error", put_response.json().get("syserror"))), 500

        flash(f"Booking deleted successfully")

    return redirect('/manage')