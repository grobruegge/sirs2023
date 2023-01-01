from flask import Blueprint, render_template, request, redirect, url_for
from flask_restful import Resource, reqparse
from .models import RestaurantModel, BookingModel, TableModel, UserModel
from .auth import get_current_session, login_required
from . import db, api
import datetime, requests

main = Blueprint('main', __name__)

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
            #return {"error": "Incorrect date format, should be YYYY-MM-DD"}, 400

def get_free_tableIDs(date: datetime.date) -> list[int]:
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
        }
        self.init_parser()

    def init_parser(self):
        self.parser['get'].add_argument('restaurantID', required=True, help='RestaurantID', type=int)
        self.parser['get'].add_argument('date', help='Please provide a date in this format: YYYY-MM-DD', type=str)
        self.parser['post'].add_argument('date', help='Please provide a date in this format: YYYY-MM-DD', type=str)
        self.parser['post'].add_argument('tableID', help='Table-ID of the reservation', type=int)

    def get(self):
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

    @login_required
    def post(self):
        args = self.parser['post'].parse_args(strict=True)

        current_session = get_current_session()
        temp = 'arne'
        user = UserModel.query.filter_by(username=temp).first()

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
                user=user, 
            )
        )
        db.session.commit()

        return {"message": "Booking successful"}, 201

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
    #else:
    #    try:
    #        date = datetime.datetime.strptime(date, '%Y-%m-%d')
    #    except Exception:
    #        abort(500, "Please provide the date in the right format")

    #bookings = BookingModel.query.join(TableModel).filter_by(date == date).all()
    
    # Get the IDs of all the tables that are booked on the specified date
    #booked_table_ids = [booking.table_id for booking in bookings]

    # Query the database for all tables that are not booked on the specified date
    #tables = TableModel.query.filter(~TableModel.id.in_(booked_table_ids), TableModel.restaurant_id.like(restaurant.id)).all()

    get_response = requests.get(
        url=request.url_root+'api/bookings',
        json={
            "restaurantID": restaurant.id,
            "date": date,
        },
        cookies=request.cookies
    )

    if get_response.status_code != 200:
        return render_template('error.html', status_code=get_response.status_code, error=get_response.json()["error"]), 500

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
        cookies=request.cookies
    )

    if post_response.status_code != 201:
        return render_template('error.html', status_code=post_response.status_code, error=post_response.json()["error"]), 500

    return redirect(url_for('main.index'))

@main.route('/create/', methods=('GET', 'POST'))
def create():
    if request.method == 'POST':
        name = request.form['name']
        category = request.form['category']
        address = request.form['address']
        description = request.form['description']
        restaurant = RestaurantModel(name=name,
                            category=category,
                            address=address,
                            description=description)
        db.session.add(restaurant)
        db.session.commit()
    return render_template('create.html')
