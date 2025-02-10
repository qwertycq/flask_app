from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class RestaurantTable(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    table_number = db.Column(db.Integer, unique=True, nullable=False)
    capacity = db.Column(db.Integer, nullable=False)

class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    guest_name = db.Column(db.String(100), nullable=False)
    guest_phone = db.Column(db.String(20), nullable=False)
    table_id = db.Column(db.Integer, db.ForeignKey('restaurant_table.id'), nullable=False)
    booking_time = db.Column(db.DateTime, nullable=False)

    table = db.relationship('RestaurantTable', backref='bookings')