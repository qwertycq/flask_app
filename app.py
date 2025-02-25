from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from datetime import datetime, timedelta
from models import db, User, RestaurantTable, Booking, bcrypt
from config import Config

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
bcrypt.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            flash('Вы успешно вошли!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Неверное имя пользователя или пароль', 'error')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы вышли из системы.', 'success')
    return redirect(url_for('index'))

@app.route('/book', methods=['GET', 'POST'])
@login_required
def book_table():
    if request.method == 'POST':
        guest_name = request.form['guest_name']
        guest_phone = request.form['guest_phone']
        table_id = request.form['table_id']
        booking_time = datetime.strptime(request.form['booking_time'], '%Y-%m-%dT%H:%M')

        existing_booking = Booking.query.filter(
            Booking.table_id == table_id,
            Booking.booking_time.between(booking_time - timedelta(hours=2), booking_time + timedelta(hours=2))
        ).first()

        if existing_booking:
            flash('Этот столик уже забронирован.', 'error')
        else:
            new_booking = Booking(
                guest_name=guest_name,
                guest_phone=guest_phone,
                table_id=table_id,
                booking_time=booking_time
            )
            db.session.add(new_booking)
            db.session.commit()
            flash('Столик забронирован!', 'success')
            return redirect(url_for('view_bookings'))

    tables = RestaurantTable.query.all()
    return render_template('book.html', tables=tables)

@app.route('/bookings')
@login_required
def view_bookings():
    bookings = Booking.query.all()
    return render_template('bookings.html', bookings=bookings)

@app.route('/cancel_booking/<int:booking_id>', methods=['POST'])
@login_required
def cancel_booking(booking_id):
    booking = Booking.query.get_or_404(booking_id)
    db.session.delete(booking)
    db.session.commit()
    flash('Бронирование отменено.', 'success')
    return redirect(url_for('view_bookings'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
