from flask import Flask, render_template, redirect, url_for, flash, request
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from datetime import datetime
from models import db, bcrypt, User, RestaurantTable, Booking
from config import Config

# Инициализация Flask-приложения
app = Flask(__name__)
app.config.from_object(Config)

# Инициализация расширений
db.init_app(app)
bcrypt.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Неверное имя пользователя или пароль', 'error')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/book', methods=['GET', 'POST'])
@login_required
def book_table():
    if request.method == 'POST':
        guest_name = request.form.get('guest_name')
        guest_phone = request.form.get('guest_phone')
        table_id = request.form.get('table_id')
        booking_time_str = request.form.get('booking_time')

        booking_time = datetime.strptime(booking_time_str, '%Y-%m-%dT%H:%M')

        # Проверка, что столик свободен в указанное время
        existing_booking = Booking.query.filter_by(
            table_id=table_id,
            booking_time=booking_time
        ).first()

        if existing_booking:
            flash('Столик уже забронирован на это время', 'error')
        else:
            new_booking = Booking(
                guest_name=guest_name,
                guest_phone=guest_phone,
                table_id=table_id,
                booking_time=booking_time
            )
            db.session.add(new_booking)
            db.session.commit()
            flash('Столик успешно забронирован!', 'success')
            return redirect(url_for('view_bookings'))

    tables = RestaurantTable.query.all()
    return render_template('book.html', tables=tables)


@app.route('/bookings')
@login_required
def view_bookings():
    bookings = Booking.query.order_by(Booking.booking_time).all()
    return render_template('bookings.html', bookings=bookings)


@app.route('/cancel/<int:booking_id>', methods=['POST'])
@login_required
def cancel_booking(booking_id):
    booking = Booking.query.get_or_404(booking_id)
    db.session.delete(booking)
    db.session.commit()
    flash('Бронирование отменено', 'success')
    return redirect(url_for('view_bookings'))


if __name__ == '__main__':
    app.run(debug=True)