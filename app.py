from flask import Flask, render_template, request, redirect, url_for, flash
from datetime import datetime, timedelta
from models import db, RestaurantTable, Booking

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'supersecretkey'  # Для использования flash-сообщений

db.init_app(app)

# Создание таблиц в базе данных
with app.app_context():
    db.create_all()

# Главная страница
@app.route('/')
def index():
    return render_template('index.html')

# Страница бронирования столика
@app.route('/book', methods=['GET', 'POST'])
def book_table():
    if request.method == 'POST':
        guest_name = request.form['guest_name']
        guest_phone = request.form['guest_phone']
        table_id = request.form['table_id']
        booking_time = datetime.strptime(request.form['booking_time'], '%Y-%m-%dT%H:%M')

        # Проверка, свободен ли столик на указанное время
        existing_booking = Booking.query.filter(
            Booking.table_id == table_id,
            Booking.booking_time.between(booking_time - timedelta(hours=2), booking_time + timedelta(hours=2))
        ).first()

        if existing_booking:
            flash('Этот столик уже забронирован на указанное время.', 'error')
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

# Просмотр всех бронирований
@app.route('/bookings')
def view_bookings():
    bookings = Booking.query.all()
    return render_template('bookings.html', bookings=bookings)

# Отмена бронирования
@app.route('/cancel/<int:booking_id>')
def cancel_booking(booking_id):
    booking = Booking.query.get_or_404(booking_id)
    db.session.delete(booking)
    db.session.commit()
    flash('Бронирование успешно отменено.', 'success')
    return redirect(url_for('view_bookings'))

if __name__ == '__main__':
    app.run(debug=True)