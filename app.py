import hashlib
import os
import base64
import pyotp
from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import UserMixin
from datetime import datetime, timedelta

# Инициализация базовых объектов
db = SQLAlchemy()
bcrypt = Bcrypt()


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    salt = db.Column(db.String(64), nullable=False)
    otp_secret = db.Column(db.String(32), nullable=True)
    is_2fa_enabled = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        # Генерация соли
        self.salt = base64.b64encode(os.urandom(32)).decode('utf-8')

        # Хэширование пароля с солью
        password_hash = hashlib.sha256((password + self.salt).encode()).hexdigest()
        self.password_hash = password_hash

    def check_password(self, password):
        # Проверка пароля с использованием соли
        password_hash = hashlib.sha256((password + self.salt).encode()).hexdigest()
        return self.password_hash == password_hash

    def enable_2fa(self):
        # Генерация секретного ключа для TOTP
        self.otp_secret = pyotp.random_base32()
        self.is_2fa_enabled = True
        return self.otp_secret

    def get_totp_uri(self):
        # Получение URI для QR-кода
        return pyotp.totp.TOTP(self.otp_secret).provisioning_uri(
            name=self.username,
            issuer_name="Restaurant Booking App"
        )

    def verify_totp(self, token):
        # Проверка TOTP кода
        totp = pyotp.TOTP(self.otp_secret)
        return totp.verify(token)


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


# Настройка приложения Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

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
            if user.is_2fa_enabled:
                # Если включена 2FA, сохраняем ID пользователя в сессии и перенаправляем на страницу 2FA
                session['user_id_for_2fa'] = user.id
                return redirect(url_for('verify_2fa'))
            else:
                # Если 2FA не включена, сразу авторизуем пользователя
                login_user(user)
                return redirect(url_for('index'))
        else:
            flash('Неверное имя пользователя или пароль', 'error')

    return render_template('login.html')


@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    # Проверяем, что пользователь прошел первый этап аутентификации
    if 'user_id_for_2fa' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id_for_2fa']
    user = User.query.get(user_id)

    if not user:
        session.pop('user_id_for_2fa', None)
        return redirect(url_for('login'))

    if request.method == 'POST':
        otp_code = request.form.get('otp_code')

        if user.verify_totp(otp_code):
            # Код верный, авторизуем пользователя
            login_user(user)
            session.pop('user_id_for_2fa', None)
            flash('Вы успешно вошли!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Неверный код аутентификации', 'error')

    return render_template('verify_2fa.html')


@app.route('/setup-2fa', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    if request.method == 'POST':
        otp_code = request.form.get('otp_code')

        # Проверяем правильность введенного кода
        if current_user.verify_totp(otp_code):
            flash('Двухфакторная аутентификация успешно настроена!', 'success')
            return redirect(url_for('profile'))
        else:
            flash('Неверный код подтверждения', 'error')

    # Если 2FA еще не настроена, генерируем секретный ключ
    if not current_user.is_2fa_enabled:
        secret = current_user.enable_2fa()
        db.session.commit()

        # Создаем QR-код и URI для настройки приложения
        totp_uri = current_user.get_totp_uri()

        return render_template('setup_2fa.html', secret=secret, totp_uri=totp_uri)

    return render_template('setup_2fa.html')


@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')


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
    with app.app_context():
        db.create_all()

        # Создаем тестового пользователя, если его нет
        if not User.query.filter_by(username="admin").first():
            admin = User(username="admin")
            admin.set_password("password")
            db.session.add(admin)
            db.session.commit()

        # Создаем тестовые столики, если их нет
        if not RestaurantTable.query.first():
            tables = [
                RestaurantTable(table_number=1, capacity=2),
                RestaurantTable(table_number=2, capacity=4),
                RestaurantTable(table_number=3, capacity=6),
            ]
            db.session.add_all(tables)
            db.session.commit()

    app.run(debug=True)