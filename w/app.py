import os
from flask import Flask, render_template, flash, redirect, url_for, request, abort, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user, login_required
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField, FloatField, IntegerField, \
    SelectField
from wtforms.validators import DataRequired, ValidationError, Email, EqualTo, Length
from datetime import datetime
from config import Config
from PIL import Image
import io


app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
login = LoginManager(app)
login.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    products = db.relationship('Product', backref='author', lazy='dynamic')
    reviews = db.relationship('Review', backref='author', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(140))
    description = db.Column(db.Text)
    price = db.Column(db.Float)
    image = db.Column(db.String(200))
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    category = db.Column(db.String(50))
    reviews = db.relationship('Review', backref='product', lazy='dynamic')


class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text)
    rating = db.Column(db.Integer)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))


@login.user_loader
def load_user(id):
    return User.query.get(int(id))


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    remember_me = BooleanField('Запомнить меня')
    submit = SubmitField('Войти')


class RegistrationForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    password2 = PasswordField(
        'Повторите пароль', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Зарегистрироваться')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Пожалуйста, используйте другое имя пользователя.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Пожалуйста, используйте другой email.')


class ProductForm(FlaskForm):
    title = StringField('Название', validators=[DataRequired(), Length(max=140)])
    description = TextAreaField('Описание', validators=[DataRequired()])
    price = FloatField('Цена (руб)', validators=[DataRequired()])
    image = FileField('Фото товара', validators=[
        FileAllowed(['jpg', 'jpeg', 'png'], 'Только изображения!')
    ])
    category = SelectField('Категория', choices=[
        ('electronics', 'Электроника'),
        ('furniture', 'Мебель'),
        ('clothing', 'Одежда'),
        ('books', 'Книги'),
        ('other', 'Другое')
    ], validators=[DataRequired()])
    submit = SubmitField('Добавить товар')


class ReviewForm(FlaskForm):
    text = TextAreaField('Отзыв', validators=[DataRequired()])
    rating = IntegerField('Оценка (1-5)', validators=[DataRequired()])
    submit = SubmitField('Оставить отзыв')


@app.route('/edit_product/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_product(id):
    product = Product.query.get_or_404(id)
    if product.author != current_user:
        abort(403)

    form = ProductForm()
    if form.validate_on_submit():
        # Обработка загрузки нового изображения
        if form.image.data:
            # Удаляем старое изображение, если оно есть
            if product.image:
                try:
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], product.image))
                except OSError:
                    pass

            # Сохраняем новое изображение с обработкой
            image = form.image.data
            filename = secure_filename(image.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            # Открываем изображение с помощью Pillow
            img = Image.open(image)

            # Создаем миниатюру (опционально)
            img.thumbnail((800, 800))

            # Сохраняем в формате JPEG с оптимальным качеством
            if filename.lower().endswith(('.png', '.jpeg', '.jpg')):
                img.save(image_path, optimize=True, quality=85)
            else:
                img.save(image_path + '.jpg', 'JPEG', optimize=True, quality=85)
                filename = filename + '.jpg'

            product.image = filename

        # Обновляем данные товара
        product.title = form.title.data
        product.description = form.description.data
        product.price = form.price.data
        product.category = form.category.data

        db.session.commit()
        flash('Товар успешно обновлен!')
        return redirect(url_for('product', id=product.id))

    elif request.method == 'GET':
        # Заполняем форму текущими данными
        form.title.data = product.title
        form.description.data = product.description
        form.price.data = product.price
        form.category.data = product.category

    return render_template('edit_product.html', title='Редактировать товар', form=form, product=product)


@app.route('/')
@app.route('/index')
def index():
    products = Product.query.order_by(Product.timestamp.desc()).limit(4).all()
    return render_template('index.html', title='Главная', products=products)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Неверный email или пароль')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page:
            next_page = url_for('index')
        return redirect(next_page)
    return render_template('login.html', title='Вход', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Поздравляем, вы зарегистрированы!')
        return redirect(url_for('login'))
    return render_template('register.html', title='Регистрация', form=form)


@app.route('/products')
def products():
    page = request.args.get('page', 1, type=int)
    products = Product.query.order_by(Product.timestamp.desc()).paginate(
        page=page, per_page=10, error_out=False)
    next_url = url_for('products', page=products.next_num) \
        if products.has_next else None
    prev_url = url_for('products', page=products.prev_num) \
        if products.has_prev else None
    return render_template('products.html', title='Товары',
                           products=products.items, next_url=next_url,
                           prev_url=prev_url)


@app.route('/product/<int:id>', methods=['GET', 'POST'])
def product(id):
    product = Product.query.get_or_404(id)
    form = ReviewForm()
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        review = Review(text=form.text.data, rating=form.rating.data,
                        author=current_user, product=product)
        db.session.add(review)
        db.session.commit()
        flash('Ваш отзыв добавлен!')
        return redirect(url_for('product', id=id))
    reviews = product.reviews.order_by(Review.timestamp.desc()).all()
    return render_template('product.html', product=product, form=form,
                           reviews=reviews, author_email=product.author.email)


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/add_product', methods=['GET', 'POST'])
@login_required
def add_product():
    form = ProductForm()
    if form.validate_on_submit():
        image_filename = None
        if form.image.data:
            image = form.image.data
            filename = secure_filename(image.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            # Обработка изображения
            try:
                img = Image.open(image)

                # Проверка и коррекция ориентации (для фото с телефонов)
                if hasattr(img, '_getexif'):
                    exif = img._getexif()
                    if exif:
                        orientation = exif.get(0x0112)
                        if orientation == 3:
                            img = img.rotate(180, expand=True)
                        elif orientation == 6:
                            img = img.rotate(270, expand=True)
                        elif orientation == 8:
                            img = img.rotate(90, expand=True)

                # Ресайз если изображение слишком большое
                if img.size[0] > app.config['IMAGE_SIZE_LIMIT'][0] or img.size[1] > app.config['IMAGE_SIZE_LIMIT'][1]:
                    img.thumbnail(app.config['IMAGE_SIZE_LIMIT'])

                # Конвертация в JPEG если это не JPEG
                if not filename.lower().endswith(('.jpg', '.jpeg')):
                    filename = os.path.splitext(filename)[0] + '.jpg'
                    image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

                # Сохранение с оптимальным качеством
                img.save(image_path, 'JPEG', quality=85, optimize=True)
                image_filename = filename
            except Exception as e:
                flash('Ошибка при обработке изображения: ' + str(e))
                return redirect(url_for('add_product'))

        product = Product(
            title=form.title.data,
            description=form.description.data,
            price=form.price.data,
            image=image_filename,
            category=form.category.data,
            author=current_user
        )
        db.session.add(product)
        db.session.commit()
        flash('Ваш товар добавлен!')
        return redirect(url_for('product', id=product.id))
    return render_template('add_product.html', title='Добавить товар', form=form)


@app.route('/delete_product/<int:id>', methods=['POST'])
@login_required
def delete_product(id):
    product = Product.query.get_or_404(id)
    if product.author != current_user:
        abort(403)

    # Удаляем изображение товара, если оно есть
    if product.image:
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], product.image))
        except OSError:
            pass

    db.session.delete(product)
    db.session.commit()
    flash('Товар удален!')
    return redirect(url_for('products'))


@app.route('/profile/<username>')
@login_required
def profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    products = user.products.order_by(Product.timestamp.desc()).all()
    return render_template('profile.html', user=user, products=products)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
