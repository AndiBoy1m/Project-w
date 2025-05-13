from flask import Flask, render_template, flash, redirect, url_for, request, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user, login_required
from flask_wtf import FlaskForm
from flask_bootstrap import Bootstrap
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField, FloatField, IntegerField, SelectField
from wtforms.validators import DataRequired, ValidationError, Email, EqualTo, Length
from datetime import datetime
import os

# Настройка приложения
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Инициализация расширений
db = SQLAlchemy(app)
login = LoginManager(app)
login.login_view = 'login'
bootstrap = Bootstrap(app)

# Модели данных
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

    def __repr__(self):
        return f'<User {self.username}>'

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(140))
    description = db.Column(db.Text)
    price = db.Column(db.Float)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    category = db.Column(db.String(50))
    reviews = db.relationship('Review', backref='product', lazy='dynamic')

    def __repr__(self):
        return f'<Product {self.title}>'

    def to_dict(self):
        data = {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'price': self.price,
            'timestamp': self.timestamp.isoformat() + 'Z',
            'user_id': self.user_id,
            'category': self.category,
            '_links': {
                'self': url_for('get_product', id=self.id),
                'author': url_for('get_user', id=self.user_id)
            }
        }
        return data

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text)
    rating = db.Column(db.Integer)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))

    def __repr__(self):
        return f'<Review {self.text[:20]}>'

@login.user_loader
def load_user(id):
    return User.query.get(int(id))

# Формы
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField(
        'Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')

class ProductForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=140)])
    description = TextAreaField('Description', validators=[DataRequired()])
    price = FloatField('Price', validators=[DataRequired()])
    category = SelectField('Category', choices=[
        ('electronics', 'Electronics'),
        ('furniture', 'Furniture'),
        ('clothing', 'Clothing'),
        ('books', 'Books'),
        ('other', 'Other')
    ], validators=[DataRequired()])
    submit = SubmitField('Submit')

class ReviewForm(FlaskForm):
    text = TextAreaField('Review', validators=[DataRequired()])
    rating = IntegerField('Rating (1-5)', validators=[DataRequired()])
    submit = SubmitField('Submit')

# Обработчики маршрутов
@app.route('/')
@app.route('/index')
def index():
    products = Product.query.order_by(Product.timestamp.desc()).limit(4).all()
    return render_template('index.html', title='Home', products=products)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page:
            next_page = url_for('index')
        return redirect(next_page)
    return render_template('login.html', title='Sign In', form=form)

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
        flash('Congratulations, you are now a registered user!')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/products')
def products():
    page = request.args.get('page', 1, type=int)
    products = Product.query.order_by(Product.timestamp.desc()).paginate(
        page=page, per_page=10, error_out=False)
    next_url = url_for('products', page=products.next_num) \
        if products.has_next else None
    prev_url = url_for('products', page=products.prev_num) \
        if products.has_prev else None
    return render_template('products.html', title='Products',
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
        flash('Your review has been added!')
        return redirect(url_for('product', id=id))
    reviews = product.reviews.order_by(Review.timestamp.desc()).all()
    return render_template('product.html', product=product, form=form,
                         reviews=reviews)

@app.route('/add_product', methods=['GET', 'POST'])
@login_required
def add_product():
    form = ProductForm()
    if form.validate_on_submit():
        product = Product(title=form.title.data, description=form.description.data,
                         price=form.price.data, category=form.category.data,
                         author=current_user)
        db.session.add(product)
        db.session.commit()
        flash('Your product has been added!')
        return redirect(url_for('product', id=product.id))
    return render_template('add_product.html', title='Add Product', form=form)

@app.route('/delete_product/<int:id>', methods=['POST'])
@login_required
def delete_product(id):
    product = Product.query.get_or_404(id)
    if product.author != current_user:
        abort(403)
    db.session.delete(product)
    db.session.commit()
    flash('Your product has been deleted!')
    return redirect(url_for('products'))

@app.route('/profile/<username>')
@login_required
def profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    products = user.products.order_by(Product.timestamp.desc()).all()
    return render_template('profile.html', user=user, products=products)

# API маршруты
@app.route('/api/products', methods=['GET'])
def get_products():
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 10, type=int), 100)
    products = Product.query.paginate(page, per_page, False)
    data = {
        'items': [item.to_dict() for item in products.items],
        '_meta': {
            'page': page,
            'per_page': per_page,
            'total_pages': products.pages,
            'total_items': products.total
        },
        '_links': {
            'self': url_for('get_products', page=page, per_page=per_page),
            'next': url_for('get_products', page=page + 1, per_page=per_page) if products.has_next else None,
            'prev': url_for('get_products', page=page - 1, per_page=per_page) if products.has_prev else None
        }
    }
    return jsonify(data)

@app.route('/api/products/<int:id>', methods=['GET'])
def get_product(id):
    return jsonify(Product.query.get_or_404(id).to_dict())

@app.route('/api/products', methods=['POST'])
@login_required
def create_product():
    data = request.get_json() or {}
    if 'title' not in data or 'description' not in data or 'price' not in data:
        return jsonify({'error': 'must include title, description and price fields'}), 400
    product = Product()
    product.title = data['title']
    product.description = data['description']
    product.price = data['price']
    product.category = data.get('category', 'other')
    product.author = current_user
    db.session.add(product)
    db.session.commit()
    response = jsonify(product.to_dict())
    response.status_code = 201
    response.headers['Location'] = url_for('get_product', id=product.id)
    return response

# Создание базы данных при первом запуске
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)