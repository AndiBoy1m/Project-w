from flask import Flask, render_template

app = Flask(__name__)

categories = ['Электроника', 'Одежда', 'Книги', 'Мебель']

items_db = {
    'Электроника': [
        {'name': 'Ноутбук', 'price': 45000, 'rating': 4},
        {'name': 'Смартфон', 'price': 30000, 'rating': 5}
    ],
    'Одежда': [
        {'name': 'Футболка', 'price': 1500, 'rating': 3},
        {'name': 'Джинсы', 'price': 3500, 'rating': 4}
    ],
    'Книги': [
        {'name': 'Python для начинающих', 'price': 1200, 'rating': 5},
        {'name': 'Искусство программирования', 'price': 2500, 'rating': 4}
    ],
    'Мебель': [
        {'name': 'Диван', 'price': 24999, 'rating': 5},
        {'name': 'Шкаф', 'price': 13999, 'rating': 4}
    ]
}

@app.route('/')
def index():
    return render_template('index.html', categories=categories)

@app.route('/category/<cat_name>')
def category(cat_name):
    items = items_db.get(cat_name, [])
    return render_template('category.html', category=cat_name, items=items)

if __name__ == '__main__':
    app.run(debug=True)
