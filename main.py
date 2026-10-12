from flask import Flask, render_template
from database import Users, Product, Orders, Reservation

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/menu')
def menu():
    return render_template('menu.html')

@app.route('/orders')
def orders():
    return render_template('orders.html')


if __name__ == '__main__':
    app.run(debug=True)