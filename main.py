import os
import secrets

from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from werkzeug.security import check_password_hash, generate_password_hash

from database import Base, SessionLocal, Users, engine

app = Flask(__name__, static_folder='img')
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY') or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    MAX_CONTENT_LENGTH=16 * 1024,
)
if not os.environ.get('SECRET_KEY'):
    app.logger.warning(
        'SECRET_KEY is not set; sessions will expire on restart. '
        'Set a stable, random SECRET_KEY before deployment.'
    )

Base.metadata.create_all(engine)


def csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']


app.jinja_env.globals['csrf_token'] = csrf_token


@app.before_request
def load_user_and_validate_csrf():
    if request.method == 'POST':
        expected_token = session.get('csrf_token')
        submitted_token = request.form.get('csrf_token', '')
        if not expected_token or not secrets.compare_digest(
            expected_token.encode('utf-8'), submitted_token.encode('utf-8')
        ):
            abort(400, description='Invalid or expired form. Reload the page and try again.')

    g.user = None
    user_id = session.get('user_id')
    if user_id is not None:
        with SessionLocal() as db:
            g.user = db.get(Users, user_id)
        if g.user is None:
            session.clear()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if g.user is not None:
        return redirect(url_for('index'))

    username = ''
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirmation = request.form.get('confirm_password', '')

        if not 3 <= len(username) <= 100:
            error = 'Username must be between 3 and 100 characters.'
        elif not 8 <= len(password) <= 128:
            error = 'Password must be between 8 and 128 characters.'
        elif password != confirmation:
            error = 'Passwords do not match.'
        else:
            with SessionLocal() as db:
                user = db.scalar(select(Users).where(Users.username == username))
                if user is not None:
                    error = 'That username is already taken.'
                else:
                    db.add(Users(
                        username=username,
                        password=generate_password_hash(password),
                    ))
                    try:
                        db.commit()
                    except IntegrityError:
                        db.rollback()
                        if db.scalar(select(Users).where(Users.username == username)) is None:
                            raise
                        error = 'That username is already taken.'
                    else:
                        flash('Account created. Please log in.', 'success')
                        return redirect(url_for('login'))

    return render_template('register.html', error=error, username=username)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if g.user is not None:
        return redirect(url_for('index'))

    username = ''
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if not 3 <= len(username) <= 100 or not 8 <= len(password) <= 128:
            error = 'Invalid username or password.'
        else:
            with SessionLocal() as db:
                user = db.scalar(select(Users).where(Users.username == username))
                if user is None or not check_password_hash(user.password, password):
                    error = 'Invalid username or password.'
                else:
                    session.clear()
                    session['user_id'] = user.id
                    flash('You are now logged in.', 'success')
                    return redirect(url_for('index'))

    return render_template('login.html', error=error, username=username)


@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))


@app.route('/menu')
def menu():
    return render_template('menu.html')

@app.route('/orders')
def orders():
    return render_template('orders.html')


if __name__ == '__main__':
    app.run(debug=True)