from copy import deepcopy

from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from random import choice
import string
import segno
from flask_login import LoginManager, login_user, logout_user, UserMixin, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from bs4 import BeautifulSoup
import requests as req
from flask import jsonify
import time

#  initializations
app = Flask(__name__)
app.config['SECRET_KEY'] = 'this should be a secret random string'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///urls_db.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = '/login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def create_db():
    with app.app_context():
        db.create_all()


def generate_random_string():
    return ''.join(choice(string.ascii_letters + string.digits) for i in range(5))


#  our urls database model
class Urls(db.Model):
    url_id = db.Column(db.Integer, primary_key=True)
    long_url = db.Column(db.String(), nullable=False)
    short_url = db.Column(db.String(20), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String())

    def __init__(self, long_url, short_url, user_id, title):
        self.long_url = long_url
        self.short_url = short_url
        self.user_id = user_id
        self.title = title


class User(db.Model, UserMixin):  # is active and login required are working because of usermixin being passed here
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(30), unique=True, nullable=False)
    urls = db.relationship('Urls', backref='user', lazy=True)

    def __init__(self, username, password, email):
        self.username = username
        self.password = password
        self.email = email


create_db()  # defined after both models so both get added to the database


@app.route('/', methods=['POST', 'GET'])
def homepage():
    if request.method == "POST":
        long_url = request.form["url"]
        url_found = Urls.query.filter_by(
            long_url=long_url).first()  # in the long_url column get the first value that matches
        if url_found:
            return redirect(url_for("show_urls", url=url_found.short_url))
        else:
            short_url_string = generate_random_string()
            both_urls = Urls(long_url, short_url_string)
            db.session.add(both_urls)
            db.session.commit()
            return redirect(url_for("show_urls", url=short_url_string))
    else:
        return render_template("index.html", current_user=current_user)


# Function to fetch the title tag from a URL
def get_title_from_url(url):
    try:
        response = req.get(url, timeout=5)  # Set timeout for the request to 5 seconds

        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            title_tag = soup.find('title')
            if title_tag:
                return title_tag.text
    except req.Timeout:
        return 'Title Issue'

    return 'No Title'


@app.route('/urls_table', methods=['GET', 'POST'])
@login_required
def show_urls():
    error_message = None  # Initialize error message

    if request.method == 'POST':
        long_url = request.form.get('long_url')
        custom_string = request.form.get('custom_string')  # Get the custom string from the form

        if long_url:
            existing_url = Urls.query.filter_by(long_url=long_url).first()
            existing_custom_url = Urls.query.filter_by(short_url=custom_string).first()

            if existing_custom_url:
                error_message = 'The string already exists in our record, please make a new one or leave blank'
            elif len(custom_string) > 20:
                error_message = 'Custom string length exceeds the limit (20 characters).'
            elif 1 < len(custom_string) < 21:
                short_url_string = custom_string
            else:
                short_url_string = generate_random_string()

            if not error_message and not existing_url:
                title = get_title_from_url(long_url)
                new_url = Urls(long_url=long_url, short_url=short_url_string, user_id=current_user.id, title=title)
                db.session.add(new_url)
                db.session.commit()
                error_message = 'URL added successfully'
            elif existing_url:
                error_message = 'The URL already exists in our record and cannot be added again.'

    return render_template('urls_table.html', Error=error_message)


@app.route('/<short_url>')
def redirect_url(short_url):
    url_row = Urls.query.filter_by(short_url=short_url).first()
    if url_row:
        return redirect(url_row.long_url)
    else:
        return render_template('basetemplate.html', error="We don't have this in record", title='Error')


@app.route('/view_my_urls', methods=['GET'])
@login_required
def view_my_urls():
    user_urls = Urls.query.filter_by(user_id=current_user.id).all()
    short_urls = db.session.query(Urls.short_url).filter(Urls.user_id == current_user.id).all()
    qr_code = []
    for short_url in short_urls:
        qr = segno.make('http://127.0.0.1:8080/' + short_url[0])
        qr_code.append(qr)
    return render_template('view_my_urls.html', user_urls=user_urls, qr_codes=qr_code)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            message = 'Successfully Logged in'
            return render_template('urls_table.html', Error=message)
        else:
            message = 'Invalid username or password, please try again'
            return render_template('login.html', Error=message)

    return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        existing_user = User.query.filter_by(username=username).first()
        existing_email = User.query.filter_by(email=email).first()

        if existing_user:
            print(existing_user)
            error = "Please make sure user doesn't already exist"
            return render_template('signup.html', Error=error)

        elif existing_email:
            error = "Please make email doesn't already exist"
            return render_template('signup.html', Error=error)

        else:
            new_user = User(username=username, password=generate_password_hash(password), email=email)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
    return render_template('signup.html')


@app.route('/logout')
def logout():
    logout_user()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))


@app.route('/copy_url/<int:url_id>', methods=['POST'])
@login_required
def copy_url(url_id):
    url = Urls.query.filter_by(url_id=url_id).first()  # Change the query to filter by url_id
    if url:
        if url.user_id == current_user.id:
            short_url = url.short_url
            full_url = 'http://127.0.0.1:8080/' + short_url
            return jsonify({'url': full_url}), 200


@app.route('/delete_url/<int:url_id>', methods=['POST'])
@login_required
def delete_url(url_id):
    url = Urls.query.get(url_id)
    if url:
        if url.user_id == current_user.id:
            db.session.delete(url)
            db.session.commit()
            return redirect(url_for('view_my_urls'))
        else:
            return jsonify({'error': 'Unauthorized to delete this URL'}), 403
    else:
        return jsonify({'error': 'URL not found'}), 404


if __name__ == '__main__':
    app.run(port=8080, debug=True)
