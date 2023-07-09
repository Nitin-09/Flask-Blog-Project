from flask import Flask, render_template, flash, redirect, url_for, session, request, logging
from flask_sqlalchemy import SQLAlchemy
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps

app = Flask(__name__)
app.secret_key = 'mysecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
db = SQLAlchemy(app)



class Article(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    body = db.Column(db.Text)
    author = db.Column(db.String(50))

    def __init__(self, title, body, author):
        self.title = title
        self.body = body
        self.author = author


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    username = db.Column(db.String(25))
    email = db.Column(db.String(50))
    password = db.Column(db.String(100))

    def __init__(self, name, username, email, password):
        self.name = name
        self.username = username
        self.email = email
        self.password = password




# Index
@app.route('/')
def index():
    return render_template('home.html')


# About
@app.route('/about')
def about():
    return render_template('about.html')


# Articles
@app.route('/articles')
def articles():
    articles = Article.query.all()

    if articles:
        return render_template('articles.html', articles=articles)
    else:
        msg = 'No Articles Found'
        return render_template('articles.html', msg=msg)


# Single Article
@app.route('/article/<int:id>/')
def article(id):
    article = Article.query.get(id)

    if article:
        return render_template('article.html', article=article)
    else:
        msg = 'Article not found'
        return render_template('article.html', msg=msg)


# Register Form Class
class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    username = StringField('Username', [validators.Length(min=4, max=25)])
    email = StringField('Email', [validators.Length(min=6, max=50)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')


# User Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    db.create_all()
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))

        user = Users(name=name, email=email, username=username, password=password)
        db.session.add(user)
        db.session.commit()

        flash('You are now registered and can log in', 'success')

        return redirect(url_for('login'))
    return render_template('register.html', form=form)


# User Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    db.create_all()
    if request.method == 'POST':
        username = request.form['username']
        password_candidate = request.form['password']

        user = Users.query.filter_by(username=username).first()
        if user:
            password = user.password

            if sha256_crypt.verify(password_candidate, password):
                session['logged_in'] = True
                session['username'] = username

                flash('You are now logged in', 'success')
                return redirect(url_for('dashboard'))
            else:
                error = 'Invalid Login'
                return render_template('login.html', error=error)
        else:
            error = 'Username not found'
            return render_template('login.html', error=error)
    return render_template('login.html')


# Check if user logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', 'danger')
            return redirect(url_for('login'))

    return wrap


# Logout
@app.route('/logout')
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))


# Dashboard
@app.route('/dashboard')
@is_logged_in
def dashboard():
    articles = Article.query.all()

    if articles:
        return render_template('dashboard.html', articles=articles)
    else:
        msg = 'No Articles Found'
        return render_template('dashboard.html', msg=msg)


class ArticleForm(Form):
    title = StringField('Title', [validators.Length(min=1, max=200)])
    body = TextAreaField('Body', [validators.Length(min=30)])


# Add Article
@app.route('/add_article', methods=['GET', 'POST'])
@is_logged_in
def add_article():
    form = ArticleForm(request.form)
    if request.method == 'POST' and form.validate():
        title = form.title.data
        body = form.body.data

        article = Article(title=title, body=body, author=session['username'])
        db.session.add(article)
        db.session.commit()

        flash('Article Created', 'success')

        return redirect(url_for('dashboard'))

    return render_template('add_article.html', form=form)


# Edit Article
@app.route('/edit_article/<int:id>', methods=['GET', 'POST'])
@is_logged_in
def edit_article(id):
    article = Article.query.get(id)

    if not article:
        flash('Article not found', 'danger')
        return redirect(url_for('dashboard'))

    form = ArticleForm(request.form)

    if request.method == 'POST' and form.validate():
        title = request.form['title']
        body = request.form['body']

        article.title = title
        article.body = body

        db.session.commit()

        flash('Article Updated', 'success')

        return redirect(url_for('dashboard'))

    form.title.data = article.title
    form.body.data = article.body

    return render_template('edit_article.html', form=form)


# Delete article
@app.route('/delete_article/<int:id>', methods=['POST'])
@is_logged_in
def delete_article(id):
    article = Article.query.get(id)

    if not article:
        flash('Article not found', 'danger')
        return redirect(url_for('dashboard'))

    db.session.delete(article)
    db.session.commit()

    flash('Article Deleted', 'success')

    return redirect(url_for('dashboard'))


if __name__ == '__main__':
    app.secret_key = 'secret123'
    app.run(debug=True, host='0.0.0.0')
