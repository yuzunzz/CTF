__author__ = "ask3m"
__updater__ = "yuzunzz"

import os
import base64
from flask import Flask, render_template, redirect, url_for, flash, session, abort, request
from werkzeug.security import generate_password_hash, check_password_hash
from flask_security import Security
from flask.ext.sqlalchemy import SQLAlchemy
from sqlalchemy import desc
from flask.ext.login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask.ext.bootstrap import Bootstrap
from flask.ext.wtf import Form
from wtforms import StringField, PasswordField, SubmitField, RadioField
from wtforms.validators import Required, Length, EqualTo, Email
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_admin.contrib import sqla
from flask_admin import helpers as admin_helpers
import datetime
from flask.ext.mail import Message
from flask_mail import Mail
from itsdangerous import URLSafeTimedSerializer
from operator import attrgetter
app = Flask('__name__')
app.config.from_object('config')
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
Bootstrap(app)
app.config['BOOTSTRAP_SERVE_LOCAL'] = True
admin = Admin(app)
mail = Mail(app)

def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])


def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            salt=app.config['SECURITY_PASSWORD_SALT'],
            max_age=expiration
        )
    except:
        return False
    return email

def send_email(to, subject, template):
    msg = Message(
        subject,
        recipients=[to],
        html=template,
        sender=app.config['MAIL_DEFAULT_SENDER']
    )
    mail.send(msg)

# Create customized model view class
class MyModelView(sqla.ModelView):

    def is_accessible(self):
        if not current_user.is_active() or not current_user.is_authenticated():
            return False

        if current_user.username == "test":
            return True

        return False

    def _handle_view(self, name, **kwargs):
        """
        Override builtin _handle_view in order to redirect users when a view is not accessible.
        """
        if not self.is_accessible():
            if current_user.is_authenticated():
                # permission denied
                abort(403)
            else:
                # login
                return redirect(url_for('security.login', next=request.url))


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    realname = db.Column(db.String(80))
    classname= db.Column(db.String(80))
    email = db.Column(db.String(80))
    password_hash = db.Column(db.String(120))
    school = db.Column(db.String(120))
    score = db.Column(db.String(20))
    solved = db.Column(db.String(400))
    lastSubmit = db.Column(db.DateTime)
    confirmed = db.Column(db.Boolean, nullable=False, default=False)

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return '<User %r>' % self.username



class Challenges(db.Model):
    __tablename__ = 'challenges'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True)
    category = db.Column(db.String(80))
    info = db.Column(db.String(2000))
    score = db.Column(db.String(20))
    flag = db.Column(db.String(40))

    def __repr__(self):
        return '<Challenges %r>' % self.name

@login_manager.user_loader
def load_user(user_id):
    """User loader callback for Flask-Login."""
    return User.query.get(int(user_id))


# The context processor makes the rank function available to all templates
# Update: Remove the administrator from the score ranking 
@app.context_processor
def utility_processor():
    def rank(user_name):
        users = User.query.filter(User.username!='test').order_by(desc(User.score)).all()
        for user in users :
            user.score = int(user.score)
        users_sort =sorted(users, key=attrgetter('score'),reverse=True)
        myuser = User.query.filter_by(username=user_name).first()
        myuser.score = int(myuser.score)
        l = []
        for user in users_sort :
            l.append(user.score)
        return int(l.index(myuser.score)) + 1
    return dict(rank=rank)

def rank(user_name):
    users = User.query.filter(User.username!='test').order_by(desc(User.score)).all()
    for user in users :
        user.score = int(user.score)
    users_sort =sorted(users, key=attrgetter('score'),reverse=True)
    myuser = User.query.filter_by(username=user_name).first()
    myuser.score = int(myuser.score)
    l = []
    for user in users_sort :
        l.append(user.score)
    return int(l.index(myuser.score)) + 1

class LoginForm(Form):
    login = StringField('Username', validators=[Required(), Length(1, 64)])
    password = PasswordField('Password', validators=[Required()])
    submit = SubmitField('Login')

class FlagForm(Form):
    flag = StringField('The Flag', validators=[Required(), Length(1, 64)])
    submit = SubmitField('Send')

class RegistrationForm(Form):
    username = StringField('Username', validators=[Required()])
    email = StringField('Email', validators=[Required(), Email()])
    password = PasswordField('Password', validators=[Required()])
    password_again = PasswordField('Password again',
                                   validators=[Required(), EqualTo('password')])
    realname = StringField()
    classname = StringField()
    school = StringField()
    submit = SubmitField('Register')

@app.route('/')
def index():
    if not current_user.is_authenticated():
        # if user is logged in we get out of here
        return redirect(url_for('login'))
    if current_user.username == "test":
        return redirect(url_for('admin.index'))
    else:
        query = db.session.query(Challenges.category.distinct().label("category"))
        challenges = Challenges.query.all()
        categories = [row.category for row in query.all()]
        ranking = rank(current_user.username)
        return render_template('index.html', challenges=challenges, categories=categories, ranking=ranking)

@app.route('/register', methods=['GET','POST'])
def register():
    if current_user.is_authenticated():
        # if user is logged in we get out of here
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is not None:
            flash('Username already exists.')
            return redirect(url_for('register'))
	user = User(username=form.username.data,
                       email=form.email.data,
		       password=form.password.data,
		       school=form.school.data,
		       realname=form.realname.data,
                 classname=form.classname.data,
		       score='0',
		       solved='*',
               confirmed=1)
	db.session.add(user)
	db.session.commit()
        # token = generate_confirmation_token(form.email.data)
        # confirm_url = url_for('confirm_email', token=token, _external=True)
        # html = render_template('email.html', confirm_url=confirm_url)
        # subject = "Please confirm your email"
        # send_email(form.email.data, subject, html)
        # flash('A confirmation email has been sent via email.', 'success')
        flash('Regeist success.', 'success')
        return redirect(url_for('index'))
    return render_template('register.html', form=form)

@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = confirm_token(token)
    except:
        flash('The confirmation link is invalid or has expired.', 'danger')
    user = User.query.filter_by(email=email).first_or_404()
    if user.confirmed:
        flash('Account already confirmed. Please login.', 'success')
    else:
        user.confirmed = True
        db.session.add(user)
        db.session.commit()
        flash('You have confirmed your account. Thanks!', 'success')
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    # Here we use a class of some kind to represent and validate our
    # client-side form data. For example, WTForms is a library that will
    # handle this for us, and we use a custom LoginForm to validate.
    if current_user.is_authenticated():
        # if user is logged in we get out of here
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        # Login and validate the user.
        # user should be an instance of your `User` class
	user = User.query.filter_by(username=form.login.data).first()
	if user is None or not user.verify_password(form.password.data) or not user.confirmed:
	    flash('Invalid username or password')
	    return redirect(url_for('login'))
        login_user(user)
        flash('Logged in successfully.')
        return redirect(url_for('index'))
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    """Logout the current user."""
    logout_user()
    return redirect(url_for('index'))

@app.route('/rules')
# @login_required
def rules():
    return render_template('rules.html')

@app.route('/scoreboard')
def scoreboard():
    users = User.query.filter(User.username!='test').order_by(desc(User.score)).all()
    for user in users:
        user.score = int(user.score)
    users_sort =sorted(users, key=attrgetter('score'),reverse=True)
    winners = []
    temps = []
    for user in users_sort :
        if rank(user.username) == 1 :
	    winners.append(user)
            temps.append(user.lastSubmit)
    winnertime = min(temps)
    return render_template('scoreboard.html', users=users_sort, winnertime=winnertime)

@app.route('/challenges/<challenge_name>',methods=["GET","POST"])
def challenges(challenge_name):
    if not current_user.is_authenticated():
        flash('Please login.')
        return redirect(url_for('index'))
    user = User.query.filter_by(username=current_user.username).first()
    challenge = Challenges.query.filter_by(name=challenge_name).first()
    a = Challenges.query.all()
    challengelist = []
    for item in Challenges.query.all():
        challengelist.append(item.name)
    if challenge_name not in challengelist:
        flash('Challenge not found')
        return redirect(url_for('index'))
    if challenge_name in user.solved:
        flash('Challenge complete')
        return redirect(url_for('index'))
    else:
        form = FlagForm()
        if form.validate_on_submit() and challenge.flag == form.flag.data :
            # Update user's score and solved tasks
            user.score = str(int(user.score) + int(challenge.score))
            user.solved = user.solved + ',' + challenge.name
            user.lastSubmit = datetime.datetime.utcnow()
            db.session.commit()
            flash('Good Job!')
            return redirect(url_for('index'))
        elif form.validate_on_submit() and challenge.flag != form.flag.data :
            flash('Wrong Flag!')
            return render_template('challenges.html',form=form, challenge=challenge )
        return render_template('challenges.html',form=form, challenge=challenge )

db.create_all()
admin.add_view(MyModelView(User, db.session))
admin.add_view(MyModelView(Challenges, db.session))
if __name__ == '__main__':
    app.run(debug=True)
