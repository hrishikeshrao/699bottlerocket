#get everything imported and set up
from datetime import datetime
from flask import Flask, jsonify, render_template, flash, url_for, request, redirect, abort, make_response #import Flask, Jinja2 rendering
from flask_bootstrap import Bootstrap #import bootstrap - don't forget to pip install flask-bootstrap first
from flask_script import Manager #import flask-script
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
import wtforms_json
from flask_wtf import Form
from wtforms import StringField, SubmitField, SelectField, BooleanField, PasswordField
from wtforms.validators import Required, Length, Email, Regexp, EqualTo
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_sslify import SSLify
from datetime import timedelta
from werkzeug.datastructures import CombinedMultiDict, MultiDict
wtforms_json.init()
#############################
##          Config         ##
#############################
#basic application initialization
basedir = os.path.abspath(os.path.dirname(__file__))
application = app = Flask(__name__, template_folder='templates') #Pass the __name__ argument to the Flask application constructor

#This is the config for the dev server + SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'data.sqlite')
app.config['TEMPLATES_AUTO_RELOAD'] = True
#This is the config for MySQL + Beanstalk
#app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://' + os.environ['RDS_USERNAME'] + ':' + os.environ['RDS_PASSWORD'] + '@' + os.environ['RDS_HOSTNAME'] + ':' + os.environ['RDS_PORT'] + '/' + os.environ['RDS_DB_NAME']

#driver = 'mysql+pymysql://'
#application.debug=True
#app.config['SQLALCHEMY_DATABASE_URI'] = driver \
#                                        + os.environ['RDS_USERNAME'] + ':' + os.environ['RDS_PASSWORD'] \
#                                        +'@' + os.environ['RDS_HOSTNAME']  +  ':' + os.environ['RDS_PORT'] \
#                                        + '/' + os.environ['RDS_DB_NAME']

app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SECRET_KEY'] = 'you_should_really_have_this_be_an_environment_variable'
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.session_protection = 'strong'
login_manager.login_view = 'login'
#we'll uncomment the line below to force SSL connections when we deploy to Amazon Elasticbeanstalk
#sslify = SSLify(application)


#############################
## Form Definitions Below ##
#############################
#revised NameForm for updating status
class NameForm(Form):
    ready = SelectField("Are you ready?",choices=[('ready', 'So. Ready.'), ('sleeping', 'So. Tired.'), ('busy', 'So. Busy.')])
    submit = SubmitField('Submit')

#Form we use for logging in
class LoginForm(Form):
    email = StringField('Email', validators=[Required(), Length(1, 64), Email()])
    password = PasswordField('Password', validators=[Required()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')

#Form for creating a new user
class RegistrationForm(Form):
    email = StringField('Email', validators=[Required(), Length(1, 64),
                                           Email()])
    username = StringField('Username', validators=[
        Required(), Length(1, 64), Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                                          'Usernames must have only letters, '
                                          'numbers, dots or underscores')])
    password = PasswordField('Password', validators=[
        Required(), EqualTo('password2', message='Passwords must match.')])
    password2 = PasswordField('Confirm password', validators=[Required()])
    submit = SubmitField('Register')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email taken')
class FundayForm(Form):
    title = StringField('Title', validators=[
        Required(), Length(1, 64)])
    thing1 = StringField('Fun Thing 1', validators=[
        Required(), Length(1, 64)])
    thing2 = StringField('Fun Thing 2', validators=[
                Required(), Length(1, 64)])
    thing3 = StringField('Fun Thing 3', validators=[
        Required(), Length(1, 64)])
    thing4 = StringField('Fun Thing 4', validators=[
        Required(), Length(1, 64)])
    thing5 = StringField('Fun Thing 5', validators=[
            Required(), Length(1, 64)])
    submit = SubmitField('Create')

class CreatePollForm(Form):
    title = StringField('Title', validators=[
        Required(), Length(1, 64)])
    option1 = StringField('Option 1', validators=[
        Required(), Length(1, 64)])
    option2 = StringField('Option 2', validators=[
                Required(), Length(1, 64)])
    anonymous = BooleanField('Anonymous'  )
    submit = SubmitField('Create')


def shutdown_server():
    func = request.environ.get('werkzeug.server.shutdown')
    if func is None:
        raise RuntimeError('Not running with the Werkzeug Server')
    func()

@app.route('/shutdown', methods=['POST'])
def shutdown():
    shutdown_server()
    return 'Server shutting down...'


#login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            return redirect(request.args.get('next') or url_for('index'))
        flash('Invalid username or password.')
    return render_template('login.html', form=form)

#logout route
@app.route('/logout/')
@login_required
def logout():
    logout_user()
    flash('You have been logged out')
    return redirect(url_for('index'))

#Route for registering a new user. Note - no password in model. Model will hash it.
@app.route('/register/', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data,
                    username=form.username.data,
                    password=form.password.data,
                    ready='new_user')
        db.session.add(user)
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

#index - used to update location and see other user locations
@app.route('/', methods=['GET', 'POST']) #define the route for <server>/
@login_required
def index(): #index function
    last_day =  datetime.today() - timedelta(days=-1)
    poll=Polls.query.filter(Polls.timestamp < last_day).order_by(Polls.timestamp.desc()).all()
#    if form.validate_on_submit():
##            current_user.ready=form.ready.data
#            db.session.add(current_user)
#            flash('Level of excitement updated.')
    otherusers=User.query.all()
    return render_template('index_ng.html', polls=poll, otherusers=otherusers)

#@app.route('/funday', methods=['GET', 'POST']) #define the route for <server>/
#@login_required
#def funday(): #index function
#    form = FundayForm()
#    if form.validate_on_submit():
#            newfunday=Funday(title=form.title.data, thing1=form.thing1.data, thing2=form.thing2.data, thing3=form.thing3.data, thing4=form.thing4.data, thing5=form.thing5.data, author=current_user._get_current_object())
#            db.session.add(newfunday)
#            flash('Epic Sunday Funday Created. Create another?')
#            return redirect(url_for('funday'))
#    otherusers=User.query.all()
#    return render_template('index.html', form=form)

@app.route('/create_poll/', methods=['GET', 'POST']) #define the route for <server>/create_poll
@login_required
def createpoll(): #index function
    form = CreatePollForm()
    if form.validate_on_submit():
            newPoll=Polls(title=form.title.data, option1=form.option1.data, option2=form.option2.data, anonymous=form.anonymous.data, author=current_user._get_current_object())
            db.session.add(newPoll)
            flash('Epic Sunday Funday Created. Create another?')
            return redirect(url_for('createpoll'))
#    otherusers=User.query.all()
    return render_template('index.html', form=form)

@app.route('/create_poll_ng/', methods=['POST'])
@login_required
def createpoll2():
    data = MultiDict(mapping=request.json)
    form = CreatePollForm.from_json(data)
    newPoll=Polls(title=form.title.data, option1=form.option1.data, option2=form.option2.data, anonymous=form.anonymous.data,author=current_user._get_current_object())
    db.session.add(newPoll)
    flash('Poll created')
    resp = jsonify(data)
    resp.status_code = 201
    return resp

@app.route('/vote_ng/', methods=['POST'])
@login_required
def votepolls():
    data = MultiDict(mapping=request.json)
    newvote = Votes(author=current_user._get_current_object(),poll_id=data["poll_id"],option = data["option"])
    db.session.add(newvote)
    return jsonify(data={'message': "1"})

@app.route('/showpoll', methods=['GET']) #define the route for <server>/showpoll
@login_required
def showpoll(): #showpoll function
    last_day =  datetime.today() - timedelta(days=-1)
    poll=Polls.query.filter(Polls.timestamp < last_day).order_by(Polls.timestamp.desc()).all()
    return render_template('show.html', polls=poll)

@app.route('/showpoll_ng/', methods=['GET']) #define the route for <server>/showpoll
@login_required
def showpoll2(): #showpoll function
    last_day =  datetime.today() - timedelta(days=-1)
    user = current_user._get_current_object()
    voted = Votes.query.filter(Votes.author_id == user.id).all()
    poll=Polls.query.filter(Polls.timestamp < last_day).order_by(Polls.timestamp.desc()).all()
    return jsonify({'polls':[e.serialize() for e in poll],'voted':voted})

@app.route('/mypoll_ng/', methods=['GET']) #define the route for <server>/showpoll
@login_required
def mypoll():
    user = current_user._get_current_object()
    polls =Polls.query.filter(Polls.author_id == user.id).all()
    for poll in polls:
        votes.append(Votes.query.filter(Votes.poll_id == poll.id).all())

@app.route('/show', methods=['GET']) #define the route for <server>/
@login_required
def show(): #index function
    fundays=Funday.query.order_by(Funday.timestamp.desc()).all()
    return render_template('show.html', fundays=fundays)


@app.route('/follow/<username>')
@login_required
def follow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid user.')
        return redirect(url_for('index'))
    if current_user.is_following(user):
        flash('You are already following this person.')
        return redirect(url_for('index'))
    current_user.follow(user)
    flash('You are now following %s.' % username)
    return redirect(url_for('index'))

@app.route('/unfollow/<username>')
@login_required
def unfollow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid user.')
        return redirect(url_for('index'))
    if not current_user.is_following(user):
        flash('You are not following this person.')
        return redirect(url_for('.user', username=username))
    current_user.unfollow(user)
    flash('You are not following %s anymore.' % username)
    return redirect(url_for('index'))


#api route
@app.route('/api/users')
def get_users():
    apiusers=User.query.all() #get all users
    return jsonify({ 'users' : [apiuser.to_json() for apiuser in apiusers]}) #return JSON of all users

@app.route('/users')
@login_required
def users():
    otherusers=User.query.all()
    return render_template('users.html', otherusers=otherusers)

@app.route('/user/<name>')
@login_required
def user(name):
    existinguser=User.query.filter_by(username=name).first()
    return render_template('user.html', existinguser=existinguser)
    #return render_template('hello_bootstrap.html', name=name)

#route for creating a new database
@app.route('/db/create_db')
def create_db():
    db.create_all()
    return '<h1>Database Created</h1>'

#route for clearing the database
@app.route('/db/drop_db')
def drop_db():
    db.drop_all()
    return '<h1>Database Cleared</h1>'

class Follow(db.Model):
    __tablename__ = 'follows'
    follower_id = db.Column(db.Integer, db.ForeignKey('users.id'),
                            primary_key=True)
    followed_id = db.Column(db.Integer, db.ForeignKey('users.id'),
                            primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Funday(db.Model):
    __tablename__ = 'fundays'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.Text)
    thing1 = db.Column(db.Text)
    thing2 = db.Column(db.Text)
    thing3 = db.Column(db.Text)
    thing4 = db.Column(db.Text)
    thing5 = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))

class Polls(db.Model):
    __polls__='polls'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.Text)
    option1 = db.Column(db.Text)
    option2 = db.Column(db.Text)
    anonymous = db.Column(db.Boolean)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    def serialize(self):
        return {
            'id': self.id,
            'title': self.title,
            'option1': self.option1,
            'option2':self.option2,
            'author_id':self.author_id,
        }

class Votes(db.Model):
    __tablename__ = "votes"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    poll_id = db.Column(db.Integer, db.ForeignKey('polls.id'))
    option =  db.Column(db.Boolean)


#user class - includes the UserMixin from flash.ext.login to help with password hashing, etc.
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    password_hash = db.Column(db.String(128))
    posts = db.relationship('Funday',
                               foreign_keys=[Funday.author_id],
                               backref=db.backref('author', lazy='joined'),
                               lazy='dynamic')
    polls = db.relationship('Polls',
                               foreign_keys=[Polls.author_id],
                               backref=db.backref('author', lazy='joined'),
                               lazy='dynamic')
    ready = db.Column(db.String(64), nullable=True)
    followed = db.relationship('Follow',
                               foreign_keys=[Follow.follower_id],
                               backref=db.backref('follower', lazy='joined'),
                               lazy='dynamic',
                               cascade='all, delete-orphan')
    followers = db.relationship('Follow',
                                foreign_keys=[Follow.followed_id],
                                backref=db.backref('followed', lazy='joined'),
                                lazy='dynamic',
                                cascade='all, delete-orphan')

    def follow(self, user):
        if not self.is_following(user):
            f = Follow(follower=self, followed=user)
            db.session.add(f)

    def unfollow(self, user):
        f = self.followed.filter_by(followed_id=user.id).first()
        if f:
            db.session.delete(f)

    def is_following(self, user):
        return self.followed.filter_by(
            followed_id=user.id).first() is not None

    def is_followed_by(self, user):
        return self.followers.filter_by(
            follower_id=user.id).first() is not None

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)
#method for spitting out user info as JSON
    def to_json(self):
        json_user = {
            'username' : self.username,
            'ready' : self.ready
        }
        return json_user

#user loader for login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

if __name__=='__main__': #only do the following if the script is executed directly skip if imported
    app.run(debug=True) #start the integrated flask webserver
