#get everything imported and set up
from datetime import datetime
from flask import Flask, jsonify, render_template, flash, url_for, request, redirect #import Flask, Jinja2 rendering
from flask_bootstrap import Bootstrap #import bootstrap - don't forget to pip install flask-bootstrap first
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
import wtforms_json
from flask_wtf import Form
from wtforms import StringField, SubmitField, SelectField, BooleanField, PasswordField
from wtforms.validators import Required, Length, Email, Regexp, EqualTo
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from datetime import timedelta
from werkzeug.datastructures import MultiDict
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

class CreatePollForm(Form):
    title = StringField('Title', validators=[
        Required(), Length(1, 64)])
    option1 = StringField('Option 1', validators=[
        Required(), Length(1, 64)])
    option2 = StringField('Option 2', validators=[
                Required(), Length(1, 64)])
    anonymous = BooleanField('Anonymous'  )
    submit = SubmitField('Create')


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
    otherusers=User.query.all()
    return render_template('index_ng.html', polls=poll, otherusers=otherusers)

@app.route('/create_poll_ng/', methods=['POST'])
@login_required
def createpoll2():
    data = MultiDict(mapping=request.json)
    form = CreatePollForm.from_json(data)
    newPoll=Polls(title=form.title.data, option1=form.option1.data, option2=form.option2.data, anonymous=form.anonymous.data,author=current_user._get_current_object())
    db.session.add(newPoll)
    resp = jsonify(data)
    resp.status_code = 201
    return resp

@app.route('/vote_ng/', methods=['POST'])
@login_required
def votepolls():
    data = MultiDict(mapping=request.json)
    newvote = Votes(author_id=current_user._get_current_object().id,poll_id=data["poll_id"],option = data["option"])
    db.session.add(newvote)
    resp = jsonify(data)
    resp.status_code = 201
    return resp

@app.route('/showpoll_ng/', methods=['GET']) #define the route for <server>/showpoll
@login_required
def showpoll2(): #showpoll function
    last_day =  datetime.today() - timedelta(days=-1)
    user = current_user._get_current_object()
    voted = Votes.query.filter(Votes.author_id == user.id).all()
    poll=Polls.query.filter(Polls.timestamp < last_day).order_by(Polls.timestamp.desc()).all()
    votes=[]
    voted = []
    total_votes = []
    total_1= []
    total_2 = []
    for poll_obj in poll:
        vote_objects = Votes.query.filter(Votes.poll_id == poll_obj.id).all()
        vote_boolean = False
        op1_count = 0
        op2_count = 0
        for element in vote_objects:
            if (element.author_id == user.id):vote_boolean = True
            if (element.option):op1_count +=1
            else:op2_count +=1
        percent1 = 0
        percent2 = 0
        try:percent1 = op1_count*100/float(op1_count+op2_count)
        except:percent1 = 0
        try:percent2 = op2_count*100/float(op1_count+op2_count)
        except:percent2 = 0
        votes.append([percent1,percent2])
        voted.append(vote_boolean)
        total_votes.append(op1_count+op2_count)
        total_1.append(op1_count)
        total_2.append(op2_count)
    poll_serialized = [e.serialize() for e in poll]
    combined=[]
    for i in range (0,len(poll)):
        poll_serialized[i]["percent1"] =votes[i][0]
        poll_serialized[i]["percent2"] =votes[i][1]
        poll_serialized[i]["voted_flag"] =voted[i]
        poll_serialized[i]["total_votes"] =total_votes[i]
        poll_serialized[i]["total_1"] =total_1[i]
        poll_serialized[i]["total_2"] =total_2[i]
        
        combined.append(poll_serialized[i])
    return jsonify({'polls':combined})

@app.route('/mypoll_ng/', methods=['GET']) #define the route for <server>/showpoll
@login_required
def mypoll():
    user = current_user._get_current_object()
    poll =Polls.query.filter(Polls.author_id == user.id).all()
    votes=[]
    voted = []
    total_votes = []
    total_1= []
    total_2 = []
    for poll_obj in poll:
        vote_objects = Votes.query.filter(Votes.poll_id == poll_obj.id).all()
        vote_boolean = False
        op1_count = 0
        op2_count = 0
        for element in vote_objects:
            if (element.author_id == user.id):vote_boolean = True
            if (element.option):op1_count +=1
            else:op2_count +=1
        percent1 = 0
        percent2 = 0
        try:percent1 = op1_count*100/float(op1_count+op2_count)
        except:percent1 = 0
        try:percent2 = op2_count*100/float(op1_count+op2_count)
        except:percent2 = 0
        votes.append([percent1,percent2])
        voted.append(vote_boolean)
        total_votes.append(op1_count+op2_count)
        total_1.append(op1_count)
        total_2.append(op2_count)
    poll_serialized = [e.serialize() for e in poll]
    combined=[]
    for i in range (0,len(poll)):
        poll_serialized[i]["percent1"] =votes[i][0]
        poll_serialized[i]["percent2"] =votes[i][1]
        poll_serialized[i]["voted_flag"] =voted[i]
        poll_serialized[i]["total_votes"] =total_votes[i]
        poll_serialized[i]["total_1"] =total_1[i]
        poll_serialized[i]["total_2"] =total_2[i]
        
        combined.append(poll_serialized[i])
    return jsonify({'polls':combined})




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
    polls = db.relationship('Polls',
                               foreign_keys=[Polls.author_id],
                               backref=db.backref('author', lazy='joined'),
                               lazy='dynamic')
    ready = db.Column(db.String(64), nullable=True)    

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
