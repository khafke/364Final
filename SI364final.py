###############################
####### SETUP (OVERALL) #######
###############################

# Import statements
import os
from flask import Flask, render_template, session, redirect, request, url_for, flash

from flask_script import Manager, Shell

from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, FileField, PasswordField, BooleanField, SelectMultipleField, ValidationError, Form, FloatField
from wtforms.validators import Required, Length, Email, Regexp, EqualTo, DataRequired

from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate, MigrateCommand

from flask_login import LoginManager, login_required, logout_user, login_user, UserMixin, current_user

from werkzeug.security import generate_password_hash, check_password_hash

import requests
import json
import spotipy
import sys
from spotipy.oauth2 import SpotifyClientCredentials

# Configure base directory of app
basedir = os.path.abspath(os.path.dirname(__file__))

# Application configurations
app = Flask(__name__)
app.static_folder = 'static'
app.config['SECRET_KEY'] = 'hardtoguessstring'
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get('DATABASE_URL') or "postgresql://localhost/final_test"
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.debug = True

# App addition setups
manager = Manager(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
manager.add_command('db', MigrateCommand)

# Login configurations setup
login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view = 'login'
login_manager.init_app(app) 

def make_shell_context():
    return dict(app=app, db=db, User=User)

manager.add_command("shell", Shell(make_context=make_shell_context))


##################
### App setup ####
##################

manager = Manager(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
manager.add_command('db', MigrateCommand)

#####################
##### API SETUP #####
####################
sp = spotipy.Spotify()

client_credentials_manager = SpotifyClientCredentials(client_id='4ea4d177cd0b446eb007833b538fe482', client_secret='e254dd99e9e741f298fef461fb7c6d9f')
spotify = spotipy.Spotify(client_credentials_manager=client_credentials_manager)

##################
##### MODELS #####
##################

## User Models ##
# Special model for users to log in
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, index=True)
    email = db.Column(db.String(64), unique=True, index=True)
    password_hash = db.Column(db.String(128))
    artist_id = db.Column(db.Integer,db.ForeignKey("artist_list.id"))

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

## DB load function

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id)) # returns User object or None

# Set up association Table between artists and albums
artists_albums = db.Table('artists_albums', db.Column('album_id', db.Integer, db.ForeignKey('album_results.id')), db.Column('artist_id', db.Integer, db.ForeignKey('artist_results.id')))


#artists searched model
class ArtistList(db.Model):
    __tablename__ = "artist_list"
    id = db.Column(db.Integer,primary_key=True)
    artist = db.Column(db.String(64))
    user = db.relationship('User',backref='ArtistList')


    def __repr__(self):
        return "{}".format(self.artist)

#artist search results model 
class ArtistResults(db.Model):
    __tablename__ = "artist_results"
    id = db.Column(db.Integer,primary_key=True)
    artist = db.Column(db.String)
    rating = db.Column(db.Float())
    albums = db.relationship('AlbumResults', secondary=artists_albums, backref = db.backref('artist_results', lazy='dynamic'), lazy='dynamic')

    def __repr__(self):
        return "{}, {}".format(self.artist, self.rating)

#albums model
class AlbumResults(db.Model):
    __tablename__ = "album_results"
    id = db.Column(db.Integer,primary_key=True)
    album = db.Column(db.String)
    artist = db.Column(db.String)
    artist_many = db.relationship('ArtistResults',secondary=artists_albums,backref=db.backref('album_results',lazy='dynamic'),lazy='dynamic')


    def __repr__(self):
        return (self.album)


############################
##### HELPER FUNCTIONS #####
############################

def get_album(album_searched):
    results = spotify.search(q='album:' + album_searched, type='album')
    album_result = results['albums']['items'][0]['name']

    return album_result 

def get_album_artist(album_searched):
    results = spotify.search(q='album:' + album_searched, type='album')
    artist_result = results['albums']['items'][0]['artists']

    return artist_result 

def get_or_create_artistlist(artist_searched):
    artist_name = ArtistList.query.filter_by(artist=artist_searched).first()
    if not artist_name:
        artist_name = ArtistList(artist=artist_searched)
        db.session.add(artist_name)
        db.session.commit()
    return artist_name

def get_or_create_album(album_and_artist):
    album = album_and_artist.album
    artist = album_and_artist.artist
    album_and_artist = AlbumResults.query.filter_by(album=album).filter_by(artist=artist).first()

    if not album_and_artist:
        album_and_artist = AlbumResults(album = album, artist = artist)
        db.session.add(album_and_artist)
        db.session.commit()
    return album_and_artist

###################
###### FORMS ######
###################

##### Set up Forms #####

class RegistrationForm(FlaskForm):
    email = StringField('Email:', validators=[Required(),Length(1,64),Email()])
    username = StringField('Username:',validators=[Required(),Length(1,64),Regexp('^[A-Za-z][A-Za-z0-9_.]*$',0,'Usernames must have only letters, numbers, dots or underscores')])
    password = PasswordField('Password:',validators=[Required(),EqualTo('password2',message="Passwords must match")])
    password2 = PasswordField("Confirm Password:",validators=[Required()])
    submit = SubmitField('Register User')

    def validate_email(self,field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

    def validate_username(self,field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already taken')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[Required(), Length(1,64), Email()])
    password = PasswordField('Password', validators=[Required()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')


# add artist list form
class artistlistform(FlaskForm):
    artist = StringField('Add an artist to the list:', validators=[DataRequired()])
    submit = SubmitField()
    def validate_artist(self, field):
        if len(field.data) > 10:
            raise ValidationError("Artist to add to list must be less than 10 characters")

# artist search form    
class artistsearchform(FlaskForm):
    artist = StringField('Search for an artist on Spotify:', validators=[DataRequired()])
    rating = FloatField("Rate this artist:", validators = [Required()])
    submit = SubmitField()
    def validate_artist(self, field):
        if len(field.data) > 20:
            raise ValidationError("Artist search term must be less than 20 characters")

# album search form    
class albumsearchform(FlaskForm):
    album = StringField('Search for an album on Spotify:', validators=[DataRequired()])
    submit = SubmitField()
    def validate_artist(self, field):
        if len(field.data) > 20:
            raise ValidationError("Album search term must be less than 20 characters")

# update button
class UpdateButtonForm(FlaskForm):
    submit = SubmitField("Update")

# update rating
class UpdateRating(FlaskForm):
    newrating = StringField("What is the new rating of this artist?", validators=[Required()])
    submit = SubmitField("Update")

# delete
class DeleteButtonForm(FlaskForm):
    submit = SubmitField("Delete")


#######################
####### ROUTES/ ####### 
###### VIEW FXNS #####
#######################

## login-related routes ##
@app.route('/login',methods=["GET","POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            return redirect(request.args.get('next') or url_for('index'))
        flash('Invalid username or password.')
    return render_template('login.html',form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out')
    return redirect(url_for('index'))

@app.route('/register',methods=["GET","POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data,username=form.username.data,password=form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('You can now log in!')
        return redirect(url_for('login'))
    return render_template('register.html',form=form)

## OTHER ROUTES ##

# index
@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    return render_template('index.html')

## ARTIST LIST THINGS ##

# add artist to list
@app.route('/artistadd', methods = ['GET','POST'])
@login_required
def artist_form():
    form = artistlistform()
    if form.validate_on_submit():
        artist_searched = form.artist.data
        new_artist = get_or_create_artistlist(artist_searched)
        db.session.add(new_artist)
        db.session.commit()
        return redirect(url_for('all_artists'))
    return render_template('artistlistform.html', form=form)

# artists list
@app.route('/list')
@login_required
def all_artists():
    form = DeleteButtonForm()
    artists = ArtistList.query.all()
    return render_template('artistlist.html',artists=artists, form=form)

# delete artist from list
@app.route('/delete/<artists>',methods=["GET","POST"])
def delete(artists):
    artists = ArtistList.query.filter_by(artist=artists).first()
    db.session.delete(artists)
    db.session.commit()
    flash("Deleted list: " + artists.artist)
    return redirect(url_for('all_artists'))

# search artist
@app.route("/searchartist", methods = ['GET','POST'])
@login_required
def artist_search():
    form = artistsearchform()
    if form.validate_on_submit():
        artist_searched = (request.form['artist'])
        results = spotify.search(q='artist:' + artist_searched, type='artist')
        artistresult = results['artists']['items'][0]['name']
        useableartist = str(artistresult)
        rating = str((request.form['rating']))
    
        artistsubmit= ArtistResults(artist = useableartist, rating=rating)
        db.session.add(artistsubmit)
        db.session.commit()

        results = ArtistResults.query.all()

        return render_template('artistsearchform.html', form=form, results=results)
    return render_template('artistsearchform.html', form=form)

# search album
@app.route("/searchalbum", methods = ['GET','POST'])
@login_required
def album_search():
    form = albumsearchform()
    if form.validate_on_submit():

        #album name
        album_searched = (request.form['album'])
        album_result = get_album(album_searched)

        # artist of album
        artist_result = get_album_artist(album_searched)
        artistlist=[]
        for artist in artist_result:
            artistlist.append(artist['name']) #getting multiple artists, if any
       
        #result strings
        usablealbum = str(album_result)
        useableartist = str(artistlist)

        album_and_artist = AlbumResults(album = usablealbum, artist = useableartist)

        new_album_and_artist = get_or_create_album(album_and_artist)

        db.session.add(new_album_and_artist)
        db.session.commit()

        results = AlbumResults.query.all()

        return render_template('albumsearchform.html', form=form, results=results)
    return render_template('albumsearchform.html', form=form)

# all search results
@app.route('/results')
@login_required
def all_results():
    form = UpdateButtonForm()
    results = ArtistResults.query.all()
    return render_template('artistresults.html' ,results=results, form = form)

# update item
@app.route('/update/<artist>',methods=["GET","POST"])
def update(artist):
    form = UpdateRating()
    if form.validate_on_submit():
        artists = ArtistResults.query.filter_by(artist = artist).first()
        artists.rating = form.newrating.data
        db.session.commit()
        return redirect(url_for('all_results'))
    return render_template("updaterating.html", form=form, artist=artist)    
# error handler
@app.errorhandler(404) 
def page_not_found(e): 
    return render_template('404.html')

## Code to run the application...

if __name__ == '__main__':
    db.create_all()
    manager.run()