from flask import Flask, render_template, flash, redirect, url_for, session, request, logging, jsonify
from wtforms import Form, StringField, TextAreaField, PasswordField, validators, SelectField
from flask_recaptcha import ReCaptcha
from passlib.hash import sha256_crypt
from flask_googlemaps import GoogleMaps
import os
import urllib.request
import ssl
import simplejson as json
import requests
#from google.cloud import storage
import firebase_admin
from firebase_admin import credentials
from firebase_admin import firestore
from google.transit import gtfs_realtime_pb2 #Experimental code
from math import sin, cos, sqrt, atan2, radians, inf
from google.cloud import datastore

app = Flask(__name__)


SECRET_KEY = os.urandom(32)
app.config['SECRET_KEY'] = SECRET_KEY
#config firestore
# Use the application default credentials
cred = credentials.Certificate('firestoredemo-c3174-02794d56d4e5.json')
firebase_admin.initialize_app(cred)

db = firestore.client()



class RegisterationForm(Form):
    name= StringField('Name', [validators.Length(min=1, max=50)])
    username = StringField('Username', [validators.Length(min=4, max=25)])
    email = StringField('Email', [validators.Length(min=6, max=50)])
    password = PasswordField('Password', [validators.DataRequired(), validators.EqualTo('confirm', message='Pasword do not match')])
    confirm = PasswordField('Confirm Password')





@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterationForm(request.form)
    print('Hi')
    if request.method == 'POST' and form.validate():
        print('Ok')
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.hash(str(form.password.data))
        print('SUCCESS')


            #------------------------Firestore--------------------------------------------------------------#
        doc_ref = db.collection(u'users').document(username)
        doc_ref.set({
            u'name': name,
            u'email': email,
            u'username': username,
            u'password': password
        })
            #------------------------Firestore--------------------------------------------------------------#

        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        #get form fields
        username = request.form['username']
        password_candidate = request.form['password']



        #-------------------firestore-------------------------------------#
        users_ref = db.collection(u'users')
        docs = users_ref.get()
        for doc in docs:
            doc_dict = doc.to_dict();
            if doc_dict['username'] == username:
                print('User exist!!')
                password = doc_dict['password']
                if sha256_crypt.verify(password_candidate, password):
                    #Passed
                    print('Password Matched')
                    session['logged_in'] = True
                    session['username'] = username
                    flash('you are now logged in', 'success')
                    return redirect(url_for('dashboard'))
                else:
                    error = 'Invalid Login'
                    return render_template('login.html', error=error)

        error = 'Username not found'
        return render_template('login.html', error=error)

        #-------------------firestore-------------------------------------#
        #-------------------datastore-------------------------------------#
        print('Username', username)
        query = datastore_client.query(kind='username')
        print(query)
        results = list(query.fetch(limit=100))
        print(results)
        for result in results:
            if result['username'] == username:
                print('User exist')
                password = result['password']
                if sha256_crypt.verify(password_candidate, password):
                #Passed
                    print('Password Matched')
                    session['logged_in'] = True
                    session['username'] = username
                    return redirect(url_for('dashboard'))
                else:
                    return render_template('login.html')
        error = 'Username not found'
        return render_template('login.html', error=error)
        #-------------------datastore-------------------------------------#
    return render_template('login.html')

@app.route('/')
def index():
    return render_template('home.html')


if __name__ == '__main__':
    print("hello World!")
    app.run(debug=True)
