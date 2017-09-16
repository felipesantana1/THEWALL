from flask import Flask, render_template, redirect, request, flash, session
from mysqlconnection import MySQLConnector
import re, md5

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
PASSWORD1_REGEX = re.compile(r'[A-Z0-9]')
app = Flask(__name__)
mysql = MySQLConnector(app, 'loginRegDB')
app.secret_key = "ThisIsASecretKeepItThatWay"

@app.route('/')

def index():
    return render_template('index.html')

@app.route('/login', methods=['POST'])

def login():

    if len(request.form['email']) < 1:
        flash('YO put some shit in bro!', 'logError')
        return redirect('/')
    elif not EMAIL_REGEX.match(request.form['email']):
        flash('Invalid email/password address!', 'logError')
        return redirect('/')
    else:
        query = 'SELECT email FROM users WHERE email = :email'
        data = {

        'email':request.form['email']

        }
        if mysql.query_db(query, data) == []:
            flash('User not found, Please Register!', 'logError')
            return redirect('/')

    password = request.form['password']
    hash_password = md5.new(password).hexdigest()

    if len(request.form['password']) < 1:
        flash('type some shit in bro!')
        return redirect('/')
    elif not PASSWORD1_REGEX.match(request.form['password']):
        flash('Email/Password not valid', 'logError')
        return redirect('/')
    else:
        query1 = 'SELECT password, id FROM users WHERE email = :email'
        data1 = {
            
            'email': request.form['email']
            
            }

        check_pw = mysql.query_db(query1, data1)
        
        if check_pw[0]['password'] != hash_password:
            flash('Email/Password is invalid!', 'logError')
            return redirect('/')
        else:

            session['id'] = check_pw[0]['id']

            return redirect('/wall')

@app.route('/wall')

def renderWall():
    
    query = 'SELECT first_name FROM users WHERE id = :id'
    data = {

        'id': session['id']

    }

    user = mysql.query_db(query, data)
    
    loggedIn = 'Welcome to The Wall! ' + user[0]['first_name'] + ' Is Logged In!'

    query1 = "SELECT CONCAT(users.first_name , ' ' , users.last_name) as full_name, message, DATE_FORMAT(messages.created_at, '%r, %b, %D, %Y') AS posted_date, messages.id FROM users JOIN messages ON users.id = messages.user_id ORDER BY messages.created_at DESC"

    all_msg= mysql.query_db(query1)

    query2 = "SELECT CONCAT(users.first_name , ' ' , users.last_name) as full_name, comment, DATE_FORMAT(comments.created_at, '%r, %b, %D, %Y') AS posted_date, comments.message_id FROM users JOIN comments ON users.id = comments.user_id ORDER BY posted_date ASC"
    all_comments = mysql.query_db(query2)


    return render_template('wall.html', loggedIn = loggedIn, all_msg = all_msg, all_comments = all_comments)

@app.route('/comments/<msg_id>', methods=["POST"])

def storeComment(msg_id):
    query = "INSERT INTO comments (comment, created_at, updated_at, user_id, message_id) VALUES (:comment, NOW(), NOW(), :user_id, :message_id )"
    data = {
        "comment": request.form['comment'],
        "message_id": msg_id,
        "user_id": session['id']
    }
    mysql.query_db(query,data)
    return redirect('/wall')

@app.route('/msg', methods=["POST"])

def storeMessage():
    
    query = "INSERT INTO messages (message, created_at, updated_at, user_id) VALUES (:message, NOW(), NOW(), :id)"
    data = {
        'message': request.form['text'],
        'id': session['id']
    }   
    author = mysql.query_db(query, data)


    return redirect('/wall')

@app.route('/register', methods=['POST'])

def register():

    password = request.form['password']
    hash_password = md5.new(password).hexdigest()

    query = 'SELECT email FROM users WHERE email = :email'
    data = {

        'email': request.form['email']
    }


    if len(request.form['first_name']) < 1:
        flash('Must fill out all text areas!', 'regError')
        return redirect('/')

    if len(request.form['last_name']) < 1:
        flash('Must fill out all text areas!', 'regError')
        return redirect('/')

    if len(request.form['email']) < 1:
        flash('Must fill out all text areas!', 'regError')
        return redirect('/')

    elif not EMAIL_REGEX.match(request.form['email']):
        flash('Invalid email address!', 'regError')
        return redirect('/')
    else:
        query = 'SELECT email FROM users WHERE email = :email'
        data = {

        'email': request.form['email']
        
        }
        if mysql.query_db(query, data) != []:
            flash('User already exists', 'regError')
            return redirect('/')

    if len(password) < 1:
        flash('Must fill out all text areas!', 'regError')
        return redirect('/')

    elif len(password) < 1:
        flash('Must fill out all text areas!', 'regError')
        return redirect('/')

    elif str(password) != str(request.form['password1']):
        flash('Passwords must match!', 'regError')
        return redirect('/')

    elif len(password) < 8:
        flash('Password must be at least 8 characters', 'regError')
        return redirect('/')

    elif not PASSWORD1_REGEX.match(request.form['password']):
        flash('Password must contain lowercase, uppercase, number', 'regError')
        return redirect('/')

    else:
        query = 'INSERT INTO users (first_name, last_name, email, password, created_at, updated_at) VALUES (:first_name, :last_name, :email, :password, NOW(), NOW())'
        data = {
            'first_name' : request.form['first_name'],
            'last_name' : request.form['last_name'],
            'email' : request.form['email'],
            'password' : hash_password
            }
        session['id'] = mysql.query_db(query,data)
         

    return redirect('/wall')

@app.route('/logout', methods=["POST"])

def logout():
    session.clear()
    return redirect('/')

@app.route('/delete/<msg_id>', methods=['POST'])

def deleteMsg(msg_id):

    query = 'SELECT messages.user_id FROM messages WHERE id = :id'
    data = {

        "id": msg_id
        
    }

    delete_if = mysql.query_db(query,data)
    print delete_if
    if session['id'] == delete_if[0]['user_id']:

        query = "DELETE FROM messages WHERE id = :message_id"
        data = {
            
            'message_id': msg_id 
            
        }
        mysql.query_db(query, data)
    else:
        flash('Cannot delete another users Post!','wallError')
    return redirect('/wall')

app.run(debug=True)