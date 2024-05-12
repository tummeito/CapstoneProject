import os
from flask import Flask, render_template, request, redirect, url_for, make_response, jsonify, abort
from flask_mysqldb import MySQL
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
# from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required
import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask_cors import CORS, cross_origin
import re
app = Flask(__name__)
# jwt = JWTManager(app)
app.config['JWT_SECRET_KEY'] = 'your-secret-key'  # Replace with a secure secret key
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = False  # You can configure token expiration
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = False  # or use timed expiration

app.secret_key = 'your secret key'

app.config['MYSQL_HOST'] = 'tummeito.mysql.pythonanywhere-services.com'
app.config['MYSQL_USER'] = 'tummeito'
app.config['MYSQL_USERNAME'] = 'tummeito'
app.config['MYSQL_PASSWORD'] = 'tummeitopassworddb'
app.config['MYSQL_DB'] = 'tummeito$capstoneproject'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

app.config['SQLALCHEMY_DATABASE_URI'] = "mysql://tummeito:@tummeito.mysql.pythonanywhere-services.com/tummeito$capstoneproject"

app.config['MAX_CONTENT_LENGTH'] = 4096 * 4096
app.config['UPLOAD_EXTENSIONS'] = ['.jpg', '.png', '.gif']
app.config['UPLOAD_PATH'] = 'uploads'

CORS(app, supports_credentials=True, allow_headers=["*"])

mysql = MySQL(app)

#Setting up User Model
db = SQLAlchemy(app)

class User(db.Model):
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)


# Default statement setting up database

@app.route('/')
def index():
    try:
        # Creating a connection cursor
        cursor = mysql.connection.cursor()

        # Executing SQL Statements
        cursor.execute(''' CREATE TABLE IF NOT EXISTS user_table (user_id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(80) UNIQUE NOT NULL, password VARCHAR(120) NOT NULL) ''')
        cursor.execute(''' INSERT IGNORE INTO user_table(username, password) VALUES ('admin', 'password') ''')

        # Saving the actions performed on the DB
        mysql.connection.commit()

        # Closing the cursor
        cursor.close()

        return "Database operations successful"

    except Exception as e:
        return f"An error occurred: {str(e)}"

# Token authenticator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # jwt is passed in the request header
        if 'Authorization' in request.headers:
            token = request.headers['Authorization']
        # return 401 if token is not passed
        if not token:
            return jsonify({'message' : 'Token is missing !!'}), 401
  
        try:
            # decoding the payload to fetch the stored details
            # return jsonify({'token':token})
            data = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
            current_user = data['username']
        except:
            return jsonify({
                'message' : 'Token is invalid !!',
                'token': token
            }), 401
        # returns the current logged in users context to the routes
        return  f(current_user, *args, **kwargs)
  
    return decorated

# Get all users endpoint

@app.route('/users', methods=['GET'])
def get_all_users():
    cursor = mysql.connection.cursor()
    cursor.execute(''' SELECT * FROM user_table''')
    results = cursor.fetchall()
    output = []
    for user in results:
        output.append({
            'user_id': user['user_id'],
            'username': user['username'],
            'password': user['password']
        })
    cursor.close()
    return jsonify(output)

# Add new user to table endpoint

@app.route('/users', methods=['POST'])
def create_user():
    cursor = mysql.connection.cursor()
    try:
        msg = ''
        new_username = request.json['username']
        new_password = request.json['password']
        cursor.execute('SELECT * FROM user_table WHERE username = %s', (new_username,))
        account = cursor.fetchone()
        if account:
            msg = "User has already been registered"
            mysql.connection.commit()
            cursor.close()
            return({'message': msg}), 401

        else:
            msg = "New user added"
            cursor.execute(''' INSERT IGNORE INTO user_table(username, password) VALUES(%s, %s)''' , (new_username, new_password))
            mysql.connection.commit()
            cursor.close()
            return jsonify({'message': msg}), 200

            
    except:
        cursor.close()
        return jsonify({'error': 'Invalid operations'}), 401
    

# Get a user endpoint

@app.route('/users/<string:username>', methods=['GET'])
def get_user(username):
    cursor = mysql.connection.cursor()
    cursor.execute(''' SELECT * FROM user_table WHERE username=%s ''', (username,))
    result = cursor.fetchone()
    cursor.close()
    if result:
        return jsonify(result)
    else:
        return jsonify({'error': 'User not found'})

# Update user endpoint

@app.route('/users/<string:username>', methods=['POST'])
def update_user(username):
    try:
        cursor = mysql.connection.cursor()
        new_username = request.json['username']
        new_password = request.json['password']
        cursor.execute(''' UPDATE user_table SET username=%s, password=%s WHERE username=%s''', (new_username, new_password, username,))
        mysql.connection.commit()
        cursor.close()
        return jsonify({'message': 'User updated!!'})
    except:
        cursor.close()
        return jsonify({'error': 'Invalid operations'}), 401
        

# Delete user from table endpoint

@app.route('/users/<string:username>', methods=['DELETE'])
def delete_user(username):
    try:
        cursor = mysql.connection.cursor()
        cursor.execute(''' DELETE FROM user_table WHERE username=%s ''', (username,))
        mysql.connection.commit()
        cursor.close()
        return jsonify({'message': 'User deleted'})
    except:
        cursor.close()
        return jsonify({'error': 'Invalid operations'}), 401


#Log in endpoint
@cross_origin
@app.route('/login', methods =['GET', 'POST'])
def login():
    msg = ''
    # if (request.method == 'POST' and 'username' in request.form and
    #    'password' in request.form):
    if (request.method == 'POST'):
       username = request.json["username"]
       password = request.json['password']
       cursor = mysql.connection.cursor()
       cursor.execute('SELECT * FROM user_table WHERE username = %s AND password = %s', (username, password,))
       account = cursor.fetchone()

       if account:
           msg = 'Success'
           token = jwt.encode({
               'username': username,
               'exp': datetime.utcnow() + timedelta(minutes = 60)
           }, app.config['JWT_SECRET_KEY'])
           return jsonify({'token' : jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256']),
                           'encoded_token' : token,
                           'message' : msg}), 200
       else:
           msg = 'Incorrect username or password !'
           return jsonify({'message' : msg}), 401
    else:
        msg = 'User not found'
        return jsonify({'message' : msg}), 401

# Error handler for HTTP 400 (Bad Request)
@app.errorhandler(400)
def bad_request(error):
    return jsonify(error='Error 400: Bad Request'), 400

# Error handler for HTTP 401 (Unauthorized)
@app.errorhandler(401)
def unauthorized(error):
    return jsonify(error='Error 401: Unauthorized'), 401

# Error handler for HTTP 404 (Not Found)
@app.errorhandler(404)
def not_found(error):
    return jsonify(error='Error 404: Not Found'), 404

# Error handler for HTTP 500 (Internal Server Error)
@app.errorhandler(500)
def internal_server_error(error):
    return jsonify(error='Error 500: Internal Server Error'), 500

# Custom route to trigger errors for testing
@app.route('/trigger_error/<int:error_code>')
def trigger_error(error_code):
    if error_code == 400:
        return 'Triggering a 400 error', 400
    elif error_code == 401:
        return 'Triggering a 401 error', 401
    elif error_code == 404:
        return 'Triggering a 404 error', 404
    elif error_code == 500:
        raise Exception('Triggering a 500 error')
    else:
        return 'No error triggered'

if __name__ == '__main__':
    app.run(debug=True)

