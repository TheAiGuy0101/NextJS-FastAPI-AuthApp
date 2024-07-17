from flask import Flask, redirect, request, session, jsonify, url_for
from flask_cors import CORS
from google_auth_oauthlib.flow import Flow as GoogleFlow
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import os
from pymongo import MongoClient
from bson.objectid import ObjectId
import requests
import bcrypt

app = Flask(__name__)
CORS(app, supports_credentials=True)
app.secret_key = 'your_secret_key'  # Replace with a real secret key

# MongoDB setup
client = MongoClient('mongodb://localhost:27017/')
db = client['auth_db']
users_collection = db['users']

@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    user_id = data.get('user_id')
    password = data.get('password')

    if not user_id or not password:
        return jsonify({'error': 'User ID and password are required'}), 400

    existing_user = users_collection.find_one({'user_id': user_id})
    if existing_user:
        return jsonify({'error': 'User ID already exists'}), 400

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    new_user = {
        'user_id': user_id,
        'password': hashed_password,
        'auth_provider': 'custom'
    }
    result = users_collection.insert_one(new_user)
    
    session['user_id'] = str(result.inserted_id)
    return jsonify({'message': 'User created successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user_id = data.get('user_id')
    password = data.get('password')

    if not user_id or not password:
        return jsonify({'error': 'User ID and password are required'}), 400

    user = users_collection.find_one({'user_id': user_id})
    if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password']):
        return jsonify({'error': 'Invalid credentials'}), 401

    session['user_id'] = str(user['_id'])
    return jsonify({'message': 'Logged in successfully'})

# Google OAuth setup
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # For development only
GOOGLE_SCOPES = ['openid', 'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile']
google_flow = GoogleFlow.from_client_secrets_file(
    'client_secrets.json',
    scopes=GOOGLE_SCOPES,
    redirect_uri='http://localhost:5000/google/callback'
)

# Facebook OAuth setup
FACEBOOK_APP_ID = '1169934434131676'
FACEBOOK_APP_SECRET = '693fc00815ca6dff2be62e8b9b9ef4ae'

@app.route('/google/login')
def google_login():
    authorization_url, state = google_flow.authorization_url()
    session['state'] = state
    return redirect(authorization_url)

@app.route('/google/callback')
def google_callback():
    try:
        google_flow.fetch_token(authorization_response=request.url)
        credentials = google_flow.credentials
        id_info = id_token.verify_oauth2_token(
            credentials.id_token, google_requests.Request(), credentials.client_id)

        google_id = id_info['sub']
        email = id_info['email']
        name = id_info.get('name', '')

        user = get_or_create_user('google', google_id, email, name)
        session['user_id'] = str(user['_id'])
        return redirect('http://localhost:3000/profile')
    except Exception as e:
        print(f"Error in Google callback: {str(e)}")
        return jsonify({'error': 'Authentication failed'}), 400

@app.route('/facebook/login')
def facebook_login():
    redirect_uri = url_for('facebook_callback', _external=True)
    return redirect(f'https://www.facebook.com/v12.0/dialog/oauth?client_id={FACEBOOK_APP_ID}&redirect_uri={redirect_uri}&scope=email')

@app.route('/facebook/callback')
def facebook_callback():
    if 'error' in request.args:
        return jsonify({'error': request.args['error_description']}), 400

    code = request.args.get('code')
    redirect_uri = url_for('facebook_callback', _external=True)
    
    # Exchange code for access token
    token_url = f'https://graph.facebook.com/v12.0/oauth/access_token'
    token_payload = {
        'client_id': FACEBOOK_APP_ID,
        'redirect_uri': redirect_uri,
        'client_secret': FACEBOOK_APP_SECRET,
        'code': code
    }
    token_response = requests.get(token_url, params=token_payload)
    access_token = token_response.json().get('access_token')

    if not access_token:
        return jsonify({'error': 'Failed to obtain access token'}), 400

    # Get user info
    user_info_url = 'https://graph.facebook.com/me'
    user_info_payload = {
        'fields': 'id,name,email',
        'access_token': access_token
    }
    user_info = requests.get(user_info_url, params=user_info_payload).json()

    facebook_id = user_info['id']
    email = user_info.get('email', f"{facebook_id}@placeholder.com")
    name = user_info.get('name', '')

    user = get_or_create_user('facebook', facebook_id, email, name)
    session['user_id'] = str(user['_id'])
    return redirect('http://localhost:3000/profile')

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user = get_user_by_id(session['user_id'])
    if user:
        return jsonify({
            'message': 'You are logged in and can access your profile information here.',
            'name': user.get('name', 'N/A'),
            'email': user.get('email', 'N/A'),
            'auth_provider': user.get('auth_provider', 'N/A')
        })
    else:
        return jsonify({'error': 'User not found'}), 404

@app.route('/logout')
def logout():
    session.clear()
    return jsonify({'message': 'Logged out successfully'})

def get_or_create_user(auth_provider, provider_id, email, name):
    user = users_collection.find_one({f'{auth_provider}_id': provider_id})
    if user is None:
        user = {
            f'{auth_provider}_id': provider_id,
            'email': email,
            'name': name,
            'auth_provider': auth_provider
        }
        result = users_collection.insert_one(user)
        user['_id'] = result.inserted_id
    return user

def get_user_by_id(user_id):
    return users_collection.find_one({'_id': ObjectId(user_id)})

if __name__ == '__main__':
    app.run(debug=True)