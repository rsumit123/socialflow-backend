# auth.py

import jwt
from functools import wraps
from flask import request, jsonify
import os
from dotenv import load_dotenv
import logging

from models import db, User  # Import the SQLAlchemy instance and User model

# Load environment variables
load_dotenv()

# Retrieve the secret key from environment variables
secret_key = os.getenv('SECRET_KEY')
if not secret_key:
    raise ValueError("SECRET_KEY is not set in the environment variables.")

# Set up logging
logger = logging.getLogger('flask_auth')
logger.setLevel(logging.DEBUG)  # Set the desired logging level

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Add a StreamHandler if no handlers are present
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logger.addHandler(handler)

# Custom decorator for token-based authentication
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        # Check for token in headers
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
            logger.debug("Token found in 'x-access-token' header.")
        elif 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
                logger.debug("Token found in 'Authorization' header with Bearer scheme.")
            else:
                token = auth_header  # Assume token is provided directly
                logger.debug("Token found in 'Authorization' header without Bearer scheme.")
        else:
            logger.debug("No token found in headers.")
            return jsonify({'error': 'Token is missing!'}), 403

        # Return an error if token is missing
        if not token:
            logger.debug("Token is missing after header checks.")
            return jsonify({'error': 'Token is missing!'}), 403

        try:
            # Decode the token and get the user's email
            data = jwt.decode(token, secret_key, algorithms=['HS256'])
            logger.debug(f"Decoded token data: {data}")

            # Fetch the user from the database using SQLAlchemy
            current_user = User.query.filter_by(email=data['email']).first()
            logger.debug(f"Fetched user from database: {current_user}")

            if not current_user:
                logger.debug("No user found with the provided email.")
                return jsonify({'error': 'Invalid token!'}), 403

        except jwt.ExpiredSignatureError:
            logger.warning("Token has expired.")
            return jsonify({'error': 'Token has expired!'}), 403
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {e}")
            return jsonify({'error': 'Token is invalid!', 'message': str(e)}), 403
        except Exception as e:
            logger.error(f"Error decoding token: {e}")
            return jsonify({'error': 'Token is invalid!', 'message': str(e)}), 403

        # Pass the current_user to the decorated function
        return f(current_user, *args, **kwargs)
    
    return decorated
