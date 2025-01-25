# app.py
from flask import Flask, request, jsonify
from flask_cors import CORS
import bcrypt
import jwt
import json
import datetime
import os
from dotenv import load_dotenv
from auth import token_required
import logging
import datetime
import json
import random
from pathlib import Path
import re
import json
from markupsafe import escape


from datetime import timedelta

# app.py (additional imports)
from flask import Flask, request, jsonify
from flask_migrate import Migrate
import requests  # To interact with DeepSeek API
from models import db, User, ChatSession, ChatMessage, ReportCard
import os
from dotenv import load_dotenv
import uuid
from utils import get_ai_response, evaluate_user_skills, parse_evaluation_result


from models import db, User  # Import the SQLAlchemy instance and User model

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Enable CORS
CORS(app, supports_credentials=True)

# Configure Flask app
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your_default_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///social-flow.db'  # SQLite database
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# app.py (after load_dotenv())
INITIAL_PROMPT = os.getenv('INITIAL_PROMPT')
SCENARIO_PROMPT = os.getenv('SCENARIO_PROMPT')

# Define the path to the scenarios.json file
SCENARIOS_FILE_PATH = Path(__file__).parent / 'scenario.json'


# Initialize SQLAlchemy with the app
db.init_app(app)
migrate = Migrate(app, db)




# Set up logging
logger = logging.getLogger('flask_app')
logger.setLevel(logging.DEBUG)  # Set the desired logging level

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
# Add handler if needed, e.g., StreamHandler or FileHandler
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logger.addHandler(handler)


# Load scenarios from the JSON file at startup
try:
    with open(SCENARIOS_FILE_PATH, 'r') as file:
        SCENARIOS = json.load(file)
        logger.info(f"Loaded {len(SCENARIOS)} scenarios from scenarios.json.")
except FileNotFoundError:
    logger.error(f"scenarios.json file not found at {SCENARIOS_FILE_PATH}.")
    SCENARIOS = []
except json.JSONDecodeError as e:
    logger.error(f"Error decoding JSON from scenarios.json: {e}")
    SCENARIOS = []





# Handle the OPTIONS request manually to avoid 404 errors
@app.before_request
def handle_options_request():
    if request.method == 'OPTIONS':
        response = app.make_default_options_response()
        headers = None
        if 'ACCESS_CONTROL_REQUEST_HEADERS' in request.headers:
            headers = {
                'Access-Control-Allow-Headers': request.headers['ACCESS_CONTROL_REQUEST_HEADERS']
            }
        h = response.headers
        h.update(headers or {})
        return response

# Registration API endpoint
@app.route('/api/auth/register/', methods=['POST', 'OPTIONS'])
def register():
    if request.method == 'OPTIONS':
        # Allow the preflight OPTIONS request
        return '', 200

    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"error": "Missing email or password"}), 400

    # Check if user with the same email already exists
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({"error": "Email already registered"}), 409

    # Hash the password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Create a new user instance
    new_user = User(
        email=email,
        password=hashed_password
    )

    try:
        # Add and commit the new user to the database
        db.session.add(new_user)
        db.session.commit()

        # Generate JWT token
        token = jwt.encode({
            'email': email,
            'exp': datetime.datetime.utcnow() + timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm='HS256')

        # Return success message along with the token
        return jsonify({"message": "User created successfully", "token": token}), 201
    except Exception as e:
        logger.error(f"Error registering user: {e}")
        db.session.rollback()
        return jsonify({"error": "Internal server error"}), 500

# Health check route
@app.route('/api/health/', methods=['GET'])
def health_check():
    return jsonify({"message": "Server is running"}), 200

# Login API endpoint
@app.route('/api/auth/login/', methods=['POST', 'OPTIONS'])
def login():
    if request.method == 'OPTIONS':
        # Handle preflight OPTIONS request
        return '', 200

    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"error": "Missing email or password"}), 400

    # Find user by email
    user = User.query.filter_by(email=email).first()

    # Check if user exists and if the password matches
    if user and bcrypt.checkpw(password.encode('utf-8'), user.password):
        # Generate a token
        token = jwt.encode({
            'email': email,
            'exp': datetime.datetime.utcnow() + timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm='HS256')

        # Return login success message along with the token
        return jsonify({"message": "Login successful", "token": token}), 200
    else:
        return jsonify({"error": "Invalid credentials"}), 401

# Example protected route
@app.route('/api/protected/', methods=['GET'])
@token_required
def protected_route(current_user):
    return jsonify({"message": f"Hello, {current_user.email}!"}), 200




# app.py (continued)

@app.route('/api/chat/sessions/', methods=['POST'])
@token_required
def create_chat_session(current_user):
    try:
        # 1. Create a new ChatSession
        new_session = ChatSession(user_id=current_user.id)
        db.session.add(new_session)
        db.session.commit()

        # 2. Select a random scenario from the loaded scenarios
        if not SCENARIOS:
            logger.error("No scenarios available to select.")
            return jsonify({"error": "No scenarios available. Please contact support."}), 500

        selected_scenario = random.choice(SCENARIOS)['scenario']
        logger.info(f"Selected Scenario: {selected_scenario}")

        # 3. Format the INITIAL_PROMPT with the selected scenario
        formatted_initial_prompt = INITIAL_PROMPT.format(custom_scenario=selected_scenario)
        logger.info(f"Formatted Initial Prompt: {formatted_initial_prompt}")

        # 4. Save the formatted system message with the custom scenario
        system_message = ChatMessage(
            session_id=new_session.id,
            sender='system',
            content=formatted_initial_prompt
        )
        db.session.add(system_message)
        db.session.commit()

        # 5. Prepare messages for AI (including the formatted system message)
        messages = [
            {"role": "system", "content": formatted_initial_prompt}
        ]

        # 6. Get AI response to the initial prompt
        ai_response = get_ai_response(messages)
        logger.info(f"AI Response: {ai_response}")

        # 7. Save AI response
        ai_msg = ChatMessage(
            session_id=new_session.id,
            sender='assistant',
            content=ai_response
        )
        db.session.add(ai_msg)
        db.session.commit()

        return jsonify({
            "message": "Chat session created successfully",
            "session_id": new_session.id,
            "ai_response": ai_msg.content,
            "custom_scenario": selected_scenario  # Optional: Return the scenario to the user
        }), 201

    except Exception as e:
        logger.error(f"Error creating chat session: {e}")
        db.session.rollback()
        return jsonify({"error": "Internal server error"}), 500

# app.py (add below existing routes)

# app.py (continued)

@app.route('/api/chat/sessions/<session_id>/messages/', methods=['POST'])
@token_required
def send_chat_message(current_user, session_id):
    data = request.get_json()
    user_message = data.get('message')

    if not user_message:
        return jsonify({"error": "Missing 'message' in request"}), 400

    # Sanitize user message
    user_message = escape(user_message)

    # Retrieve the chat session
    session = ChatSession.query.filter_by(id=session_id, user_id=current_user.id).first()
    if not session:
        return jsonify({"error": "Chat session not found"}), 404

    # Check if a ReportCard already exists for this session
    if session.report_card:
        return jsonify({"error": "This session has already been evaluated."}), 400

    try:
        # Save user message
        user_msg = ChatMessage(
            session_id=session.id,
            sender='user',
            content=user_message
        )
        db.session.add(user_msg)
        db.session.commit()

        # Retrieve all user messages in the session
        user_messages = [
            msg.content for msg in session.messages if msg.sender == 'user'
        ]

        # Count the number of user messages
        user_message_count = len(user_messages)

        # If user has sent less than 10 messages, continue the chat
        if user_message_count < 10:
            # Retrieve all messages in the session to send to AI (excluding system messages)
            messages = [
                {"role": msg.sender, "content": msg.content}
                for msg in session.messages
                if msg.sender in ['user', 'assistant']
            ]

            # Prepend the system message for context
            messages.insert(0, {"role": "system", "content": INITIAL_PROMPT})

            # Optionally, limit to the last N messages for context
            MAX_MESSAGES = 20
            if len(messages) > MAX_MESSAGES:
                messages = messages[-MAX_MESSAGES:]

            # Get AI response
            ai_response = get_ai_response(messages)

            # Save AI response
            ai_msg = ChatMessage(
                session_id=session.id,
                sender='assistant',
                content=ai_response
            )
            db.session.add(ai_msg)
            db.session.commit()

            return jsonify({
                "user_message": user_msg.content,
                "ai_response": ai_msg.content
            }), 200

        elif user_message_count == 10 or user_message_count > 10:
            # Trigger evaluation
            evaluation_result = evaluate_user_skills(user_messages)

            # Parse the AI's response
            evaluation_data = parse_evaluation_result(evaluation_result)

            logger.info(f"Evaluation ===> {evaluation_data}")

            # Assign default values if parsing failed
            score = evaluation_data.get('total_score', 0)
            feedback = ""
            # Combine all feedbacks
            if evaluation_data.get('feedback', None):
                feedback += f"**Feedback:** {evaluation_data['feedback']}\n\n"
            if evaluation_data.get('engagement_feedback', None):
                feedback += f"**Engagement:** {evaluation_data['engagement_feedback']}\n\n"
            if evaluation_data.get('humor_feedback', None):
                feedback += f"**Humor:** {evaluation_data['humor_feedback']}\n\n"
            if evaluation_data.get('empathy_feedback', None):
                feedback += f"**Empathy:** {evaluation_data['empathy_feedback']}\n\n"

            if not feedback:
                feedback = "There was an error evaluating your performance."

            # Save the evaluation in ReportCard
            report_card = ReportCard(
                session_id=session.id,
                user_id=current_user.id,
                engagement_score=evaluation_data.get('engagement_score'),
                humor_score=evaluation_data.get('humor_score'),
                empathy_score=evaluation_data.get('empathy_score'),
                total_score=evaluation_data.get('total_score'),
                engagement_feedback=evaluation_data.get('engagement_feedback'),
                humor_feedback=evaluation_data.get('humor_feedback'),
                empathy_feedback=evaluation_data.get('empathy_feedback'),
                feedback = evaluation_data.get('feedback')
            )
            db.session.add(report_card)
            db.session.commit()

            return jsonify({
                "user_message": user_msg.content,
                "ai_response": "You have completed the game! Your performance has been evaluated.",
                "evaluation": {
                    "engagement_score": report_card.engagement_score,
                    "engagement_feedback": report_card.engagement_feedback,
                    "humor_score": report_card.humor_score,
                    "humor_feedback": report_card.humor_feedback,
                    "empathy_score": report_card.empathy_score,
                    "empathy_feedback": report_card.empathy_feedback,
                    "total_score": report_card.total_score,
                    "feedback_summary": feedback,
                    "feedback": feedback
                }
            }), 200

        else:
            # More than 10 messages; prevent further messages or allow based on requirements
            return jsonify({"error": "This session has already been evaluated."}), 400

    except Exception as e:
        logger.error(f"Error handling chat message: {e}")
        db.session.rollback()
        return jsonify({"error": "Internal server error"}), 500



@app.route('/api/chat/sessions/<session_id>/report_card/', methods=['GET'])
@token_required
def get_report_card(current_user, session_id):
    # Retrieve the chat session
    session = ChatSession.query.filter_by(id=session_id, user_id=current_user.id).first()
    if not session:
        return jsonify({"error": "Chat session not found"}), 404

    # Retrieve the report card
    report_card = ReportCard.query.filter_by(session_id=session.id, user_id=current_user.id).first()
    if not report_card:
        return jsonify({"error": "Report card not found for this session."}), 404

    return jsonify({
        "score": report_card.score,
        "feedback": report_card.feedback,
        "created_at": report_card.created_at.isoformat()
    }), 200



@app.route('/api/report-cards/', methods=['GET'])
@token_required
def get_all_report_cards(current_user):
    try:
        # Retrieve all report cards for the current user where total_score is not null
        report_cards = ReportCard.query.filter(
            ReportCard.user_id == current_user.id,
            ReportCard.total_score.isnot(None)
        ).all()
        
        # Serialize report cards
        report_cards_data = []
        for rc in report_cards:
            report_cards_data.append({
                "session_id": rc.session_id,
                "engagement_score": rc.engagement_score,
                "engagement_feedback": rc.engagement_feedback,
                "humor_score": rc.humor_score,
                "humor_feedback": rc.humor_feedback,
                "empathy_score": rc.empathy_score,
                "empathy_feedback": rc.empathy_feedback,
                "feedback": rc.feedback,
                "total_score": rc.total_score,
                "created_at": rc.created_at.isoformat()
            })
        
        return jsonify({"report_cards": report_cards_data}), 200
    
    except Exception as e:
        logger.error(f"Error retrieving report cards: {e}")
        return jsonify({"error": "Internal server error"}), 500


# Run the app
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create tables if they don't exist
    app.run(debug=True)
