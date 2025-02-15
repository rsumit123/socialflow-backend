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
INITIAL_PROMPT_V2 = os.getenv('INITIAL_PROMPT_V2')
SCENARIO_PROMPT = os.getenv('SCENARIO_PROMPT')
CLIENT_URL = os.getenv('CLIENT_URL')

# Define the path to the scenarios.json file
SCENARIOS_FILE_PATH = Path(__file__).parent / 'scenario.json'
ROLE_SCENARIO_FILE_PATH = Path(__file__).parent / 'role_scenario.json'


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
    with open(ROLE_SCENARIO_FILE_PATH, 'r') as file:
        ROLE_SCENARIOS = json.load(file)
        logger.info(f"Loaded {len(ROLE_SCENARIOS)} scenarios from scenarios.json.")
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


@app.route('/api/auth/guest/', methods=['POST', 'OPTIONS'])
def guest_login():
    if request.method == 'OPTIONS':
        # Handle preflight OPTIONS request
        return '', 200

    # Generate a unique guest identifier
    guest_id = str(uuid.uuid4())
    guest_email = f"guest_{guest_id}@example.com"
    
    # Optionally, if you want to store guest status on the user, you might add an 'is_guest' field
    # For now, we assume creating a new User record for each guest login.
    guest_user = User.query.filter_by(email=guest_email).first()
    if not guest_user:
        guest_user = User(email=guest_email, password=b"")
        # Set password empty or a default value
        # Optionally, if your model has an 'is_guest' flag:
        # guest_user.is_guest = True
        db.session.add(guest_user)
        db.session.commit()
    
    # Generate a JWT token that includes a 'guest' flag
    token = jwt.encode({
        'email': guest_email,
        'guest': True,
        'exp': datetime.datetime.utcnow() + timedelta(hours=24)
    }, app.config['SECRET_KEY'], algorithm='HS256')
    
    return jsonify({
        "message": "Guest login successful",
        "token": token
    }), 200


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
        # logger.info(f"Formatted Initial Prompt: {formatted_initial_prompt}")

        logger.info("Saving chat message..........")

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

        logger.info("Getting AI Response.......")

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



@app.route('/api/v2/chat/sessions/', methods=['POST'])
@token_required
def create_chat_session_v2(current_user):
    try:
        # 1. Create a new ChatSession
        new_session = ChatSession(user_id=current_user.id)
        db.session.add(new_session)
        db.session.commit()

        # 2. Select a random scenario from the loaded scenarios
        if not SCENARIOS:
            logger.error("No scenarios available to select.")
            return jsonify({"error": "No scenarios available. Please contact support."}), 500

        selected= random.choice(ROLE_SCENARIOS)
        selected_scenario, selected_role, ai_name  = selected["scenario"], selected["ai_role"], selected["ai_name"]
        logger.info(f"Selected Scenario: {selected_scenario}")

        # 3. Format the INITIAL_PROMPT with the selected scenario
        formatted_initial_prompt = INITIAL_PROMPT_V2.format(custom_role=selected_role, name=ai_name)

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
        logger.info("Getting AI Response.......")

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
    # if session.report_card:
    #     return jsonify({"error": "This session has already been evaluated."}), 400

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

        
        system_msg = [msg.content for msg in session.messages if msg.sender == 'system']

        system_msg = " ".join(system_msg)

        # logger.info(f" SYSTEM MESSAGE: {system_msg}")

        # Count the number of user messages
        user_message_count = len(user_messages)

        # Retrieve all messages in the session to send to AI (excluding system messages)
        messages = [
                {"role": msg.sender, "content": msg.content}
                for msg in session.messages
                if msg.sender in ['user', 'assistant']
            ]

        # logger.info(f"ALL MESSAGES {messages}")

        # Prepend the system message for context
        messages.insert(0, {"role": "system", "content": system_msg})

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


        # If user has sent less than 10 messages, continue the chat
        if user_message_count < 10 and not ('end chat' in user_message.lower() or 'end this chat' in user_message.lower()):
            
            return jsonify({
                "user_message": user_msg.content,
                "ai_response": ai_msg.content
            }), 200

        elif user_message_count == 10: 
            # Trigger evaluation
            ai_messages = [
                msg.content for msg in session.messages if msg.sender == 'assistant'
                ]

            prompt_to_send = [{"ai_message": i, "user_message": j} for i, j in zip(ai_messages, user_messages)]
            evaluation_result = evaluate_user_skills(prompt_to_send)

            # Parse the AI's response
            evaluation_data = parse_evaluation_result(evaluation_result)

            # logger.info(f"Evaluation ===> {evaluation_data}")

            feedback = evaluation_data.get('feedback', "Empty")

            engagement_score = evaluation_data.get('engagement_score', 0)
            empathy_score = evaluation_data.get('empathy_score', 0)
            humor_score = evaluation_data.get('humor_score', 0)
            total_score = sum([int(i) for i in [engagement_score, empathy_score, humor_score]])//3

            
            logger.info(f"engagement score {engagement_score} feedback {feedback}")

            # Save the evaluation in ReportCard
            report_card = ReportCard(
                session_id=session.id,
                user_id=current_user.id,
                engagement_score=int(engagement_score),
                humor_score=int(humor_score),
                empathy_score=int(empathy_score),
                total_score=total_score,
                engagement_feedback="",
                humor_feedback="",
                empathy_feedback="",
                feedback =feedback
            )
            db.session.add(report_card)
            db.session.commit()

            return jsonify({
                "user_message": user_msg.content,
                "ai_response": ai_msg.content,
                "evaluation": {
                    "engagement_score": report_card.engagement_score,
                    "engagement_feedback": report_card.engagement_feedback,
                    "humor_score": report_card.humor_score,
                    "humor_feedback": report_card.humor_feedback,
                    "empathy_score": report_card.empathy_score,
                    "empathy_feedback": report_card.empathy_feedback,
                    "total_score": report_card.total_score,
                    "feedback_summary": feedback,
                    "feedback": feedback,
                    "report_link": f"{CLIENT_URL}/report-cards/{session_id}"
                }
            }), 200

        elif 'end chat' in user_message.lower() or 'end this chat' in user_message.lower():

            ai_messages = [
                msg.content for msg in session.messages if msg.sender == 'assistant'
                ]

            prompt_to_send = [{"ai_message": i, "user_message": j} for i, j in zip(ai_messages, user_messages)]
            evaluation_result = evaluate_user_skills(prompt_to_send)

            # Parse the AI's response
            evaluation_data = parse_evaluation_result(evaluation_result)

            logger.info(f"Evaluation ===> {evaluation_data}")

            feedback = evaluation_data.get('feedback', "Empty")

            engagement_score = evaluation_data.get('engagement_score', 0)
            empathy_score = evaluation_data.get('empathy_score', 0)
            humor_score = evaluation_data.get('humor_score', 0)
            total_score = sum([int(i) for i in [engagement_score, empathy_score, humor_score]])//3

            
            # logger.info(f"engagement score {engagement_score} feedback {feedback}")

            # Save the evaluation in ReportCard
            report_card = ReportCard(
                session_id=session.id,
                user_id=current_user.id,
                engagement_score=int(engagement_score),
                humor_score=int(humor_score),
                empathy_score=int(empathy_score),
                total_score=total_score,
                engagement_feedback="",
                humor_feedback="",
                empathy_feedback="",
                feedback =feedback
            )
            db.session.add(report_card)
            db.session.commit()
        
            

            return jsonify({
                "user_message": user_msg.content,
                "ai_response": "You have completed the game! Your performance has been evaluated. Go to Report Cards to view your Score.",
                "evaluation": {
                    "engagement_score": report_card.engagement_score,
                    "engagement_feedback": report_card.engagement_feedback,
                    "humor_score": report_card.humor_score,
                    "humor_feedback": report_card.humor_feedback,
                    "empathy_score": report_card.empathy_score,
                    "empathy_feedback": report_card.empathy_feedback,
                    "total_score": report_card.total_score,
                    "feedback_summary": feedback,
                    "feedback": feedback,
                    "report_link": f"{CLIENT_URL}/report-cards/{session_id}"
                }
            }), 200
        # else:
        #     return jsonify({
        #         "user_message": user_msg.content,
        #         "ai_response": ai_msg.content,
        #         "evaluation": {
        #             "engagement_score": report_card.engagement_score,
        #             "engagement_feedback": report_card.engagement_feedback,
        #             "humor_score": report_card.humor_score,
        #             "humor_feedback": report_card.humor_feedback,
        #             "empathy_score": report_card.empathy_score,
        #             "empathy_feedback": report_card.empathy_feedback,
        #             "total_score": report_card.total_score,
        #             "feedback_summary": feedback,
        #             "feedback": feedback,
        #             "report_link": f"{CLIENT_URL}/report-cards/{session_id}"
        #         }
        #     }), 200


        else:
            # More than 10 messages; prevent further messages or allow based on requirements
            logger.info("Report already generated...")
            # return jsonify({"error": "This session has already been evaluated."}), 400
            return jsonify({
                    "user_message": user_msg.content,
                    "ai_response": ai_msg.content
                }), 200

    except Exception as e:
        logger.error(f"Error handling chat message: {e}")
        db.session.rollback()
        return jsonify({"error": "Internal server error"}), 500



@app.route('/api/chat/sessions/<session_id>/report-card/', methods=['GET'])
@token_required
def get_report_card(current_user, session_id):
    # Retrieve the chat session
    session = ChatSession.query.filter_by(id=session_id, user_id=current_user.id).first()
    if not session:
        return jsonify({"error": "Chat session not found"}), 404

    # Retrieve the report card
    rc = ReportCard.query.filter_by(session_id=session.id, user_id=current_user.id).first()
    if not rc:
        return jsonify({"error": "Report card not found for this session."}), 404

    return jsonify({
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
