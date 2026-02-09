import os
import requests
import logging
import json

import re
import json
from markupsafe import escape

from dotenv import load_dotenv
load_dotenv()
# Set up logging
logger = logging.getLogger('flask_app')
logger.setLevel(logging.DEBUG)  # Set the desired logging level

EVALUATION_PROMPT = os.getenv('EVALUATION_PROMPT')

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

def get_ai_response(messages, temperature=1.3):
    api_key = os.getenv('DEEPSEEK_API_KEY')
    api_url = os.getenv('DEEPSEEK_API_URL', 'https://api.deepseek.com/chat/completions')
    
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {api_key}'
    }
    
    payload = {
        'model': 'deepseek-chat',
        'messages': messages,
        'stream': False,
        'temperature': temperature
    }
    
    try:
        response = requests.post(api_url, headers=headers, json=payload, timeout=30)
        response.raise_for_status()
        data = response.json()
        ai_message = data['choices'][0]['message']['content']
        return ai_message
    except requests.exceptions.RequestException as e:
        logger.error(f"Error communicating with DeepSeek API: {e}")
        return "I'm sorry, I'm having trouble processing your request right now."
    


def evaluate_user_skills(user_messages):
    """
    Sends the user's messages to the AI for evaluation and returns the AI's response.
    """
    logger.info(f"GOT USER MESSAGES AS {user_messages}")
    user_messages = [str(msg) for msg in user_messages]
    evaluation_prompt_formatted = EVALUATION_PROMPT.format(
        user_messages="\n".join(user_messages)
    )

    logger.info(f"Evaluation prompt formatted {evaluation_prompt_formatted}")

    # Prepare messages for AI
    messages = [
        {"role": "system", "content": evaluation_prompt_formatted}
    ]

    # Get AI response
    ai_response = get_ai_response(messages)

    return ai_response


# app.py
import re
import json
from markupsafe import escape

def parse_evaluation_result(evaluation_text):
    """
    Parses the AI's evaluation text and extracts scores and feedback.
    
    Parameters:
        evaluation_text (str): The textual evaluation response from the AI.
    
    Returns:
        dict: A dictionary containing extracted scores and feedback.
    """
    
    # Clean markdown code fences from AI response
    cleaned = evaluation_text.strip()
    if cleaned.startswith('```'):
        cleaned = re.sub(r'^```(?:json)?\s*', '', cleaned)
        cleaned = re.sub(r'\s*```$', '', cleaned)
    cleaned = cleaned.strip()

    logger.info(f"EVALUATION (cleaned) => {cleaned[:500]}")

    try:
        result = json.loads(cleaned)
        logger.info(f"RESULT {result}")

        # Ensure all expected keys exist with safe defaults
        result.setdefault('engagement_score', 0)
        result.setdefault('empathy_score', 0)
        result.setdefault('humor_score', 0)
        result.setdefault('feedback', 'Evaluation completed.')

        # Ensure scores are valid integers
        for key in ['engagement_score', 'empathy_score', 'humor_score']:
            try:
                result[key] = int(result[key])
            except (TypeError, ValueError):
                logger.warning(f"Invalid score for {key}: {result[key]}, defaulting to 0")
                result[key] = 0

        logger.info(f"==>RESULT {result}")

        return result
    except (json.JSONDecodeError, ValueError) as e:
        logger.info(f"GOT ERROR EVALUATING JSON: {e}")

        # Initialize a dictionary to hold the results with safe defaults
        evaluation_data = {
            "engagement_score": 0,
            "engagement_feedback": "",
            "humor_score": 0,
            "humor_feedback": "",
            "empathy_score": 0,
            "empathy_feedback": "",
            "total_score": 0,
            "feedback": "Evaluation completed."
        }

        # Define regex patterns for each score and explanation
        patterns = {
            "engagement": {
                "score": r"### \*\*Engagement Score:\s*(\d{1,3}(?:\.\d{1,2})?)/100\*\*",
                "feedback": r"### \*\*Engagement Score:.*?\*\*\n\*\*Explanation:\*\*\s*(.*?)\n---"
            },
            "humor": {
                "score": r"### \*\*Humor Score:\s*(\d{1,3}(?:\.\d{1,2})?)/100\*\*",
                "feedback": r"### \*\*Humor Score:.*?\*\*\n\*\*Explanation:\*\*\s*(.*?)\n---"
            },
            "empathy": {
                "score": r"### \*\*Empathy Score:\s*(\d{1,3}(?:\.\d{1,2})?)/100\*\*",
                "feedback": r"### \*\*Empathy Score:.*?\*\*\n\*\*Explanation:\*\*\s*(.*?)\n---"
            },
            "total": {
                "score": r"### \*\*Total Score:\s*(\d{1,3}(?:\.\d{1,2})?)/100\*\*",
                "feedback": None  # No feedback for total score
            }
        }

        # Iterate over each pattern and extract data
        for category, pattern in patterns.items():
            # Extract score
            score_match = re.search(pattern["score"], evaluation_text, re.DOTALL)
            if score_match:
                score = float(score_match.group(1))
                key = f"{category}_score"
                evaluation_data[key] = score
            else:
                logger.warning(f"Score for {category} not found in evaluation text.")

            # Extract feedback if applicable
            if pattern["feedback"]:
                feedback_match = re.search(pattern["feedback"], evaluation_text, re.DOTALL)
                if feedback_match:
                    feedback = feedback_match.group(1).strip()
                    key = f"{category}_feedback"
                    evaluation_data[key] = feedback
                else:
                    logger.warning(f"Feedback for {category} not found in evaluation text.")

    return evaluation_data



