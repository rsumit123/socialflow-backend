# models.py
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from datetime import timedelta
import uuid

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    auth0_id = db.Column(db.String(100), unique=True, nullable=True)  # Nullable if not using Auth0
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.LargeBinary(60), nullable=False)  # Store hashed passwords
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    verified = db.Column(db.Boolean, default=False)  # Add this field

    # Relationships
    sessions = db.relationship('ChatSession', backref='user', lazy=True)
    report_cards = db.relationship('ReportCard', backref='user', lazy=True)

class ChatSession(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, default=lambda: datetime.utcnow() + timedelta(days=30))  # Optional

    # Relationships
    messages = db.relationship('ChatMessage', backref='session', lazy=True)
    report_card = db.relationship('ReportCard', backref='session', uselist=False)

class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(36), db.ForeignKey('chat_session.id'), nullable=False)
    sender = db.Column(db.String(10), nullable=False)  # 'user', 'assistant', or 'system'
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class ReportCard(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(36), db.ForeignKey('chat_session.id'), nullable=False, unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    engagement_score = db.Column(db.Float, nullable=True)
    humor_score = db.Column(db.Float, nullable=True)
    empathy_score = db.Column(db.Float, nullable=True)
    total_score = db.Column(db.Float, nullable=True)
    engagement_feedback = db.Column(db.Text, nullable=True)
    humor_feedback = db.Column(db.Text, nullable=True)
    feedback = db.Column(db.Text, nullable=True)
    empathy_feedback = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
