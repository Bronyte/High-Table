from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'user_credentials'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_login = db.Column(db.DateTime, nullable=True)
    role = db.Column(db.String(20), nullable=False, default='user')
    
    profile = db.relationship('UserProfile', backref='user', uselist=False)  # String reference

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def update_last_login(self):
        self.last_login = datetime.utcnow()
        db.session.commit()


class UserProfile(db.Model):
    __tablename__ = 'user_profiles'

    user_id = db.Column(db.Integer, db.ForeignKey('user_credentials.id'), primary_key=True)  # Make sure this matches the foreign key
    firstname = db.Column(db.String(100))
    surname = db.Column(db.String(100))
    phone_number = db.Column(db.String(20))
    type_of_institution = db.Column(db.String(50))
    name_of_institution = db.Column(db.String(100))
    participated_in_past_competitions = db.Column(db.Boolean, default=False)
    preferred_coding_language = db.Column(db.String(100))
    preferred_ide = db.Column(db.String(100))
    message = db.Column(db.Text)


class Chat(db.Model):
    __tablename__ = 'chat'
    
    id = db.Column(db.Integer, primary_key=True)  # Chat_ID
    sender_id = db.Column(db.Integer, db.ForeignKey('user_credentials.id'), nullable=False)  # Sender_ID
    receiver_id = db.Column(db.Integer, db.ForeignKey('user_credentials.id'), nullable=False)  # Receiver_ID
    message = db.Column(db.Text, nullable=False)  # Message
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)  # Timestamp
