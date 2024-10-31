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
    
    profile = db.relationship('UserProfile', backref='user', uselist=False)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def update_last_login(self):
        self.last_login = datetime.utcnow()
        db.session.commit()



class UserProfile(db.Model):
    __tablename__ = 'user_profile'
    
    id = db.Column(db.Integer, primary_key=True)  # Profile_ID
    user_id = db.Column(db.Integer, db.ForeignKey('user_credentials.id'), nullable=False)  # User_ID
    firstname = db.Column(db.String(150), nullable=False)  # Firstname
    surname = db.Column(db.String(150), nullable=False)  # Surname
    phone_number = db.Column(db.String(20))  # Phone_Number
    type_of_institution = db.Column(db.String(150))  # Type_of_Institution
    name_of_institution = db.Column(db.String(150))  # Name_of_Institution
    participated_in_past_competitions = db.Column(db.Boolean, default=False)  # Participated_in_past_Competitions
    preferred_coding_language = db.Column(db.String(50))  # Preferred_Coding_Language
    preferred_ide = db.Column(db.String(50))  # Preferred_IDE


class Chat(db.Model):
    __tablename__ = 'chat'
    
    id = db.Column(db.Integer, primary_key=True)  # Chat_ID
    sender_id = db.Column(db.Integer, db.ForeignKey('user_credentials.id'), nullable=False)  # Sender_ID
    receiver_id = db.Column(db.Integer, db.ForeignKey('user_credentials.id'), nullable=False)  # Receiver_ID
    message = db.Column(db.Text, nullable=False)  # Message
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)  # Timestamp
