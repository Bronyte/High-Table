from flask_mail import Mail, Message

class MailService:
    def __init__(self, app):
        self.mail = Mail(app)

    def send_chat_message(self, recipient, sender_username, message_content):
        msg = Message("New Chat Message", recipients=[recipient])
        msg.body = f"Message from {sender_username}: {message_content}"
        self.mail.send(msg)
