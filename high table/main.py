from flask import Flask, jsonify, redirect, url_for, request, render_template, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
from db import db, User, UserProfile  # Import the database and other models
from mail import MailService


app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # Use SQLite for simplicity
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Get form data
        first_name = request.form['firstName']
        last_name = request.form['lastName']
        email = request.form['email']
        phone = request.form['phone']
        institution = request.form['institution']
        username = email  # assuming username is email for unique identification
        password = request.form['password']
        confirm_password = request.form['confirmPassword']
        
        # Validate if the passwords match
        if password != confirm_password:
            flash('Passwords do not match.', 'negative')
            return redirect(url_for('register'))
        
        # Check if the username already exists
        if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
            flash('Username or email already exists.', 'negative')
            return redirect(url_for('register'))
        
        # Hash the password and store the new user
        password_hash = generate_password_hash(password)
        new_user = User(
            username=username,
            password_hash=password_hash,
            email=email
        )
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful. Please log in.', 'positive')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/')
def home():
    if current_user.is_authenticated:
        # Redirect to the dashboard if the user is logged in
        return redirect(url_for('dashboard'))
    return render_template('LoginRegistration.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login_input = request.form['username']  # This can be either the username or email
        password = request.form['password']
        
        # Check if the input is a username or email and find the user
        user = User.query.filter((User.username == login_input) | (User.email == login_input)).first()
        
        if user and check_password_hash(user.password_hash, password):
            session.permanent = True
            login_user(user)
            user.update_last_login()  # Update the last login time if you have that method
            flash(f"Logged in as {user.username} with role: {user.role}", "positive") 
            return redirect(url_for('dashboard'))
        
        flash('Invalid username or password.', 'negative')
        return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/chats', methods=['GET', 'POST'])
@login_required
def chats():
    if request.method == 'POST':
        recipient = request.form['recipient']
        message_content = request.form['message']
        
        # Send the chat message via email
        mail_service.send_chat_message(recipient, current_user.username, message_content)
        
        flash('Chat message sent!', 'positive')
        return redirect(url_for('chats'))

    return render_template('chats.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/profile', methods=['GET', 'POST'])
@login_required  # Ensure the user is logged in
def profile():
    # Query the database for the user's profile
    user_profile = UserProfile.query.filter_by(user_id=current_user.id).first()

    if request.method == 'POST':
        if user_profile:
            # Update the user's profile with the form data
            user_profile.firstname = request.form['firstName']
            user_profile.surname = request.form['lastName']
            user_profile.phone_number = request.form['phone']
            user_profile.type_of_institution = request.form['institutionType']
            user_profile.name_of_institution = request.form['institutionName']
            user_profile.participated_in_past_competitions = request.form['pastCompetitions'].lower() == 'true'
            user_profile.preferred_coding_language = request.form['preferredLanguage']
            user_profile.preferred_ide = request.form['preferredIDE']
            user_profile.message = request.form.get('message', '')  # Optional message field

            db.session.commit()  # Save changes to the database

        return redirect(url_for('profile'))  # Redirect back to the profile page

    # If the request is GET, render the profile page
    return render_template('ViewProfile.html', user=user_profile)



@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html')

@app.route('/appointments')
@login_required
def appointments():
    pass

@app.route('/repositories')
@login_required
def repositories():
    pass

def create_admin_user():
    # Check if an admin user with username "admin" already exists
    admin_user = User.query.filter_by(username="admin").first()
    if not admin_user:
        # Create the admin user with username "admin" and password "admin"
        admin_user = User(
            username="admin",
            password_hash=generate_password_hash("admin"),
            email= "None",  # Use a placeholder email for admin
            role="admin user"  # Ensure this matches the expected role name
        )
        db.session.add(admin_user)
        db.session.commit()
        print("Admin user created with username 'admin' and password 'admin'.")

@app.route('/admin')
@login_required
def admin():
    if current_user.role != 'admin user':
        return "Unauthorized", 403

    users = User.query.all()

    user_data = []
    for user in users:
        profile = UserProfile.query.filter_by(user_id=user.id).first()
        user_data.append({
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'role': user.role,
            'firstname': profile.firstname if profile else None,
            'surname': profile.surname if profile else None,
            'phone_number': profile.phone_number if profile else None,
            'type_of_institution': profile.type_of_institution if profile else None,
            'name_of_institution': profile.name_of_institution if profile else None,
            'participated_in_past_competitions': profile.participated_in_past_competitions if profile else None,
            'preferred_coding_language': profile.preferred_coding_language if profile else None,
            'preferred_ide': profile.preferred_ide if profile else None
        })

    return render_template('AdminPanel.html', users=user_data)

@app.route('/edit_user/<int:user_id>', methods=['POST'])
@login_required
def edit_user(user_id):
    if current_user.role != 'admin user':
        return "Unauthorized", 403

    user = User.query.get(user_id)
    if user:
        user.username = request.form['username']
        user.email = request.form['email']
        db.session.commit()
        flash('User updated successfully!', 'positive')
    else:
        flash('User not found.', 'negative')
    
    return redirect(url_for('admin'))

@app.route('/promote_user/<int:user_id>', methods=['POST'])
@login_required
def promote_user(user_id):
    if current_user.role != 'admin user':
        return "Unauthorized", 403

    user = User.query.get(user_id)
    if user:
        user.role = 'admin user'
        db.session.commit()
        flash(f'User {user.username} promoted to admin user!', 'positive')
    else:
        flash('User not found.', 'negative')

    return redirect(url_for('admin'))

@app.route('/demote_user/<int:user_id>', methods=['POST'])
@login_required
def demote_user(user_id):
    if current_user.role != 'admin user':
        return "Unauthorized", 403

    user = User.query.get(user_id)
    if user:
        user.role = 'user'
        db.session.commit()
        flash(f'User {user.username} demoted to user!', 'positive')
    else:
        flash('User not found.', 'negative')

    return redirect(url_for('admin'))

@app.route('/add_user', methods=['POST'])
@login_required
def add_user():
    if current_user.role != 'admin user':
        return "Unauthorized", 403

    username = request.form['username']
    email = request.form['email']
    # Assume you have more fields for the user
    
    new_user = User(username=username, email=email, role='user')
    db.session.add(new_user)
    db.session.commit()
    
    flash('User added successfully!', 'positive')
    return redirect(url_for('admin'))

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role != 'admin user':
        return "Unauthorized", 403

    user = User.query.get(user_id)
    if user:
        # Delete the associated user profile if needed
        profile = UserProfile.query.filter_by(user_id=user.id).first()
        if profile:
            db.session.delete(profile)

        db.session.delete(user)
        db.session.commit()
        flash(f'User {user.username} deleted successfully!', 'positive')
    else:
        flash('User not found.', 'negative')

    return redirect(url_for('admin'))


@app.route('/changepassword', methods=['GET', 'POST'])
@login_required
def change_password():
    if not current_user.is_authenticated:
        flash('Please log in to access this page.', 'negative')  # Set category to 'negative'
        return redirect(url_for('login'))
    if request.method == 'POST':
        new_password = request.form['new_password']
        current_user.password_hash = generate_password_hash(new_password)
        db.session.commit()  # Commit changes to the database
        flash('Password updated successfully.', 'positive')
        return redirect(url_for('dashboard'))
    
    return render_template('change_password.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.errorhandler(403)
def forbidden(e):
    flash("Access is forbidden.", 'negative')
    return render_template('error.html', error="403 Forbidden"), 403

@app.errorhandler(404)
def page_not_found(e):
    flash("Page not found", 'negative')
    return render_template('error.html', error="404 Forbidden"), 404


# Run the create_admin_user function in app startup
if __name__ == "__main__":
    with app.app_context():
        db.drop_all()
        db.create_all()  # Create tables if they don't exist
        create_admin_user()  # Call the function to create the admin user
    app.run(debug=True)

