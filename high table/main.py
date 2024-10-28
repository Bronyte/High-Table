from flask import Flask, redirect, url_for, request, render_template, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
from db import db, User  # Import the database and User model

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
            flash('Passwords do not match.')
            return redirect(url_for('register'))
        
        # Check if the username already exists
        if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
            flash('Username or email already exists.')
            return redirect(url_for('register'))
        
        # Hash the password and store the new user
        password_hash = generate_password_hash(password)
        new_user = User(
            username=username,
            password_hash=password_hash,
            first_name=first_name,
            last_name=last_name,
            email=email,
            phone=phone,
            institution=institution
        )
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful. Please log in.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/')
def home():
    return render_template('LoginRegistration.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            session.permanent = True
            login_user(user)
            return redirect(url_for('dashboard'))
        
        flash('Invalid username or password.')
        return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

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

@app.route('/admin', methods=['GET', 'POST'])
@login_required 
def admin():
    # Only allow access if the user is an admin (replace with your logic if needed)
    #if not current_user.is_authenticated or current_user.username != "admin":
    #    flash("You do not have permission to access this page.")
    #    return redirect(url_for('dashboard'))
    
    users = User.query.all()
    return render_template('admin.html', users=users)

@app.route('/admin/add_user', methods=['POST'])
@login_required
def add_user():
    #if not current_user.is_authenticated or current_user.username != "admin":
    #    flash("You do not have permission to access this page.")
    #    return redirect(url_for('dashboard'))
    
    # Get form data
    username = request.form.get('username')
    password = request.form.get('password')
    first_name = request.form.get('first_name')
    last_name = request.form.get('last_name')
    email = request.form.get('email')
    phone = request.form.get('phone')
    institution = request.form.get('institution')

    # Check if the user already exists
    if User.query.filter_by(username=username).first():
        flash("User with that username already exists.")
        return redirect(url_for('admin'))

    # Add new user
    password_hash = generate_password_hash(password)
    new_user = User(username=username, password_hash=password_hash, first_name=first_name,
                    last_name=last_name, email=email, phone=phone, institution=institution)
    db.session.add(new_user)
    db.session.commit()
    flash("User added successfully.")
    return redirect(url_for('admin'))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    #if not current_user.is_authenticated or current_user.username != "admin":
    #    flash("You do not have permission to access this page.")
    #   return redirect(url_for('dashboard'))

    # Find and delete the user
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash("User deleted successfully.")
    else:
        flash("User not found.")
    return redirect(url_for('admin'))

@app.route('/changepassword', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        new_password = request.form['new_password']
        current_user.password_hash = generate_password_hash(new_password)
        db.session.commit()  # Commit changes to the database
        flash('Password updated successfully.')
        return redirect(url_for('dashboard'))
    
    return render_template('change_password.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.errorhandler(400)
def bad_request(e):
    return "Error 400: Bad request"

@app.errorhandler(401)
def unauthorized(e):
    return "Error 401: Unauthorized"

@app.errorhandler(403)
def forbidden(e):
    return "Error 403: Forbidden"

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html')

if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Create database tables
    app.run(debug=True)
