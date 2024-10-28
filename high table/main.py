from flask import Flask, redirect, url_for, request, render_template, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Temporary mock database as a dictionary for users
users_db = {}  # Replace with actual database setup in production

class User(UserMixin):
    def __init__(self, id, username, password_hash, first_name, last_name, email, phone, institution):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.phone = phone
        self.institution = institution

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return users_db.get(int(user_id))

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
        if username in [u.username for u in users_db.values()]:
            flash('Username already exists.')
            return redirect(url_for('register'))
        
        # Hash the password and store the new user
        password_hash = generate_password_hash(password)
        new_user_id = len(users_db) + 1
        new_user = User(
            id=new_user_id,
            username=username,
            password_hash=password_hash,
            first_name=first_name,
            last_name=last_name,
            email=email,
            phone=phone,
            institution=institution
        )
        users_db[new_user_id] = new_user
        
        flash('Registration successful. Please log in.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

# Other routes remain unchanged
@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = next((u for u in users_db.values() if u.username == username), None)
        
        if user and user.check_password(password):
            session.permanent = True
            login_user(user)
            return redirect(url_for('dashboard'))
        
        flash('Invalid username or password.')
        return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/dashboard')
#@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/changepassword', methods=['GET', 'POST'])
#@login_required
def change_password():
    if request.method == 'POST':
        new_password = request.form['new_password']
        current_user.password_hash = generate_password_hash(new_password)
        flash('Password updated successfully.')
        return redirect(url_for('dashboard'))
    
    return render_template('change_password.html')

@app.route('/profile')
#@login_required
def profile():
    pass

@app.route('/repositories')
#@login_required
def repositories():
    pass

@app.route('/appointments')
#@login_required
def appointments():
    pass

@app.route('/admin')
#@login_required
def admin():
    pass

@app.route('/settings')
#@login_required
def settings():
    pass

@app.route('/logout')
#@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.errorhandler(400)
def page_not_found(e):
    return "Error 400 bad request"

@app.errorhandler(401)
def page_not_found(e):
    return "Error 400 unauthorized"

@app.errorhandler(403)
def page_not_found(e):
    return "Error 400 forbidden"

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html')


if __name__ == "__main__":
    app.run(debug=True)
