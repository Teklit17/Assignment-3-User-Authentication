import os, json, bcrypt, pyotp, qrcode, secrets;
from datetime import datetime, timedelta;
from flask import Flask, render_template, redirect, url_for, flash, session, send_file;
from flask_sqlalchemy import SQLAlchemy;
from flask_migrate import Migrate;
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user;
from flask_wtf import FlaskForm;
from wtforms import StringField, PasswordField, SubmitField;
from wtforms.validators import DataRequired;
from flask_wtf.csrf import CSRFProtect;
from authlib.integrations.flask_client import OAuth;
from flask_limiter import Limiter



# Initialize Flask application
app = Flask(__name__, template_folder='templates')

# Configure Flask application
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'  # Database configuration
app.config['SECRET_KEY'] = 'your-secret-key'  # Secret key for session and CSRF protection
app.config['WTF_CSRF_ENABLED'] = True  # Enable CSRF protection

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Initialize database and migration tool
db = SQLAlchemy(app)  # Database ORM
migrate = Migrate(app, db)  # Database migration management

# Initialize and configure login manager
login_manager = LoginManager()  # Login manager for user authentication
login_manager.init_app(app)
login_manager.login_view = "login"  # Default login view

# Initialize and configure rate limiter
limiter = Limiter(
    app,
    default_limits=["200 per day", "50 per hour"]  # Rate limiting configuration
)

# Function to load configuration from a JSON file
def load_config():
    with open('config.json', 'r') as config_file:
        config = json.load(config_file)
    return config

# Load configuration and set OAuth credentials
config = load_config()
google_client_id = config['client_id']  # Google client ID
google_client_secret = config['client_secret']  # Google client secret

# Initialize and configure OAuth for Google authentication
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=google_client_id,
    client_secret=google_client_secret,
    access_token_url='https://oauth2.googleapis.com/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'openid email profile'},
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs'
)



# Registration form class for user registration
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])  # Username field
    password = PasswordField('Password', validators=[DataRequired()])  # Password field
    submit = SubmitField('Register')  # Submit button for registration

# Login form class for user login
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])  # Username field
    password = PasswordField('Password', validators=[DataRequired()])  # Password field
    submit = SubmitField('Login')  # Submit button for login

# User model class for database
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)  # User ID
    username = db.Column(db.String(80), unique=True, nullable=False)  # Username
    password = db.Column(db.String(120), nullable=False)  # Password
    totp_secret = db.Column(db.String(16))  # TOTP secret for two-factor authentication
    google_id = db.Column(db.String(120), unique=True, nullable=True)  # Google ID for OAuth
    email = db.Column(db.String(120), unique=True, nullable=True)  # Email address
    posts = db.relationship('Post', backref='author', lazy=True)  # Relationship to posts
    failed_attempts = db.Column(db.Integer, default=0)  # Failed login attempts
    lock_until = db.Column(db.DateTime, nullable=True)  # Account lockout time

# Post model class for database
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # Post ID
    title = db.Column(db.String(100))  # Post title
    content = db.Column(db.Text)  # Post content
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', name='fk_user_id'))  # User ID foreign key

# Form class for TOTP verification
class VerifyTOTPForm(FlaskForm):
    totp_token = StringField('TOTP Token', validators=[DataRequired()])  # TOTP token field
    submit = SubmitField('Verify')  # Submit button for verification

# Flask-WTForm class for creating a new post
class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])  # Field for the title of the post
    content = StringField('Content', validators=[DataRequired()])  # Field for the content of the post
    submit = SubmitField('Create Post')  # Submit button for the form

# Function to load user from database given a user ID, used by Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))  # Retrieve user from database by user ID

# Function to hash passwords using bcrypt
def hash_password(password):
    salt = bcrypt.gensalt()  # Generate a salt
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)  # Hash the password with salt
    return hashed_password.decode('utf-8')  # Return the hashed password as a string

# Route for initiating Google OAuth login
@app.route('/login/google')
def login_google():
    redirect_uri = url_for('authorize', _external=True)  # Define the redirect URI for OAuth
    return google.authorize_redirect(redirect_uri)  # Redirect user to Google for authorization

# Route for handling the callback from Google OAuth
@app.route('/login/google/authorize')
def authorize():
    try:
        token = google.authorize_access_token()  # Get the authorization token from Google
    except Exception as e:
        flash("Authorization failed or was cancelled: " + str(e), "error")  # Handle authorization failure
        return redirect(url_for('login'))

    resp = google.get('userinfo', token=token)  # Retrieve user information from Google
    user_info = resp.json()  # Convert the response to JSON

    # Check if a user with the given Google ID exists in the database
    user = User.query.filter_by(google_id=user_info['id']).first()
    if not user:
        placeholder_password = secrets.token_hex(16)  # Generate a placeholder password

        # Create a new user with the information from Google
        user = User(
            username=user_info['name'],  # Use the name from Google as username
            google_id=user_info['id'],  # Store Google ID
            email=user_info['email'],  # Store email from Google
            password=hash_password(placeholder_password)  # Hash the placeholder password
            # Additional fields can be added here
        )
        db.session.add(user)  # Add the new user to the database session
        db.session.commit()  # Commit the session to save the user to the database

    login_user(user, remember=True)  # Log in the user

    return redirect(url_for('index'))  # Redirect to the index page

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()  # Assuming you have a form class defined
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # Check if the username is already in use
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username is already taken.', 'error')
            return render_template('register.html', form=form)

        # Hash the password and create a new user
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        new_user = User(username=username, password=hashed_password.decode('utf-8'))

        # Generate TOTP secret for the new user
        new_user.totp_secret = pyotp.random_base32()

        # Add the new user to the database
        db.session.add(new_user)
        db.session.commit()

        # Generate QR code for TOTP
        totp_uri = pyotp.TOTP(new_user.totp_secret).provisioning_uri(name=new_user.username, issuer_name="YourAppName")
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(totp_uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")

        # Ensure the static/qrcodes directory exists
        if not os.path.exists('static/qrcodes'):
            os.makedirs('static/qrcodes')

        img.save(f'static/qrcodes/{new_user.username}.png')  # Save QR code image

        flash('Registration successful. Please scan the QR code with your Authenticator app.', 'success')
        return redirect(url_for('display_qr', username=new_user.username))

    # This return statement handles the case where the form is not validated or it's a GET request
    return render_template('register.html', form=form)


# Route to display QR code for a user
@app.route('/display_qr/<username>')
def display_qr(username):
    path = f'static/qrcodes/{username}.png'  # Path to the user's QR code image
    return render_template('display_qr.html', qr_path=path, username=username)  # Render the QR code display page

# Route for user login
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Rate limit to 5 requests per minute
def login():
    form = LoginForm()  # Initialize login form
    if form.validate_on_submit():
        username = form.username.data  # Get username from form
        password = form.password.data  # Get password from form

        user = User.query.filter_by(username=username).first()  # Query user by username
        if user:
            # Check if account is temporarily locked due to failed attempts
            if user.lock_until and user.lock_until > datetime.utcnow():
                flash('Account is locked due to multiple failed login attempts. Please try again later.', 'error')
                return render_template('login.html', form=form)  # Render login page with error message

            # Check if password login is disallowed for users registered through Google
            if user.google_id and not bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
                flash('Login through Google is required for this account.', 'error')
                return render_template('login.html', form=form)  # Render login page with error message

            # Validate password
            if bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
                # Reset failed login attempts
                user.failed_attempts = 0
                user.lock_until = None
                db.session.commit()
                # Redirect to TOTP verification if password is correct
                return redirect(url_for('verify_totp', username=user.username))
            else:
                # Increment failed attempts and lock account if necessary
                user.failed_attempts += 1
                if user.failed_attempts >= 3:
                    user.lock_until = datetime.utcnow() + timedelta(minutes=15)  # Lock account for 15 minutes
                db.session.commit()
                flash('Invalid username or password.', 'error')

    return render_template('login.html', form=form)  # Render login page

# Route for TOTP verification
@app.route('/verify_totp/<username>', methods=['GET', 'POST'])
def verify_totp(username):
    user = User.query.filter_by(username=username).first()  # Query user by username
    form = VerifyTOTPForm()  # Initialize TOTP verification form
    if form.validate_on_submit():
        totp_token = form.totp_token.data  # Get TOTP token from form
        totp = pyotp.TOTP(user.totp_secret)  # Create TOTP object
        if totp.verify(totp_token):  # Verify TOTP token
            login_user(user)  # Log in the user
            flash('Login successful.', 'success')  # Show success message
            return redirect(url_for('index'))  # Redirect to index page
        else:
            flash('Invalid TOTP token.', 'error')  # Show error message

    return render_template('verify_totp.html', form=form, username=username)  # Render TOTP verification page

# Route for logging out
@app.route('/logout')
@login_required  # Require user to be logged in
def logout():
    logout_user()  # Log out the user
    session.pop('google_token', None)  # Remove Google token from session
    return redirect(url_for('login'))  # Redirect to login page

# Route for index page
@app.route('/')
def index():
    posts = Post.query.all()  # Query all posts
    return render_template('index.html', posts=posts)  # Render index page with posts

# Route for creating a new post
@app.route('/create', methods=['GET', 'POST'])
@login_required  # Require user to be logged in
def create_post():
    form = PostForm()  # Initialize post creation form
    if form.validate_on_submit():
        title = form.title.data  # Get title from form
        content = form.content.data  # Get content from form
        post = Post(title=title, content=content, user_id=current_user.id)  # Create new post
        db.session.add(post)  # Add post to database session
        db.session.commit()  # Commit changes to database
        flash('Your post has been created!', 'success')  # Show success message
        return redirect(url_for('index'))  # Redirect to index page

    return render_template('create.html', form=form)  # Render post creation page

# Create all database tables
with app.app_context():
    db.create_all()

# Run the application
if __name__ == '__main__':
    app.run(debug=True)  # Run with debug mode enabled
