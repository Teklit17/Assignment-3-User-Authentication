from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
import bcrypt
from flask_wtf.csrf import CSRFProtect
import pyotp
from PIL import Image
import io
from flask import send_file
import qrcode
from flask import send_file
import pyotp

app = Flask(__name__, template_folder='templates')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SECRET_KEY'] = 'your-secret-key'  # Replace with a secure secret key
app.config['WTF_CSRF_ENABLED'] = True  # Enable CSRF protection
csrf = CSRFProtect(app)
# Initialize SQLAlchemy and Flask-Migrate
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Configure the login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Define RegistrationForm
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Register')

# Define LoginForm
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Define a User class
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    totp_secret = db.Column(db.String(16))
    # Relationship to link users to their posts
    posts = db.relationship('Post', backref='author', lazy=True)
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    content = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', name='fk_user_id'))



# Create a user loader function
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Function to hash passwords
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password.decode('utf-8')

# Define Post class for the database


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
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
        totp_uri = pyotp.totp.TOTP(new_user.totp_secret).provisioning_uri(name=new_user.username, issuer_name="YourAppName")
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(totp_uri)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        img.save(f'static/qrcodes/{new_user.username}.png')  # Save QR code image

        flash('Registration successful. Please scan the QR code with your Authenticator app.', 'success')
        return redirect(url_for('display_qr', username=new_user.username))

    return render_template('register.html', form=form)

@app.route('/display_qr/<username>')
def display_qr(username):
    path = f'static/qrcodes/{username}.png'
    return send_file(path, mimetype='image/png')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = User.query.filter_by(username=username).first()

        if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            # If password is correct, redirect to TOTP verification
            return redirect(url_for('verify_totp', username=user.username))
        else:
            flash('Invalid username or password.', 'error')

    return render_template('login.html', form=form)


class VerifyTOTPForm(FlaskForm):
    totp_token = StringField('TOTP Token', validators=[DataRequired()])
    submit = SubmitField('Verify')


@app.route('/verify_totp/<username>', methods=['GET', 'POST'])
def verify_totp(username):
    user = User.query.filter_by(username=username).first()
    form = VerifyTOTPForm()
    if request.method == 'POST':
        totp_token = request.form.get('totp_token')
        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(totp_token):
            login_user(user)
            flash('Login successful.', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid TOTP token.', 'error')

    return render_template('verify_totp.html', form=form, username=username)

    # Create a route for user logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Create a route to display posts
@app.route('/')
def index():
    posts = Post.query.all()
    return render_template('index.html', posts=posts)

# Define PostForm
class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = StringField('Content', validators=[DataRequired()])
    submit = SubmitField('Create Post')


# Create a route to create new posts
# Create a route to create new posts
@app.route('/create', methods=['GET', 'POST'])
@login_required
def create_post():
    form = PostForm()  # Create an instance of PostForm
    if form.validate_on_submit():

        title = form.title.data
        content = form.content.data
        # Create a new Post object with the current user's id
        post = Post(title=title, content=content, user_id=current_user.id)
        db.session.add(post)
        db.session.commit()
        flash('Your post has been created!', 'success')
        return redirect(url_for('index'))
    return render_template('create.html', form=form)

if __name__ == '__main__':
    app.run(debug=True)
