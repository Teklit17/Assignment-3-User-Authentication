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






app = Flask(__name__, template_folder='templates')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['WTF_CSRF_ENABLED'] = True
csrf = CSRFProtect(app)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

limiter = Limiter(
    app,
    default_limits=["200 per day", "50 per hour"]
)



def load_config():
    with open('config.json', 'r') as config_file:
        config = json.load(config_file)
    return config


config = load_config()
google_client_id = config['client_id']
google_client_secret = config['client_secret']


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


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    totp_secret = db.Column(db.String(16))
    google_id = db.Column(db.String(120), unique=True, nullable=True)
    email = db.Column(db.String(120), unique=True, nullable=True)
    posts = db.relationship('Post', backref='author', lazy=True)
    failed_attempts = db.Column(db.Integer, default=0)
    lock_until = db.Column(db.DateTime, nullable=True)


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    content = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', name='fk_user_id'))


class VerifyTOTPForm(FlaskForm):
    totp_token = StringField('TOTP Token', validators=[DataRequired()])
    submit = SubmitField('Verify')


class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = StringField('Content', validators=[DataRequired()])
    submit = SubmitField('Create Post')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# hash passwords
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password.decode('utf-8')


# Google OAuth token getter

@app.route('/login/google')
def login_google():
    redirect_uri = url_for('authorize', _external=True)
    return google.authorize_redirect(redirect_uri)


@app.route('/login/google/authorize')
def authorize():
    try:
        token = google.authorize_access_token()
    except Exception as e:
        flash("Authorization failed or was cancelled: " + str(e), "error")
        return redirect(url_for('login'))

    resp = google.get('userinfo', token=token)
    user_info = resp.json()

    # Check if user exists
    user = User.query.filter_by(google_id=user_info['id']).first()
    if not user:
        placeholder_password = secrets.token_hex(16)

        user = User(
            username=user_info['name'],  # Assuming you have a username field
            google_id=user_info['id'],
            email=user_info['email'],
            password=hash_password(placeholder_password)
            # You can add other fields here as needed
        )
        db.session.add(user)
        db.session.commit()

    # Log in the user
    login_user(user, remember=True)

    return redirect(url_for('index'))


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


@app.route('/display_qr/<username>')
def display_qr(username):
    path = f'static/qrcodes/{username}.png'
    return render_template('display_qr.html', qr_path=path, username=username)


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = User.query.filter_by(username=username).first()
        if user:
            # Check if the account is locked due to failed attempts
            if user.lock_until and user.lock_until > datetime.utcnow():
                flash('Account is locked due to multiple failed login attempts. Please try again later.',
                      'error')
                return render_template('login.html', form=form)
            # If user registered through Google, disallow password login
            if user.google_id and not bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
                flash('Login through Google is required for this account.', 'error')
                return render_template('login.html', form=form)

            if bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
                # Reset failed attempts
                user.failed_attempts = 0
                user.lock_until = None
                db.session.commit()
                # If password is correct, redirect to TOTP verification
                return redirect(url_for('verify_totp', username=user.username))
            else:
                # Increment failed attempts and lock account if necessary
                user.failed_attempts += 1
                if user.failed_attempts >= 3:
                    user.lock_until = datetime.utcnow() + timedelta(minutes=15)  # Lock for 15 minutes
                db.session.commit()
                flash('Invalid username or password.', 'error')

    return render_template('login.html', form=form)


@app.route('/verify_totp/<username>', methods=['GET', 'POST'])
def verify_totp(username):
    user = User.query.filter_by(username=username).first()
    form = VerifyTOTPForm()
    if form.validate_on_submit():
        totp_token = form.totp_token.data
        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(totp_token):
            login_user(user)
            flash('Login successful.', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid TOTP token.', 'error')

    return render_template('verify_totp.html', form=form, username=username)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('google_token', None)
    return redirect(url_for('login'))


@app.route('/')
def index():
    posts = Post.query.all()
    return render_template('index.html', posts=posts)


@app.route('/create', methods=['GET', 'POST'])
@login_required
def create_post():
    form = PostForm()
    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data
        post = Post(title=title, content=content, user_id=current_user.id)
        db.session.add(post)
        db.session.commit()
        flash('Your post has been created!', 'success')
        return redirect(url_for('index'))

    return render_template('create.html', form=form)


with app.app_context():
    db.create_all()
if __name__ == '__main__':
    app.run(debug=True)
