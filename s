

requiremtns to install 
Flask==3.0.3
Flask-WTF==1.2.1
Flask-Login==0.6.3
Flask-SQLAlchemy==3.1.1
Werkzeug==3.0.3
Flask-Limiter==3.5.1
Flask-Talisman==1.0.0


**New application/__init__.py code**


from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
import logging
import os

aplication = Flask(__name__)
aplication.config['SECRET_KEY'] = 'your_secret_key_here'  # Replace with a secure key
aplication.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
aplication.config['UPLOAD_FOLDER'] = 'static/uploads'

db = SQLAlchemy(aplication)
login_manager = LoginManager(aplication)
login_manager.login_view = 'login'

# Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=aplication,
    default_limits=["200 per day", "50 per hour"]
)

# Content Security Policy and Secure Headers
csp = {
    'default-src': "'self'",
    'script-src': "'self'",
    'style-src': "'self'",
    'img-src': "'self' data:",
}
talisman_config = {
    'force_https': True,  # Enable HSTS
    'frame_options': 'DENY',  # X-Frame-Options: DENY
    'content_security_policy': csp,
}
talisman = Talisman(aplication, **talisman_config)

# Logging Configuration
if not os.path.exists('logs'):
    os.makedirs('logs')
logging.basicConfig(
    filename='logs/security.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

from aplication import models, controllers



**application/controllers.py**


from flask import render_template, redirect, url_for, flash, request
from aplication import aplication, db, logger
from aplication.forms import LoginForm, RegisterForm, EditUserForm, UploadForm
from aplication.models import User
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
import os

@aplication.route('/')
def home():
    return render_template('inicial.html')

@aplication.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        user = User(name=form.name.data, email=form.email.data)
        user.set_password(form.password.data)
        if form.image.data:
            filename = secure_filename(form.image.data.filename)
            form.image.data.save(os.path.join(aplication.config['UPLOAD_FOLDER'], filename))
            user.image = filename
        db.session.add(user)
        db.session.commit()
        flash('Cadastro realizado com sucesso!', 'success')
        return redirect(url_for('login'))
    return render_template('cadastrar.html', form=form)

@aplication.route('/login', methods=['GET', 'POST'])
@limiter.limit("100 per day", methods=['GET'])
@limiter.limit("5 per minute", methods=['POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            logger.info(f"Successful login for user: {user.email}")
            flash('Login realizado com sucesso!', 'success')
            return redirect(url_for('home'))
        else:
            logger.warning(f"Failed login attempt for email: {form.email.data}")
            flash('E-mail ou senha inválidos', 'danger')
    return render_template('login.html', form=form)

@aplication.route('/logout')
@login_required
def logout():
    logger.info(f"Logout for user: {current_user.email}")
    logout_user()
    return redirect(url_for('home'))

@aplication.route('/users')
@login_required
def users():
    contas = User.query.all()
    return render_template('contas.html', contas=contas)

@aplication.route('/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    form = EditUserForm()
    if form.validate_on_submit():
        user.name = form.name.data
        user.email = form.email.data
        if form.password.data:
            user.set_password(form.password.data)
        if form.image.data:
            filename = secure_filename(form.image.data.filename)
            form.image.data.save(os.path.join(aplication.config['UPLOAD_FOLDER'], filename))
            user.image = filename
        db.session.commit()
        logger.info(f"User updated: {user.email}")
        flash('Usuário atualizado com sucesso!', 'success')
        return redirect(url_for('users'))
    form.name.data = user.name
    form.email.data = user.email
    return render_template('editar.html', form=form, editar_usuario=user)

@aplication.route('/delete/<int:user_id>')
@login_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    logger.info(f"User deleted: {user.email}")
    db.session.delete(user)
    db.session.commit()
    flash('Usuário apagado com sucesso!', 'success')
    return redirect(url_for('users'))

@aplication.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    form = UploadForm()
    if form.validate_on_submit():
        filename = secure_filename(form.image.data.filename)
        form.image.data.save(os.path.join(aplication.config['UPLOAD_FOLDER'], filename))
        current_user.image = filename
        db.session.commit()
        logger.info(f"Image uploaded for user: {current_user.email}")
        flash('Imagem salva com sucesso!', 'success')
        return redirect(url_for('home'))
    return render_template('upload.html', form=form)

@aplication.errorhandler(429)
def ratelimit_handler(e):
    logger.warning(f"Rate limit exceeded for IP: {get_remote_address()}")
    flash("Too many requests. Please try again later.", "danger")
    return redirect(url_for('home'))

   
    
    **application/models.py**


    
    from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from aplication import db, login_manager

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    image = db.Column(db.String(200))  # Path to profile image

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))




    **aplication/forms.py**

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, FileField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo

class RegisterForm(FlaskForm):
    name = StringField('Nome', validators=[DataRequired()])
    email = StringField('E-mail', validators=[DataRequired(), Email()])
    password = PasswordField('Senha', validators=[DataRequired()])
    confirm_password = PasswordField('Confirmar Senha', validators=[DataRequired(), EqualTo('password')])
    image = FileField('Foto')
    submit = SubmitField('Cadastrar')

class LoginForm(FlaskForm):
    email = StringField('E-mail', validators=[DataRequired(), Email()])
    password = PasswordField('Senha', validators=[DataRequired()])
    submit = SubmitField('Logar')

class EditUserForm(FlaskForm):
    name = StringField('Nome', validators=[DataRequired()])
    email = StringField('E-mail', validators=[DataRequired(), Email()])
    password = PasswordField('Nova Senha')
    confirm_password = PasswordField('Confirmar Nova Senha', validators=[EqualTo('password')])
    image = FileField('Foto')
    submit = SubmitField('Confirmar')

class UploadForm(FlaskForm):
    image = FileField('Foto', validators=[DataRequired()])
    submit = SubmitField('Salvar')


**run.py**

from aplication import aplication, db

if __name__ == '__main__':
    with aplication.app_context():
        db.create_all()  # Creates the database tables
    aplication.run(debug=True, port=5310)


    6. Templates Unchanged: No changes needed for cadastrar.html, contas.html, editar.html, 
    upload.html, base.html, inicial.html, login.html.
    Ensure base.html includes flash messages as shown earlier if not present


    static/style.css
Unchanged: No changes needed for security features.

body {
    background-image: linear-gradient(to right, cyan, white, cyan);
}
ul {
    list-style: circle;
}
.footer {
    width: 100%;
    bottom: 0px;
    position: absolute;
    height: 50px;
    text-align: center;
    background-color: grey;
    color: #fff;
    padding-top: 12px;
    letter-spacing: 2px;
    font-style: italic;
    font-family: Verdana, Geneva, Tahoma, sans-serif;
}
.inicial {
    display: grid;
    grid-template-columns: 1fr;
    margin: 0 auto;
    background-color: blanchedalmond;
    text-align: center;
    padding: 50px;
}
.inicial a {
    margin-top: 10px;
}
.cadastro {
    background-color: blanchedalmond;
    text-align: center;
    padding-bottom: 10px;
}
.cadastro a, input {
    margin-top: 10px;
}
.login {
    background-color: blanchedalmond;
    text-align: center;
    padding-bottom: 10px;
}
.login a, button {
    margin-top: 10px;
}
.login img {
    border-radius: 50%;
}
.table {
    background-color: blanchedalmond;
    text-align: center;
}
.btn a + a {
    margin-top: 10px;
}
.home {
    margin-top: -20px;
    padding: 20px 0px 20px 0px;
    background-color: blanchedalmond;
}
.home a {
    margin-left: 10px;
}


    
