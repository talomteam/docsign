from flask import Blueprint, render_template, redirect, url_for,request,flash,current_app
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user
from flask_ldap3_login import AuthenticationResponseStatus
from .models import User
from . import db

auth = Blueprint('auth',__name__)


@auth.route('/login')
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.profile'))

    return render_template('login.html')


@auth.route('/login', methods=['POST'])
def login_post():
    # login code goes here
    email = request.form.get('email')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    ldap_mgr = current_app.ldap3_login_manager
    result = ldap_mgr.authenticate(email, password)
 
    if not result.status == AuthenticationResponseStatus.success:
        return redirect(url_for('auth.login'))

    # if the above check passes, then we know the user has the right credentials
    ldap_mgr._save_user(result.user_dn,result.user_id,result.user_info,result.user_groups)
    user = User(result.user_dn, email, result.user_info)
    login_user(user, remember=remember)
    return redirect(url_for('main.profile'))

@auth.route('/signup')
def signup():
    return render_template('signup.html')

@auth.route('/signup', methods=['POST'])
def signup_post():
    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')

    user = User.query.filter_by(email=email).first()
    if user:
        flash('Email address already exists')
        return redirect(url_for('auth.signup'))
    
    new_user = User(email=email,name=name,password=generate_password_hash(password,method='sha256'))
    db.session.add(new_user)
    db.session.commit()
    return redirect(url_for('auth.login'))

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))


