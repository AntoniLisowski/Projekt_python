from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db   ##means from __init__.py import db
from flask_login import login_user, login_required, logout_user, current_user


auth = Blueprint('auth', __name__)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Pomyślnie zalogowano!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Złe hasło, spróbuj ponownie.', category='error')
        else:
            flash('E-mail nie istnieje.', category='error')

    return render_template("login.html", user=current_user)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Wylogowano.', category='error')
    return redirect(url_for('auth.login'))


@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':     
        email = request.form.get('email') 
        first_name = request.form.get('imie')
        haslo1 = request.form.get('haslo1')
        haslo2 = request.form.get('haslo2')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('E-mail już istnieje w bazie. Spróbuj się zalogować ponownie.', category='error')
        elif len(first_name) < 2:
            flash('Imię musi mieć więcej niż jedną literę.', category='error')
        elif haslo1 != haslo2:
            flash('Hasła się nie zgadzają.', category='error')
        elif len(haslo1) < 7:
            flash('Hasło musi mieć conajmniej 7 znaków.', category='error')
        else:
            new_user = User(email=email, first_name=first_name, password=generate_password_hash(
                haslo1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Konto utworzone!', category='success')
            return redirect(url_for('views.home'))

    return render_template("sign_up.html", user=current_user)
