"""Login, role checks and CSRF protection."""
import secrets
from functools import wraps

from flask import abort, flash, redirect, request, session, url_for

from database import query


def current_user():
    if 'user_id' not in session:
        return None
    return query('SELECT u.*, s.name AS station_name FROM users u LEFT JOIN stations s ON s.id = u.station_id '
                 'WHERE u.id = ?', (session['user_id'],), one=True)


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please sign in to continue.', 'error')
            return redirect(url_for('public.login', next=request.path))
        user = current_user()
        if user is None or user['status'] != 'Active':
            session.clear()
            flash('Your account is not active. Contact the System Administrator.', 'error')
            return redirect(url_for('public.login'))
        return view(*args, **kwargs)
    return wrapper


def role_required(*roles):
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapper(*args, **kwargs):
            if session.get('role') not in roles:
                abort(403)
            return view(*args, **kwargs)
        return wrapper
    return decorator


# ------------------------------------------------------------------
# CSRF: every POST must include the token from the session.
# Forms:  <input type="hidden" name="_csrf" value="{{ csrf_token() }}">
# fetch:  header  X-CSRF-Token
# ------------------------------------------------------------------
def csrf_token():
    if '_csrf' not in session:
        session['_csrf'] = secrets.token_hex(16)
    return session['_csrf']


def csrf_protect():
    if request.method == 'POST':
        sent = request.form.get('_csrf') or request.headers.get('X-CSRF-Token')
        if not sent or sent != session.get('_csrf'):
            abort(400, description='Your form has expired. Please go back, refresh the page and try again.')
