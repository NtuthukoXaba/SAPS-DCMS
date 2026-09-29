"""Public pages: homepage, kiosk check-in, case tracking, login and logout."""
from flask import (Blueprint, current_app, flash, jsonify, redirect, render_template,
                   request, session, url_for)
from werkzeug.security import check_password_hash

from database import audit, execute, next_checkin_ref, now, query

bp = Blueprint('public', __name__)

LANGUAGES = ['English', 'isiZulu', 'isiXhosa', 'Afrikaans', 'Sepedi', 'Setswana', 'Sesotho',
             'Xitsonga', 'siSwati', 'Tshivenda', 'isiNdebele']
VISIT_REASONS = ['Report a crime', 'Follow up on a case', 'Give a statement', 'Other enquiry']


@bp.route('/')
def index():
    stations = query('SELECT id, name FROM stations ORDER BY id')
    return render_template('index.html', stations=stations, languages=LANGUAGES, reasons=VISIT_REASONS)


@bp.post('/api/checkin')
def api_checkin():
    """Kiosk check-in: records that the person was at the station, before any officer is involved."""
    data = request.get_json(silent=True) or request.form
    name = (data.get('full_name') or '').strip()
    id_no = (data.get('id_no') or '').replace(' ', '')
    reason = data.get('reason') or VISIT_REASONS[0]
    language = data.get('language') or 'English'
    station = query('SELECT id, name FROM stations WHERE id = ?', (data.get('station_id'),), one=True)

    if len(name) < 2:
        return jsonify(ok=False, error='Please enter your full name.'), 400
    if not (id_no.isdigit() and len(id_no) == 13):
        return jsonify(ok=False, error='Please enter a valid 13-digit ID number.'), 400
    if not station:
        return jsonify(ok=False, error='Please choose your police station.'), 400

    ref = next_checkin_ref()
    created = now()
    execute('INSERT INTO checkins (ref, full_name, id_no, reason, language, station_id, created_at) VALUES (?,?,?,?,?,?,?)',
            (ref, name, id_no, reason, language, station['id'], created))
    audit('CHECK_IN', ref, reason, user_id=None, actor=f'Kiosk – {station["name"]}')
    return jsonify(ok=True, ref=ref, time=created[11:16], station=station['name'])


@bp.post('/api/track')
def api_track():
    """Complainant looks up their own case with docket number + ID number."""
    data = request.get_json(silent=True) or request.form
    number = (data.get('docket') or '').strip().upper()
    id_no = (data.get('id_no') or '').replace(' ', '')
    d = query('SELECT d.*, u.full_name AS detective FROM dockets d LEFT JOIN users u ON u.id = d.detective_id '
              'WHERE d.number = ? AND d.id_no = ?', (number, id_no), one=True)
    if not d:
        return jsonify(ok=False, error='No case matches those details. Check the docket number and ID number.'), 404
    return jsonify(ok=True, number=d['number'], crime=d['crime_type'], status=d['status'],
                   detective=d['detective'] or 'Not yet assigned', updated=d['updated_at'][:16])


@bp.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('common.dashboard'))

    error, persal = None, ''
    if request.method == 'POST':
        persal = request.form.get('persal', '').strip()
        password = request.form.get('password', '')
        user = query('SELECT u.*, s.name AS station_name FROM users u LEFT JOIN stations s ON s.id = u.station_id '
                     'WHERE persal = ?', (persal,), one=True)

        if user and user['status'] == 'Locked':
            error = 'This account is locked after too many wrong passwords. Contact the System Administrator.'
        elif user and user['status'] in ('Pending', 'Inactive'):
            error = f'This account is {user["status"].lower()}. Contact the System Administrator.'
        elif user and check_password_hash(user['password_hash'], password):
            execute('UPDATE users SET failed_attempts = 0, last_login = ? WHERE id = ?', (now(), user['id']))
            session.clear()
            session.update(user_id=user['id'], role=user['role'], name=user['full_name'],
                           persal=user['persal'], station_id=user['station_id'], station=user['station_name'])
            audit('LOGIN', user['persal'], 'Signed in')
            nxt = request.args.get('next', '')
            return redirect(nxt if nxt.startswith('/') and not nxt.startswith('//') else url_for('common.dashboard'))
        else:
            error = 'Incorrect personnel number or password.'
            if user:
                attempts = user['failed_attempts'] + 1
                limit = current_app.config['MAX_FAILED_LOGINS']
                if attempts >= limit:
                    execute("UPDATE users SET failed_attempts = ?, status = 'Locked' WHERE id = ?", (attempts, user['id']))
                    error = 'Too many wrong passwords. This account is now locked. Contact the System Administrator.'
                    audit('ACCOUNT_LOCKED', user['persal'], f'{attempts} failed attempts', user_id=user['id'], actor=user['full_name'])
                else:
                    execute('UPDATE users SET failed_attempts = ? WHERE id = ?', (attempts, user['id']))
                    error += f' {limit - attempts} attempt{"s" if limit - attempts != 1 else ""} left before the account locks.'
            audit('LOGIN_FAILED', persal, 'Wrong personnel number or password', user_id=None, actor='Unknown')

    return render_template('login.html', error=error, persal=persal,
                           show_demo=current_app.config['SHOW_DEMO_ACCOUNTS'])


@bp.route('/logout')
def logout():
    if 'user_id' in session:
        audit('LOGOUT', session.get('persal', ''), 'Signed out')
    session.clear()
    flash('You have been signed out.', 'success')
    return redirect(url_for('public.login'))
