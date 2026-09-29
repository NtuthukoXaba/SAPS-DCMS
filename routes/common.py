"""Pages shared by all signed-in staff: dashboard redirect, profile, docket view helpers, evidence files."""
import os

from flask import (Blueprint, abort, current_app, flash, redirect, render_template,
                   request, send_from_directory, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

from auth import current_user, login_required
from database import audit, execute, query

bp = Blueprint('common', __name__)


@bp.route('/dashboard')
@login_required
def dashboard():
    return redirect(url_for(f'{session["role"]}.dashboard'))


@bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = current_user()
    if request.method == 'POST':
        current = request.form.get('current', '')
        new = request.form.get('new', '')
        confirm = request.form.get('confirm', '')
        if not check_password_hash(user['password_hash'], current):
            flash('Your current password is not correct.', 'error')
        elif len(new) < 8 or new.isalpha() or new.isdigit():
            flash('The new password must be at least 8 characters and include letters and numbers.', 'error')
        elif new != confirm:
            flash('The new passwords do not match.', 'error')
        else:
            execute('UPDATE users SET password_hash = ? WHERE id = ?', (generate_password_hash(new), user['id']))
            audit('PASSWORD_CHANGE', user['persal'], 'Changed own password')
            flash('Your password has been changed.', 'success')
        return redirect(url_for('common.profile'))
    return render_template('profile.html', user=user)


def docket_bundle(number):
    """Everything about one docket (used by the docket detail pages)."""
    d = query('SELECT d.*, s.name AS station_name, r.full_name AS registered_name, det.full_name AS detective_name, '
              'c.ref AS checkin_ref FROM dockets d '
              'JOIN stations s ON s.id = d.station_id JOIN users r ON r.id = d.registered_by '
              'LEFT JOIN users det ON det.id = d.detective_id LEFT JOIN checkins c ON c.id = d.checkin_id '
              'WHERE d.number = ?', (number,), one=True)
    if not d:
        abort(404)
    return {
        'd': d,
        'suspects': query('SELECT s.*, u.full_name AS added_name FROM suspects s JOIN users u ON u.id = s.added_by '
                          'WHERE docket_id = ? ORDER BY s.id', (d['id'],)),
        'witnesses': query('SELECT w.*, u.full_name AS added_name FROM witnesses w JOIN users u ON u.id = w.added_by '
                           'WHERE docket_id = ? ORDER BY w.id', (d['id'],)),
        'evidence': query('SELECT e.*, u.full_name AS added_name FROM evidence e JOIN users u ON u.id = e.uploaded_by '
                          'WHERE docket_id = ? ORDER BY e.id', (d['id'],)),
        'notes': query('SELECT n.*, u.full_name AS author FROM case_notes n JOIN users u ON u.id = n.author_id '
                       'WHERE docket_id = ? ORDER BY n.id DESC', (d['id'],)),
        'history': query('SELECT * FROM audit_log WHERE record = ? ORDER BY id DESC', (d['number'],)),
    }


def can_see_docket(d):
    role = session.get('role')
    if role == 'admin':
        return True
    if role == 'detective':
        return d['detective_id'] == session['user_id']
    return d['station_id'] == session.get('station_id')


@bp.route('/evidence/<int:evidence_id>')
@login_required
def evidence_file(evidence_id):
    e = query('SELECT e.*, d.detective_id, d.station_id, d.number FROM evidence e JOIN dockets d ON d.id = e.docket_id '
              'WHERE e.id = ?', (evidence_id,), one=True)
    if not e or not can_see_docket(e):
        abort(404)
    if not e['stored_name']:
        flash('This is a demo evidence record. No file is stored for it.', 'error')
        return redirect(request.referrer or url_for('common.dashboard'))
    audit('EVIDENCE_VIEW', e['number'], e['filename'])
    return send_from_directory(current_app.config['UPLOAD_FOLDER'], e['stored_name'],
                               as_attachment=False, download_name=e['filename'])
