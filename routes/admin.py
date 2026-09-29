"""System Administrator: users, roles, stations, audit log and system health."""
import csv
import io
import os
import secrets

from flask import (Blueprint, Response, abort, current_app, flash, redirect, render_template,
                   request, session, url_for)
from werkzeug.security import generate_password_hash

from auth import role_required
from database import (ROLE_NAMES, USER_STATUSES, audit, execute, now, query, scalar,
                      verify_audit_chain)

bp = Blueprint('admin', __name__, url_prefix='/admin')


def stations():
    return query('SELECT * FROM stations ORDER BY name')


def strong(pw):
    return len(pw) >= 8 and not pw.isalpha() and not pw.isdigit()


@bp.route('/')
@role_required('admin')
def dashboard():
    ok, checked, bad = verify_audit_chain()
    db_path = current_app.config['DATABASE']
    uploads = os.listdir(current_app.config['UPLOAD_FOLDER']) if os.path.isdir(current_app.config['UPLOAD_FOLDER']) else []
    health = {
        'audit_ok': ok, 'audit_checked': checked, 'audit_bad': bad,
        'db_size': f'{os.path.getsize(db_path) / 1024:.0f} KB' if os.path.exists(db_path) else '—',
        'uploads': len(uploads),
        'dockets': scalar('SELECT COUNT(*) FROM dockets'),
    }
    stats = {
        'active': scalar("SELECT COUNT(*) FROM users WHERE status='Active'"),
        'pending': scalar("SELECT COUNT(*) FROM users WHERE status='Pending'"),
        'locked': scalar("SELECT COUNT(*) FROM users WHERE status='Locked'"),
        'audit_today': scalar("SELECT COUNT(*) FROM audit_log WHERE date(created_at)=date('now','localtime')"),
    }
    attention = query("SELECT u.*, s.name AS station_name FROM users u LEFT JOIN stations s ON s.id=u.station_id "
                      "WHERE u.status IN ('Pending','Locked') ORDER BY u.status")
    users = query('SELECT u.*, s.name AS station_name FROM users u LEFT JOIN stations s ON s.id=u.station_id '
                  'ORDER BY u.last_login IS NULL, u.last_login DESC LIMIT 6')
    latest = query('SELECT * FROM audit_log ORDER BY id DESC LIMIT 8')
    return render_template('admin/dashboard.html', stats=stats, health=health, attention=attention, users=users, latest=latest)


@bp.route('/users')
@role_required('admin')
def users():
    f = {k: request.args.get(k, '') for k in ('role', 'status', 'q')}
    sql = 'SELECT u.*, s.name AS station_name FROM users u LEFT JOIN stations s ON s.id=u.station_id WHERE 1=1'
    args = []
    if f['role']:
        sql += ' AND u.role=?'; args.append(f['role'])
    if f['status']:
        sql += ' AND u.status=?'; args.append(f['status'])
    if f['q']:
        sql += ' AND (u.full_name LIKE ? OR u.persal LIKE ? OR u.email LIKE ?)'; args += [f'%{f["q"]}%'] * 3
    rows = query(sql + ' ORDER BY u.role, u.full_name', args)
    return render_template('admin/users.html', users=rows, f=f, roles=ROLE_NAMES, statuses=USER_STATUSES)


def _user_form():
    return {k: request.form.get(k, '').strip() for k in ('persal', 'full_name', 'role', 'station_id', 'email', 'phone', 'status', 'password')}


def _validate(form, editing=None):
    errors = {}
    if not (form['persal'].isdigit() and 5 <= len(form['persal']) <= 10):
        errors['persal'] = 'Personnel number must be 5–10 digits.'
    elif scalar('SELECT COUNT(*) FROM users WHERE persal=? AND id != ?', (form['persal'], editing or 0)):
        errors['persal'] = 'This personnel number is already in use.'
    if len(form['full_name']) < 3:
        errors['full_name'] = 'Full name is required (include rank, e.g. "Const. T. Mabena").'
    if form['role'] not in ROLE_NAMES:
        errors['role'] = 'Choose a role.'
    if not scalar('SELECT COUNT(*) FROM stations WHERE id=?', (form['station_id'] or 0,)):
        errors['station_id'] = 'Choose a station.'
    if form['email'] and '@' not in form['email']:
        errors['email'] = 'Enter a valid email address.'
    if form['status'] not in USER_STATUSES:
        errors['status'] = 'Choose a status.'
    if editing is None and not strong(form['password']):
        errors['password'] = 'Password must be at least 8 characters with letters and numbers.'
    if editing is not None and form['password'] and not strong(form['password']):
        errors['password'] = 'New password must be at least 8 characters with letters and numbers.'
    return errors


@bp.route('/users/new', methods=['GET', 'POST'])
@role_required('admin')
def new_user():
    form = {'status': 'Active', 'role': 'csc', 'password': ''}
    errors = {}
    if request.method == 'POST':
        form = _user_form()
        errors = _validate(form)
        if not errors:
            execute('INSERT INTO users (persal, password_hash, full_name, role, station_id, email, phone, status, created_at) '
                    'VALUES (?,?,?,?,?,?,?,?,?)',
                    (form['persal'], generate_password_hash(form['password']), form['full_name'], form['role'],
                     int(form['station_id']), form['email'], form['phone'], form['status'], now()))
            audit('USER_CREATE', form['persal'], f'{form["full_name"]} as {ROLE_NAMES[form["role"]]}')
            flash(f'Account created for {form["full_name"]}. They can sign in with personnel number {form["persal"]}.', 'success')
            return redirect(url_for('admin.users'))
    return render_template('admin/user_form.html', form=form, errors=errors, stations=stations(),
                           roles=ROLE_NAMES, statuses=USER_STATUSES, editing=None,
                           suggested=secrets.token_urlsafe(6) + '9a')


@bp.route('/users/<int:uid>', methods=['GET', 'POST'])
@role_required('admin')
def edit_user(uid):
    user = query('SELECT * FROM users WHERE id=?', (uid,), one=True)
    if not user:
        abort(404)
    form = dict(user)
    form['password'] = ''
    errors = {}
    if request.method == 'POST':
        form = _user_form()
        errors = _validate(form, editing=uid)
        if uid == session['user_id'] and (form['role'] != 'admin' or form['status'] != 'Active'):
            errors['role'] = 'You cannot remove your own admin access or deactivate yourself.'
        if not errors:
            changes = [f'{k}: {user[k]} → {form[k]}' for k in ('full_name', 'role', 'station_id', 'email', 'phone', 'status')
                       if str(user[k] or '') != str(form[k] or '')]
            execute('UPDATE users SET persal=?, full_name=?, role=?, station_id=?, email=?, phone=?, status=?, '
                    'failed_attempts = CASE WHEN ? = \'Active\' THEN 0 ELSE failed_attempts END WHERE id=?',
                    (form['persal'], form['full_name'], form['role'], int(form['station_id']), form['email'], form['phone'],
                     form['status'], form['status'], uid))
            if form['password']:
                execute('UPDATE users SET password_hash=? WHERE id=?', (generate_password_hash(form['password']), uid))
                changes.append('password reset')
            audit('USER_UPDATE', form['persal'], '; '.join(changes) or 'No changes')
            flash(f'{form["full_name"]} updated.', 'success')
            return redirect(url_for('admin.users'))
    return render_template('admin/user_form.html', form=form, errors=errors, stations=stations(),
                           roles=ROLE_NAMES, statuses=USER_STATUSES, editing=user, suggested=None)


@bp.post('/users/<int:uid>/quick')
@role_required('admin')
def quick_action(uid):
    """One-click Approve / Unlock / Deactivate from the tables."""
    user = query('SELECT * FROM users WHERE id=?', (uid,), one=True)
    action = request.form.get('action')
    if not user or uid == session['user_id']:
        abort(400)
    new_status = {'approve': 'Active', 'unlock': 'Active', 'deactivate': 'Inactive'}.get(action)
    if not new_status:
        abort(400)
    execute('UPDATE users SET status=?, failed_attempts=0 WHERE id=?', (new_status, uid))
    audit(f'USER_{action.upper()}', user['persal'], user['full_name'])
    flash(f'{user["full_name"]}: {action}d.' if action != 'unlock' else f'{user["full_name"]} unlocked.', 'success')
    return redirect(request.referrer or url_for('admin.users'))


@bp.route('/stations', methods=['GET', 'POST'], endpoint='stations')
@role_required('admin')
def stations_page():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        province = request.form.get('province', '').strip() or 'Gauteng'
        if len(name) < 3:
            flash('Enter the station name.', 'error')
        elif scalar('SELECT COUNT(*) FROM stations WHERE name = ?', (name,)):
            flash('That station already exists.', 'error')
        else:
            execute('INSERT INTO stations (name, province, created_at) VALUES (?,?,?)', (name, province, now()))
            audit('STATION_CREATE', name, province)
            flash(f'Station {name} added.', 'success')
        return redirect(url_for('admin.stations'))
    rows = query("SELECT s.*, (SELECT COUNT(*) FROM users u WHERE u.station_id=s.id) AS users, "
                 "(SELECT COUNT(*) FROM dockets d WHERE d.station_id=s.id) AS dockets, "
                 "(SELECT COUNT(*) FROM dockets d WHERE d.station_id=s.id AND d.status != 'Closed') AS open_dockets "
                 "FROM stations s ORDER BY s.name")
    return render_template('admin/stations.html', stations=rows)



def _audit_filter():
    f = {k: request.args.get(k, '') for k in ('q', 'action', 'date_from', 'date_to')}
    where, args = 'WHERE 1=1', []
    if f['q']:
        where += ' AND (actor LIKE ? OR record LIKE ? OR details LIKE ?)'; args += [f'%{f["q"]}%'] * 3
    if f['action']:
        where += ' AND action = ?'; args.append(f['action'])
    if f['date_from']:
        where += ' AND date(created_at) >= ?'; args.append(f['date_from'])
    if f['date_to']:
        where += ' AND date(created_at) <= ?'; args.append(f['date_to'])
    return f, where, args


@bp.route('/audit', endpoint='audit')
@role_required('admin')
def audit_page():
    f, where, args = _audit_filter()
    page = max(request.args.get('page', 1, type=int), 1)
    total = scalar(f'SELECT COUNT(*) FROM audit_log {where}', args)
    rows = query(f'SELECT * FROM audit_log {where} ORDER BY id DESC LIMIT 30 OFFSET ?', args + [(page - 1) * 30])
    actions = [r[0] for r in query('SELECT DISTINCT action FROM audit_log ORDER BY action')]
    ok, checked, bad = verify_audit_chain()
    return render_template('admin/audit.html', rows=rows, f=f, page=page, pages=max((total + 29) // 30, 1),
                           total=total, actions=actions, chain_ok=ok, checked=checked, bad=bad)



@bp.route('/audit/export')
@role_required('admin')
def audit_export():
    f, where, args = _audit_filter()
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(['id', 'time', 'actor', 'action', 'record', 'details', 'ip', 'hash'])
    for r in query(f'SELECT * FROM audit_log {where} ORDER BY id', args):
        w.writerow([r['id'], r['created_at'], r['actor'], r['action'], r['record'], r['details'], r['ip'], r['hash']])
    audit('AUDIT_EXPORT', '', 'Exported audit log to CSV')
    return Response(out.getvalue(), mimetype='text/csv',
                    headers={'Content-Disposition': 'attachment; filename=saps_dcms_audit_log.csv'})
