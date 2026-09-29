"""CSC Official (front desk): check-in queue, register cases, log refusals, dockets, search, reports."""
from flask import Blueprint, abort, flash, redirect, render_template, request, session, url_for

from auth import role_required
from database import (CRIME_TYPES, REFUSAL_REASONS, STATUSES, audit, execute, get_db,
                      next_docket_number, now, query, scalar)
from routes.common import docket_bundle

bp = Blueprint('csc', __name__, url_prefix='/csc')


def waiting_checkins():
    return query("SELECT *, CAST((julianday('now','localtime') - julianday(created_at)) * 1440 AS INTEGER) AS wait "
                 "FROM checkins WHERE station_id = ? AND status = 'Waiting' ORDER BY created_at",
                 (session['station_id'],))


@bp.route('/')
@role_required('csc')
def dashboard():
    uid = session['user_id']
    stats = {
        'waiting': scalar("SELECT COUNT(*) FROM checkins WHERE station_id=? AND status='Waiting'", (session['station_id'],)),
        'today': scalar("SELECT COUNT(*) FROM dockets WHERE registered_by=? AND date(created_at)=date('now','localtime')", (uid,)),
        'month': scalar("SELECT COUNT(*) FROM dockets WHERE registered_by=? AND strftime('%Y-%m',created_at)=strftime('%Y-%m','now','localtime')", (uid,)),
        'refusals': scalar("SELECT COUNT(*) FROM refusals WHERE officer_id=? AND date(created_at)=date('now','localtime')", (uid,)),
    }
    recent = query('SELECT * FROM dockets WHERE registered_by=? ORDER BY created_at DESC LIMIT 5', (uid,))
    return render_template('csc/dashboard.html', stats=stats, checkins=waiting_checkins()[:5], recent=recent)


@bp.route('/queue')
@role_required('csc')
def queue():
    return render_template('csc/queue.html', checkins=waiting_checkins(), reasons=REFUSAL_REASONS)


@bp.post('/refuse')
@role_required('csc')
def refuse():
    ref = request.form.get('ref', '')
    reason = request.form.get('reason', '')
    notes = request.form.get('notes', '').strip()
    c = query("SELECT * FROM checkins WHERE ref=? AND station_id=? AND status='Waiting'", (ref, session['station_id']), one=True)
    if not c:
        flash('That check-in is no longer waiting.', 'error')
    elif reason not in REFUSAL_REASONS:
        flash('Please choose a refusal reason.', 'error')
    elif reason == 'Other' and len(notes) < 5:
        flash('Please explain the reason in the notes when choosing "Other".', 'error')
    else:
        db = get_db()
        t = now()
        db.execute('INSERT INTO refusals (checkin_id, reason, notes, officer_id, created_at) VALUES (?,?,?,?,?)',
                   (c['id'], reason, notes, session['user_id'], t))
        db.execute("UPDATE checkins SET status='Refused', handled_by=?, handled_at=? WHERE id=?", (session['user_id'], t, c['id']))
        db.commit()
        audit('CHECKIN_REFUSE', ref, reason)
        flash(f'Refusal logged for {c["full_name"]} ({ref}). The Station Commander can see this record.', 'success')
    return redirect(url_for('csc.queue'))


REG_FIELDS = ['checkin_ref', 'full_name', 'id_no', 'contact', 'email', 'address', 'date', 'time',
              'location', 'crime', 'priority', 'description']


def validate_case(form):
    errors = {}
    id_digits = form['id_no'].replace(' ', '')
    phone = form['contact'].replace(' ', '')
    if len(form['full_name']) < 2:
        errors['full_name'] = 'Full name is required.'
    if not (id_digits.isdigit() and len(id_digits) == 13):
        errors['id_no'] = 'Enter a valid 13-digit ID number.'
    if not (phone.isdigit() and len(phone) == 10):
        errors['contact'] = 'Enter a valid 10-digit contact number.'
    if form['email'] and ('@' not in form['email'] or '.' not in form['email'].split('@')[-1]):
        errors['email'] = 'Enter a valid email address.'
    if len(form['address']) < 4:
        errors['address'] = 'Address is required.'
    if not form['date']:
        errors['date'] = 'Date of incident is required.'
    elif form['date'] > now()[:10]:
        errors['date'] = 'Date of incident cannot be in the future.'
    if not form['time']:
        errors['time'] = 'Time of incident is required.'
    if form['crime'] not in CRIME_TYPES:
        errors['crime'] = 'Please select a crime / offence type.'
    if len(form['description']) < 10:
        errors['description'] = 'Description is required (at least 10 characters).'
    return errors


@bp.route('/register', methods=['GET', 'POST'])
@role_required('csc')
def register():
    checkins = waiting_checkins()
    form = {k: '' for k in REG_FIELDS}
    form['priority'] = 'Medium'
    pre = next((c for c in checkins if c['ref'] == request.args.get('checkin')), None)
    if pre:
        form.update(checkin_ref=pre['ref'], full_name=pre['full_name'], id_no=pre['id_no'])
    errors = {}

    if request.method == 'POST':
        form = {k: request.form.get(k, '').strip() for k in REG_FIELDS}
        errors = validate_case(form)
        if not errors:
            db = get_db()
            checkin = None
            if form['checkin_ref']:
                checkin = db.execute("SELECT * FROM checkins WHERE ref=? AND status='Waiting' AND station_id=?",
                                     (form['checkin_ref'], session['station_id'])).fetchone()
            number = next_docket_number(db)
            t = now()
            db.execute('INSERT INTO dockets (number, checkin_id, station_id, complainant, id_no, contact, email, address, '
                       'incident_date, incident_time, location, crime_type, priority, description, status, registered_by, created_at, updated_at) '
                       "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,'Unassigned',?,?,?)",
                       (number, checkin['id'] if checkin else None, session['station_id'], form['full_name'],
                        form['id_no'].replace(' ', ''), form['contact'], form['email'], form['address'], form['date'],
                        form['time'], form['location'], form['crime'],
                        form['priority'] if form['priority'] in ('High', 'Medium', 'Low') else 'Medium',
                        form['description'], session['user_id'], t, t))
            if checkin:
                db.execute("UPDATE checkins SET status='Registered', handled_by=?, handled_at=? WHERE id=?",
                           (session['user_id'], t, checkin['id']))
            db.commit()
            audit('CASE_REGISTER', number, f'{form["crime"]} – {form["full_name"]}')
            flash(f'Case registered successfully. Docket number: {number}. Give this number to the complainant.', 'success')
            return redirect(url_for('csc.docket', number=number))

    return render_template('csc/register.html', form=form, errors=errors, crime_types=CRIME_TYPES, checkins=checkins)


@bp.route('/dockets')
@role_required('csc')
def dockets():
    status = request.args.get('status', 'All')
    uid = session['user_id']
    rows = query('SELECT d.*, u.full_name AS detective FROM dockets d LEFT JOIN users u ON u.id = d.detective_id '
                 'WHERE registered_by = ? ' + ('' if status == 'All' else 'AND d.status = ? ') + 'ORDER BY d.created_at DESC',
                 (uid,) if status == 'All' else (uid, status))
    counts = {s: scalar('SELECT COUNT(*) FROM dockets WHERE registered_by=? AND status=?', (uid, s)) for s in STATUSES}
    counts['All'] = sum(counts.values())
    return render_template('csc/dockets.html', dockets=rows, status=status, counts=counts, statuses=STATUSES)


@bp.route('/dockets/<number>')
@role_required('csc')
def docket(number):
    b = docket_bundle(number)
    if b['d']['station_id'] != session['station_id']:
        abort(404)
    return render_template('csc/docket.html', **b)


@bp.route('/search')
@role_required('csc')
def search():
    q = request.args.get('q', '').strip()
    crime = request.args.get('crime', '')
    results = None
    if q or crime:
        sql = ('SELECT d.*, u.full_name AS detective FROM dockets d LEFT JOIN users u ON u.id = d.detective_id '
               'WHERE d.station_id = ?')
        args = [session['station_id']]
        if q:
            sql += ' AND (d.number LIKE ? OR d.complainant LIKE ? OR d.id_no LIKE ?)'
            args += [f'%{q.upper()}%', f'%{q}%', f'%{q.replace(" ", "")}%']
        if crime:
            sql += ' AND d.crime_type = ?'
            args.append(crime)
        results = query(sql + ' ORDER BY d.created_at DESC LIMIT 100', args)
        audit('DOCKET_SEARCH', '', f'q="{q}" crime="{crime}" results={len(results)}')
    return render_template('csc/search.html', q=q, crime=crime, results=results, crime_types=CRIME_TYPES)


@bp.route('/reports')
@role_required('csc')
def reports():
    uid = session['user_id']
    by_crime = query('SELECT crime_type, COUNT(*) AS n FROM dockets WHERE registered_by=? GROUP BY crime_type ORDER BY n DESC', (uid,))
    refusals = query('SELECT r.*, c.ref, c.full_name FROM refusals r JOIN checkins c ON c.id = r.checkin_id '
                     'WHERE officer_id=? ORDER BY r.created_at DESC', (uid,))
    avg_wait = scalar("SELECT AVG((julianday(handled_at) - julianday(created_at)) * 1440) FROM checkins WHERE handled_by=?", (uid,))
    stats = {'total': scalar('SELECT COUNT(*) FROM dockets WHERE registered_by=?', (uid,)),
             'refusals': len(refusals),
             'waiting': scalar("SELECT COUNT(*) FROM checkins WHERE station_id=? AND status='Waiting'", (session['station_id'],)),
             'avg_wait': round(avg_wait) if avg_wait else 0}
    top = by_crime[0]['n'] if by_crime else 1
    return render_template('csc/reports.html', stats=stats, by_crime=by_crime, top=top, refusals=refusals)
