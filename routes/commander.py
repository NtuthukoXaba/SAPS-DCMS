"""Station Commander: assign dockets, oversee refusals and stalled cases, approve closures, reports, audit log."""
from datetime import datetime, timedelta

from flask import (Blueprint, abort, current_app, flash, redirect, render_template, request,
                   session, url_for)

from auth import role_required
from database import (CRIME_TYPES, PRIORITIES, STATUSES, TIME_FMT, audit, execute, get_db, now,
                      query, scalar)
from routes.common import docket_bundle

bp = Blueprint('commander', __name__, url_prefix='/commander')


def cutoff(**kw):
    return (datetime.now() - timedelta(**kw)).strftime(TIME_FMT)


def station():
    return session['station_id']


def stalled_dockets():
    return query("SELECT d.*, u.full_name AS detective, CAST(julianday('now','localtime') - julianday(d.updated_at) AS INTEGER) AS idle "
                 "FROM dockets d LEFT JOIN users u ON u.id = d.detective_id "
                 "WHERE d.station_id = ? AND d.status IN ('Assigned','Under investigation') AND d.updated_at < ? "
                 "ORDER BY d.updated_at", (station(), cutoff(days=current_app.config['STALLED_DAYS'])))


def unmatched_checkins():
    return query("SELECT *, CAST((julianday('now','localtime') - julianday(created_at)) * 24 AS INTEGER) AS hours "
                 "FROM checkins WHERE station_id = ? AND status = 'Waiting' AND created_at < ? ORDER BY created_at",
                 (station(), cutoff(hours=current_app.config['UNMATCHED_HOURS'])))


def detectives_with_load():
    return query("SELECT u.id, u.full_name, u.status, "
                 "(SELECT COUNT(*) FROM dockets d WHERE d.detective_id = u.id AND d.status NOT IN ('Closed')) AS open_cases, "
                 "(SELECT COUNT(*) FROM dockets d WHERE d.detective_id = u.id AND d.status = 'Closed') AS closed_cases, "
                 "(SELECT COUNT(*) FROM dockets d WHERE d.detective_id = u.id AND d.status IN ('Assigned','Under investigation') "
                 "   AND d.updated_at < ?) AS stalled "
                 "FROM users u WHERE u.role = 'detective' AND u.station_id = ? ORDER BY open_cases DESC, u.full_name",
                 (cutoff(days=current_app.config['STALLED_DAYS']), station()))


@bp.route('/')
@role_required('commander')
def dashboard():
    s = station()
    stats = {
        'unassigned': scalar("SELECT COUNT(*) FROM dockets WHERE station_id=? AND status='Unassigned'", (s,)),
        'stalled': len(stalled_dockets()),
        'refusals_week': scalar("SELECT COUNT(*) FROM refusals r JOIN checkins c ON c.id=r.checkin_id "
                                "WHERE c.station_id=? AND r.created_at >= ?", (s, cutoff(days=7))),
        'closure': scalar("SELECT COUNT(*) FROM dockets WHERE station_id=? AND status='Ready for closure'", (s,)),
    }
    return render_template('commander/dashboard.html', stats=stats,
                           stalled=stalled_dockets(), unmatched=unmatched_checkins(),
                           detectives=detectives_with_load(),
                           unassigned=query("SELECT * FROM dockets WHERE station_id=? AND status='Unassigned' "
                                            "ORDER BY CASE priority WHEN 'High' THEN 0 WHEN 'Medium' THEN 1 ELSE 2 END, created_at LIMIT 5", (s,)),
                           closure=query("SELECT d.*, u.full_name AS detective FROM dockets d LEFT JOIN users u ON u.id=d.detective_id "
                                         "WHERE d.station_id=? AND d.status='Ready for closure' ORDER BY d.updated_at", (s,)),
                           refusals=query("SELECT r.reason, COUNT(*) AS n FROM refusals r JOIN checkins c ON c.id=r.checkin_id "
                                          "WHERE c.station_id=? AND r.created_at >= ? GROUP BY r.reason ORDER BY n DESC", (s, cutoff(days=7))))


@bp.route('/unassigned')
@role_required('commander')
def unassigned():
    rows = query("SELECT d.*, u.full_name AS registered_name FROM dockets d JOIN users u ON u.id = d.registered_by "
                 "WHERE d.station_id=? AND d.status='Unassigned' "
                 "ORDER BY CASE priority WHEN 'High' THEN 0 WHEN 'Medium' THEN 1 ELSE 2 END, d.created_at", (station(),))
    stats = {
        'unassigned': len(rows),
        'assigned_today': scalar("SELECT COUNT(*) FROM dockets WHERE station_id=? AND date(assigned_at)=date('now','localtime')", (station(),)),
        'month': scalar("SELECT COUNT(*) FROM dockets WHERE station_id=? AND strftime('%Y-%m',created_at)=strftime('%Y-%m','now','localtime')", (station(),)),
        'closed_month': scalar("SELECT COUNT(*) FROM dockets WHERE station_id=? AND strftime('%Y-%m',closed_at)=strftime('%Y-%m','now','localtime')", (station(),)),
    }
    return render_template('commander/unassigned.html', dockets=rows, stats=stats,
                           detectives=detectives_with_load(), priorities=PRIORITIES)


@bp.post('/assign')
@role_required('commander')
def assign():
    number = request.form.get('number', '')
    det_id = request.form.get('detective_id', type=int)
    priority = request.form.get('priority', '')
    d = query('SELECT * FROM dockets WHERE number=? AND station_id=?', (number, station()), one=True)
    det = query("SELECT * FROM users WHERE id=? AND role='detective' AND station_id=? AND status='Active'",
                (det_id, station()), one=True)
    if not d or not det:
        flash('Please choose a docket and an active detective.', 'error')
        return redirect(request.referrer or url_for('commander.unassigned'))
    if d['status'] == 'Closed':
        flash('A closed docket cannot be reassigned.', 'error')
        return redirect(url_for('commander.docket', number=number))
    t = now()
    new_status = 'Assigned' if d['status'] == 'Unassigned' else d['status']
    execute('UPDATE dockets SET detective_id=?, priority=?, status=?, assigned_at=?, updated_at=? WHERE id=?',
            (det['id'], priority if priority in PRIORITIES else d['priority'], new_status, t, t, d['id']))
    action = 'DOCKET_ASSIGN' if d['detective_id'] is None else 'DOCKET_REASSIGN'
    audit(action, number, f'Assigned to {det["full_name"]} · priority {priority or d["priority"]}')
    flash(f'{number} assigned to {det["full_name"]}.', 'success')
    return redirect(request.referrer or url_for('commander.unassigned'))


@bp.route('/dockets')
@role_required('commander')
def dockets():
    f = {k: request.args.get(k, '') for k in ('status', 'crime', 'detective', 'q')}
    sql = ("SELECT d.*, u.full_name AS detective FROM dockets d LEFT JOIN users u ON u.id = d.detective_id "
           "WHERE d.station_id = ?")
    args = [station()]
    if f['status']:
        sql += ' AND d.status = ?'; args.append(f['status'])
    if f['crime']:
        sql += ' AND d.crime_type = ?'; args.append(f['crime'])
    if f['detective']:
        sql += ' AND d.detective_id = ?'; args.append(f['detective'])
    if f['q']:
        sql += ' AND (d.number LIKE ? OR d.complainant LIKE ? OR d.id_no LIKE ?)'
        args += [f'%{f["q"].upper()}%', f'%{f["q"]}%', f'%{f["q"]}%']
    rows = query(sql + ' ORDER BY d.created_at DESC', args)
    det_options = [(d['id'], d['full_name']) for d in detectives_with_load()]
    return render_template('commander/dockets.html', dockets=rows, f=f, statuses=STATUSES,
                           crime_types=CRIME_TYPES, det_options=det_options)


@bp.route('/dockets/<number>')
@role_required('commander')
def docket(number):
    b = docket_bundle(number)
    if b['d']['station_id'] != station():
        abort(404)
    return render_template('commander/docket.html', detectives=detectives_with_load(), priorities=PRIORITIES, **b)


@bp.post('/dockets/<number>/closure')
@role_required('commander')
def closure(number):
    d = query('SELECT * FROM dockets WHERE number=? AND station_id=?', (number, station()), one=True)
    if not d or d['status'] != 'Ready for closure':
        flash('This docket is not waiting for closure approval.', 'error')
        return redirect(url_for('commander.docket', number=number))
    decision = request.form.get('decision')
    comment = request.form.get('comment', '').strip()
    t = now()
    db = get_db()
    if decision == 'approve':
        db.execute("UPDATE dockets SET status='Closed', closed_at=?, updated_at=? WHERE id=?", (t, t, d['id']))
        msg, action = f'{number} has been closed.', 'CASE_CLOSE_APPROVE'
    elif decision == 'return':
        if len(comment) < 5:
            flash('Please tell the detective what still needs to be done.', 'error')
            return redirect(url_for('commander.docket', number=number))
        db.execute("UPDATE dockets SET status='Under investigation', updated_at=? WHERE id=?", (t, d['id']))
        msg, action = f'{number} was sent back to the detective.', 'CASE_CLOSE_RETURN'
    else:
        abort(400)
    if comment:
        db.execute('INSERT INTO case_notes (docket_id, note, author_id, created_at) VALUES (?,?,?,?)',
                   (d['id'], f'[Commander] {comment}', session['user_id'], t))
    db.commit()
    audit(action, number, comment)
    flash(msg, 'success')
    return redirect(url_for('commander.docket', number=number))


@bp.post('/dockets/<number>/priority')
@role_required('commander')
def priority(number):
    p = request.form.get('priority')
    d = query('SELECT * FROM dockets WHERE number=? AND station_id=?', (number, station()), one=True)
    if not d or p not in PRIORITIES:
        abort(400)
    execute('UPDATE dockets SET priority=?, updated_at=? WHERE id=?', (p, now(), d['id']))
    audit('PRIORITY_CHANGE', number, f'{d["priority"]} → {p}')
    flash(f'Priority of {number} changed to {p}.', 'success')
    return redirect(url_for('commander.docket', number=number))


@bp.route('/detectives')
@role_required('commander')
def detectives():
    dets = detectives_with_load()
    cases = query("SELECT d.number, d.crime_type, d.status, d.priority, d.detective_id, d.updated_at FROM dockets d "
                  "WHERE d.station_id=? AND d.detective_id IS NOT NULL AND d.status != 'Closed' ORDER BY d.updated_at", (station(),))
    return render_template('commander/detectives.html', detectives=dets, cases=cases)


@bp.route('/refusals')
@role_required('commander')
def refusals():
    rows = query("SELECT r.*, c.ref, c.full_name, c.id_no, c.created_at AS checked_in, u.full_name AS officer "
                 "FROM refusals r JOIN checkins c ON c.id = r.checkin_id JOIN users u ON u.id = r.officer_id "
                 "WHERE c.station_id=? ORDER BY r.created_at DESC", (station(),))
    today = query("SELECT c.*, u.full_name AS handled_name FROM checkins c LEFT JOIN users u ON u.id = c.handled_by "
                  "WHERE c.station_id=? AND date(c.created_at)=date('now','localtime') ORDER BY c.created_at DESC", (station(),))
    return render_template('commander/refusals.html', refusals=rows, unmatched=unmatched_checkins(), today=today)


@bp.route('/reports')
@role_required('commander')
def reports():
    s = station()
    by_status = {st: scalar('SELECT COUNT(*) FROM dockets WHERE station_id=? AND status=?', (s, st)) for st in STATUSES}
    by_crime = query('SELECT crime_type, COUNT(*) AS n FROM dockets WHERE station_id=? GROUP BY crime_type ORDER BY n DESC', (s,))
    by_reason = query('SELECT r.reason, COUNT(*) AS n FROM refusals r JOIN checkins c ON c.id=r.checkin_id '
                      'WHERE c.station_id=? GROUP BY r.reason ORDER BY n DESC', (s,))
    avg_assign = scalar('SELECT AVG((julianday(assigned_at) - julianday(created_at)) * 24) FROM dockets '
                        'WHERE station_id=? AND assigned_at IS NOT NULL', (s,))
    avg_close = scalar('SELECT AVG(julianday(closed_at) - julianday(created_at)) FROM dockets '
                       'WHERE station_id=? AND closed_at IS NOT NULL', (s,))
    total_checkins = scalar('SELECT COUNT(*) FROM checkins WHERE station_id=?', (s,))
    metrics = {
        'total': sum(by_status.values()),
        'avg_assign': round(avg_assign, 1) if avg_assign else 0,
        'avg_close': round(avg_close, 1) if avg_close else 0,
        'refusal_rate': round(100 * sum(r['n'] for r in by_reason) / total_checkins) if total_checkins else 0,
    }
    return render_template('commander/reports.html', by_status=by_status, by_crime=by_crime, by_reason=by_reason,
                           metrics=metrics, top_crime=by_crime[0]['n'] if by_crime else 1,
                           top_status=max(by_status.values()) or 1, detectives=detectives_with_load())


@bp.route('/audit', endpoint='audit')
@role_required('commander')
def audit_log():
    page = max(request.args.get('page', 1, type=int), 1)
    q = request.args.get('q', '').strip()
    st = query('SELECT name FROM stations WHERE id=?', (station(),), one=True)['name']
    where = ("WHERE (a.user_id IN (SELECT id FROM users WHERE station_id = ?) OR a.actor = ? "
             "OR a.record IN (SELECT number FROM dockets WHERE station_id = ?))")
    args = [station(), f'Kiosk – {st}', station()]
    if q:
        where += ' AND (a.action LIKE ? OR a.record LIKE ? OR a.actor LIKE ?)'
        args += [f'%{q}%'] * 3
    total = scalar(f'SELECT COUNT(*) FROM audit_log a {where}', args)
    rows = query(f'SELECT a.* FROM audit_log a {where} ORDER BY a.id DESC LIMIT 25 OFFSET ?', args + [(page - 1) * 25])
    return render_template('commander/audit.html', rows=rows, page=page, pages=max((total + 24) // 25, 1), q=q, total=total)

