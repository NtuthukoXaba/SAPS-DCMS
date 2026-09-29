"""Detective: assigned cases, investigation workspace (suspects, witnesses, evidence, notes), submit for closure."""
import hashlib
import os
import uuid

from flask import (Blueprint, abort, current_app, flash, redirect, render_template, request,
                   session, url_for)
from werkzeug.utils import secure_filename

from auth import role_required
from database import SUSPECT_STATUSES, audit, execute, get_db, now, query, scalar
from routes.common import docket_bundle

bp = Blueprint('detective', __name__, url_prefix='/detective')

IDLE_DAYS = 10     # "needs an update" after this many days without activity


def my_case(number, editable=True):
    """Load a docket assigned to the signed-in detective (404 otherwise)."""
    d = query('SELECT * FROM dockets WHERE number=? AND detective_id=?', (number, session['user_id']), one=True)
    if not d:
        abort(404)
    if editable and d['status'] in ('Ready for closure', 'Closed'):
        flash('This case has been submitted for closure and can no longer be changed.', 'error')
        return None
    return d


def touch(docket_id, progress_floor=None):
    """Mark activity on a case (moves Assigned → Under investigation)."""
    d = query('SELECT status, progress FROM dockets WHERE id=?', (docket_id,), one=True)
    status = 'Under investigation' if d['status'] == 'Assigned' else d['status']
    progress = max(d['progress'], progress_floor or 0)
    execute('UPDATE dockets SET updated_at=?, status=?, progress=? WHERE id=?', (now(), status, progress, docket_id))


def back(number, tab):
    return redirect(url_for('detective.case', number=number, tab=tab))


@bp.route('/')
@role_required('detective')
def dashboard():
    uid = session['user_id']
    cases = query("SELECT *, CAST(julianday('now','localtime') - julianday(updated_at) AS INTEGER) AS idle "
                  "FROM dockets WHERE detective_id=? AND status != 'Closed' "
                  "ORDER BY CASE priority WHEN 'High' THEN 0 WHEN 'Medium' THEN 1 ELSE 2 END, updated_at", (uid,))
    stats = {
        'open': sum(1 for c in cases if c['status'] in ('Assigned', 'Under investigation')),
        'high': sum(1 for c in cases if c['priority'] == 'High' and c['status'] != 'Ready for closure'),
        'idle': sum(1 for c in cases if c['idle'] >= IDLE_DAYS and c['status'] != 'Ready for closure'),
        'closure': sum(1 for c in cases if c['status'] == 'Ready for closure'),
    }
    new = [c for c in cases if c['status'] == 'Assigned']
    activity = query("SELECT * FROM audit_log WHERE user_id=? AND action NOT IN ('LOGIN','LOGOUT') ORDER BY id DESC LIMIT 6", (uid,))
    return render_template('detective/dashboard.html', cases=cases, stats=stats, new=new, activity=activity, idle_days=IDLE_DAYS)


@bp.route('/cases')
@role_required('detective')
def cases():
    status = request.args.get('status', 'Open')
    sql = "SELECT *, CAST(julianday('now','localtime') - julianday(updated_at) AS INTEGER) AS idle FROM dockets WHERE detective_id=?"
    if status == 'Open':
        sql += " AND status IN ('Assigned','Under investigation')"
    elif status != 'All':
        sql += ' AND status = ?'
    rows = query(sql + ' ORDER BY updated_at DESC', (session['user_id'],) if status in ('Open', 'All') else (session['user_id'], status))
    return render_template('detective/cases.html', cases=rows, status=status, idle_days=IDLE_DAYS)


@bp.route('/cases/<number>')
@role_required('detective')
def case(number):
    my_case(number, editable=False)
    b = docket_bundle(number)
    tab = request.args.get('tab', 'overview')
    return render_template('detective/case.html', tab=tab, suspect_statuses=SUSPECT_STATUSES,
                           locked=b['d']['status'] in ('Ready for closure', 'Closed'), **b)


@bp.post('/cases/<number>/suspects')
@role_required('detective')
def add_suspect(number):
    d = my_case(number)
    if not d:
        return back(number, 'suspects')
    name = request.form.get('full_name', '').strip()
    id_no = request.form.get('id_no', '').replace(' ', '')
    status = request.form.get('status', '')
    if len(name) < 2 or status not in SUSPECT_STATUSES or (id_no and not (id_no.isdigit() and len(id_no) == 13)):
        flash('Enter the suspect\'s name, a status, and (if known) a valid 13-digit ID number.', 'error')
        return back(number, 'suspects')
    execute('INSERT INTO suspects (docket_id, full_name, id_no, status, notes, added_by, created_at) VALUES (?,?,?,?,?,?,?)',
            (d['id'], name, id_no, status, request.form.get('notes', '').strip(), session['user_id'], now()))
    touch(d['id'], 20)
    audit('SUSPECT_ADD', number, f'{name} ({status})')
    flash(f'Suspect {name} added.', 'success')
    return back(number, 'suspects')


@bp.post('/cases/<number>/suspects/<int:sid>')
@role_required('detective')
def update_suspect(number, sid):
    d = my_case(number)
    if not d:
        return back(number, 'suspects')
    status = request.form.get('status', '')
    s = query('SELECT * FROM suspects WHERE id=? AND docket_id=?', (sid, d['id']), one=True)
    if not s or status not in SUSPECT_STATUSES:
        abort(400)
    execute('UPDATE suspects SET status=? WHERE id=?', (status, sid))
    touch(d['id'])
    audit('SUSPECT_STATUS', number, f'{s["full_name"]}: {s["status"]} → {status}')
    flash(f'{s["full_name"]} is now "{status}".', 'success')
    return back(number, 'suspects')


@bp.post('/cases/<number>/witnesses')
@role_required('detective')
def add_witness(number):
    d = my_case(number)
    if not d:
        return back(number, 'witnesses')
    name = request.form.get('full_name', '').strip()
    statement = request.form.get('statement', '').strip()
    date = request.form.get('statement_date', '') or now()[:10]
    if len(name) < 2 or len(statement) < 10:
        flash('Enter the witness name and their statement (at least 10 characters).', 'error')
        return back(number, 'witnesses')
    execute('INSERT INTO witnesses (docket_id, full_name, contact, statement, statement_date, added_by, created_at) VALUES (?,?,?,?,?,?,?)',
            (d['id'], name, request.form.get('contact', '').strip(), statement, date, session['user_id'], now()))
    touch(d['id'], 30)
    audit('WITNESS_ADD', number, name)
    flash(f'Statement from {name} saved.', 'success')
    return back(number, 'witnesses')


@bp.post('/cases/<number>/evidence')
@role_required('detective')
def upload_evidence(number):
    d = my_case(number)
    if not d:
        return back(number, 'evidence')
    file = request.files.get('file')
    if not file or not file.filename:
        flash('Choose a file to upload.', 'error')
        return back(number, 'evidence')
    original = secure_filename(file.filename) or 'evidence'
    ext = original.rsplit('.', 1)[-1].lower() if '.' in original else ''
    if ext not in current_app.config['ALLOWED_EVIDENCE']:
        flash('That file type is not allowed. Use photos, video, audio, PDF, Word or text files.', 'error')
        return back(number, 'evidence')
    data = file.read()
    stored = f'{uuid.uuid4().hex}.{ext}'
    with open(os.path.join(current_app.config['UPLOAD_FOLDER'], stored), 'wb') as f:
        f.write(data)
    digest = hashlib.sha256(data).hexdigest()
    execute('INSERT INTO evidence (docket_id, filename, stored_name, description, sha256, uploaded_by, created_at) VALUES (?,?,?,?,?,?,?)',
            (d['id'], original, stored, request.form.get('description', '').strip(), digest, session['user_id'], now()))
    touch(d['id'], 40)
    audit('EVIDENCE_UPLOAD', number, f'{original} sha256:{digest[:16]}…')
    flash(f'Evidence {original} uploaded. Its fingerprint (SHA-256) is recorded for the chain of custody.', 'success')
    return back(number, 'evidence')


@bp.post('/cases/<number>/notes')
@role_required('detective')
def add_note(number):
    d = my_case(number)
    if not d:
        return back(number, 'notes')
    note = request.form.get('note', '').strip()
    if len(note) < 3:
        flash('The note is empty.', 'error')
        return back(number, 'notes')
    execute('INSERT INTO case_notes (docket_id, note, author_id, created_at) VALUES (?,?,?,?)', (d['id'], note, session['user_id'], now()))
    touch(d['id'])
    audit('NOTE_ADD', number, note[:60])
    flash('Note added.', 'success')
    return back(number, 'notes')


@bp.post('/cases/<number>/progress')
@role_required('detective')
def update_progress(number):
    d = my_case(number)
    if not d:
        return back(number, 'overview')
    progress = max(0, min(request.form.get('progress', type=int, default=d['progress']), 95))
    execute('UPDATE dockets SET progress=?, updated_at=?, status=? WHERE id=?',
            (progress, now(), 'Under investigation', d['id']))
    audit('PROGRESS_UPDATE', number, f'{d["progress"]}% → {progress}%')
    flash(f'Progress updated to {progress}%.', 'success')
    return back(number, 'overview')


@bp.post('/cases/<number>/submit')
@role_required('detective')
def submit_closure(number):
    d = my_case(number)
    if not d:
        return back(number, 'overview')
    summary = request.form.get('summary', '').strip()
    if len(summary) < 20:
        flash('Write a short closing summary (at least 20 characters) before submitting.', 'error')
        return back(number, 'overview')
    t = now()
    db = get_db()
    db.execute("UPDATE dockets SET status='Ready for closure', progress=100, updated_at=? WHERE id=?", (t, d['id']))
    db.execute('INSERT INTO case_notes (docket_id, note, author_id, created_at) VALUES (?,?,?,?)',
               (d['id'], f'[Closing summary] {summary}', session['user_id'], t))
    db.commit()
    audit('CASE_SUBMIT_CLOSURE', number, summary[:80])
    flash(f'{number} was sent to the Station Commander for closure approval.', 'success')
    return back(number, 'overview')


def _across_cases(table, order):
    return query(f'SELECT x.*, d.number, d.crime_type FROM {table} x JOIN dockets d ON d.id = x.docket_id '
                 f'WHERE d.detective_id = ? ORDER BY {order}', (session['user_id'],))


@bp.route('/suspects')
@role_required('detective')
def suspects():
    return render_template('detective/list_suspects.html', rows=_across_cases('suspects', 'x.created_at DESC'))


@bp.route('/witnesses')
@role_required('detective')
def witnesses():
    return render_template('detective/list_witnesses.html', rows=_across_cases('witnesses', 'x.statement_date DESC'))


@bp.route('/evidence')
@role_required('detective')
def evidence():
    return render_template('detective/list_evidence.html', rows=_across_cases('evidence', 'x.created_at DESC'))
