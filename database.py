"""
SAPS-DCMS database layer (SQLite).

- The database file is created automatically on first run (instance/saps_dcms.db)
  and filled with demo data.
- The audit_log table is APPEND-ONLY: SQLite triggers block every UPDATE/DELETE,
  and each entry stores a SHA-256 hash of the previous entry (a hash chain), so
  any tampering with the file can be detected by verify_audit_chain().
"""
import hashlib
import os
import sqlite3
from datetime import datetime, timedelta

import click
from flask import current_app, g, request, session
from werkzeug.security import generate_password_hash

TIME_FMT = '%Y-%m-%d %H:%M:%S'

STATUSES = ['Unassigned', 'Assigned', 'Under investigation', 'Ready for closure', 'Closed']
PRIORITIES = ['High', 'Medium', 'Low']
CRIME_TYPES = ['Theft', 'Assault', 'Burglary', 'Robbery', 'Malicious Damage', 'Fraud',
               'Housebreaking', 'Domestic Violence', 'Stock Theft', 'Other']
REFUSAL_REASONS = ['No crime disclosed', 'Referred to correct station (jurisdiction)',
                   'Civil matter – referred to court', 'Complainant withdrew before registration',
                   'Duplicate of an existing docket', 'Other']
SUSPECT_STATUSES = ['Person of Interest', 'Under Investigation', 'Arrested', 'Released', 'Cleared']
ROLE_NAMES = {'csc': 'CSC Official', 'commander': 'Station Commander',
              'detective': 'Detective', 'admin': 'System Administrator'}
USER_STATUSES = ['Active', 'Locked', 'Pending', 'Inactive']

SCHEMA = """
CREATE TABLE IF NOT EXISTS stations (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    province    TEXT NOT NULL DEFAULT 'Gauteng',
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    persal           TEXT NOT NULL UNIQUE,          -- personnel number (login)
    password_hash    TEXT NOT NULL,
    full_name        TEXT NOT NULL,
    role             TEXT NOT NULL CHECK (role IN ('csc','commander','detective','admin')),
    station_id       INTEGER REFERENCES stations(id),
    email            TEXT,
    phone            TEXT,
    status           TEXT NOT NULL DEFAULT 'Active',
    failed_attempts  INTEGER NOT NULL DEFAULT 0,
    last_login       TEXT,
    created_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS checkins (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ref         TEXT NOT NULL UNIQUE,
    full_name   TEXT NOT NULL,
    id_no       TEXT NOT NULL,
    reason      TEXT NOT NULL,
    language    TEXT NOT NULL,
    station_id  INTEGER NOT NULL REFERENCES stations(id),
    status      TEXT NOT NULL DEFAULT 'Waiting',   -- Waiting / Registered / Refused
    handled_by  INTEGER REFERENCES users(id),
    handled_at  TEXT,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS dockets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    number          TEXT NOT NULL UNIQUE,
    checkin_id      INTEGER REFERENCES checkins(id),
    station_id      INTEGER NOT NULL REFERENCES stations(id),
    complainant     TEXT NOT NULL,
    id_no           TEXT NOT NULL,
    contact         TEXT NOT NULL,
    email           TEXT,
    address         TEXT NOT NULL,
    incident_date   TEXT NOT NULL,
    incident_time   TEXT NOT NULL,
    location        TEXT,
    crime_type      TEXT NOT NULL,
    priority        TEXT NOT NULL DEFAULT 'Medium',
    description     TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'Unassigned',
    progress        INTEGER NOT NULL DEFAULT 0,
    registered_by   INTEGER NOT NULL REFERENCES users(id),
    detective_id    INTEGER REFERENCES users(id),
    assigned_at     TEXT,
    closed_at       TEXT,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS refusals (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    checkin_id  INTEGER NOT NULL REFERENCES checkins(id),
    reason      TEXT NOT NULL,
    notes       TEXT,
    officer_id  INTEGER NOT NULL REFERENCES users(id),
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS suspects (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    docket_id   INTEGER NOT NULL REFERENCES dockets(id),
    full_name   TEXT NOT NULL,
    id_no       TEXT,
    status      TEXT NOT NULL,
    notes       TEXT,
    added_by    INTEGER NOT NULL REFERENCES users(id),
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS witnesses (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    docket_id       INTEGER NOT NULL REFERENCES dockets(id),
    full_name       TEXT NOT NULL,
    contact         TEXT,
    statement       TEXT NOT NULL,
    statement_date  TEXT NOT NULL,
    added_by        INTEGER NOT NULL REFERENCES users(id),
    created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    docket_id     INTEGER NOT NULL REFERENCES dockets(id),
    filename      TEXT NOT NULL,          -- original name shown to users
    stored_name   TEXT,                   -- name on disk (NULL for demo items)
    description   TEXT,
    sha256        TEXT,                   -- fingerprint of the file for chain of custody
    uploaded_by   INTEGER NOT NULL REFERENCES users(id),
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS case_notes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    docket_id   INTEGER NOT NULL REFERENCES dockets(id),
    note        TEXT NOT NULL,
    author_id   INTEGER NOT NULL REFERENCES users(id),
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  TEXT NOT NULL,
    user_id     INTEGER,
    actor       TEXT NOT NULL,            -- name shown in the log (user or kiosk)
    action      TEXT NOT NULL,            -- e.g. CASE_REGISTER
    record      TEXT,                     -- e.g. DCMS-2026-0001
    details     TEXT,
    ip          TEXT,
    prev_hash   TEXT NOT NULL,
    hash        TEXT NOT NULL
);

-- The audit log can only be added to. Any change or delete is rejected.
CREATE TRIGGER IF NOT EXISTS audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;

CREATE INDEX IF NOT EXISTS idx_dockets_station ON dockets(station_id, status);
CREATE INDEX IF NOT EXISTS idx_dockets_detective ON dockets(detective_id);
CREATE INDEX IF NOT EXISTS idx_checkins_station ON checkins(station_id, status);
"""


# ------------------------------------------------------------------
# Connection helpers
# ------------------------------------------------------------------
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(current_app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA foreign_keys = ON')
    return g.db


def close_db(_=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def query(sql, args=(), one=False):
    cur = get_db().execute(sql, args)
    rows = cur.fetchall()
    cur.close()
    return (rows[0] if rows else None) if one else rows


def scalar(sql, args=()):
    row = query(sql, args, one=True)
    return row[0] if row else None


def execute(sql, args=()):
    db = get_db()
    cur = db.execute(sql, args)
    db.commit()
    return cur.lastrowid


def now():
    return datetime.now().strftime(TIME_FMT)


# ------------------------------------------------------------------
# Audit log (append-only, hash-chained)
# ------------------------------------------------------------------
def _entry_hash(prev_hash, created_at, user_id, actor, action, record, details, ip):
    raw = '|'.join(str(x) for x in (prev_hash, created_at, user_id, actor, action, record, details, ip))
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()


def audit(action, record='', details='', user_id=None, actor=None, db=None, when=None):
    """Write one entry to the audit log."""
    db = db or get_db()
    if user_id is None and session.get('user_id'):
        user_id = session['user_id']
    if actor is None:
        actor = session.get('name', 'System')
    try:
        ip = request.remote_addr or ''
    except RuntimeError:
        ip = ''
    created_at = when or now()
    last = db.execute('SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1').fetchone()
    prev_hash = last[0] if last else 'GENESIS'
    h = _entry_hash(prev_hash, created_at, user_id, actor, action, record, details, ip)
    db.execute('INSERT INTO audit_log (created_at, user_id, actor, action, record, details, ip, prev_hash, hash) '
               'VALUES (?,?,?,?,?,?,?,?,?)',
               (created_at, user_id, actor, action, record, details, ip, prev_hash, h))
    db.commit()


def verify_audit_chain():
    """Recompute every hash. Returns (ok, entries_checked, first_bad_id)."""
    prev = 'GENESIS'
    count = 0
    for r in query('SELECT * FROM audit_log ORDER BY id'):
        count += 1
        expected = _entry_hash(prev, r['created_at'], r['user_id'], r['actor'], r['action'],
                               r['record'], r['details'], r['ip'])
        if r['prev_hash'] != prev or r['hash'] != expected:
            return False, count, r['id']
        prev = r['hash']
    return True, count, None


# ------------------------------------------------------------------
# Numbers
# ------------------------------------------------------------------
def next_docket_number(db=None):
    db = db or get_db()
    year = datetime.now().year
    row = db.execute("SELECT number FROM dockets WHERE number LIKE ? ORDER BY number DESC LIMIT 1",
                     (f'DCMS-{year}-%',)).fetchone()
    seq = int(row[0].split('-')[-1]) + 1 if row else 1
    return f'DCMS-{year}-{seq:04d}'


def next_checkin_ref(db=None):
    db = db or get_db()
    year = datetime.now().year
    row = db.execute("SELECT ref FROM checkins WHERE ref LIKE ? ORDER BY ref DESC LIMIT 1",
                     (f'CHK-{year}-%',)).fetchone()
    seq = int(row[0].split('-')[-1]) + 1 if row else 40001
    return f'CHK-{year}-{seq:05d}'


# ------------------------------------------------------------------
# Create + seed
# ------------------------------------------------------------------
def init_db(db):
    db.executescript(SCHEMA)
    db.commit()


def seed_demo_data(db):
    """Fill a fresh database with demo stations, users, dockets and history."""
    t = datetime.now()
    ago = lambda **kw: (t - timedelta(**kw)).strftime(TIME_FMT)
    year = t.year

    db.execute("INSERT INTO stations (name, province, created_at) VALUES ('Soshanguve', 'Gauteng', ?)", (ago(days=400),))
    db.execute("INSERT INTO stations (name, province, created_at) VALUES ('Mabopane', 'Gauteng', ?)", (ago(days=400),))

    users = [
        # persal,    password,          name,                   role,        station, email,                          phone,          status
        ('1000004', 'Admin@2026',     'S. Pillay',            'admin',     1, 's.pillay@saps-dcms.demo',       '012 555 0104', 'Active'),
        ('1000001', 'Csc@2026',       'Const. J. Mokoena',    'csc',       1, 'j.mokoena@saps-dcms.demo',      '012 555 0101', 'Active'),
        ('1000002', 'Commander@2026', 'Lt. C. van der Merwe', 'commander', 1, 'c.vandermerwe@saps-dcms.demo',  '012 555 0102', 'Active'),
        ('1000003', 'Detective@2026', 'Det. A. Naidoo',       'detective', 1, 'a.naidoo@saps-dcms.demo',       '012 555 0103', 'Active'),
        ('1000005', 'Detective@2026', 'Det. S. Khumalo',      'detective', 1, 's.khumalo@saps-dcms.demo',      '012 555 0105', 'Active'),
        ('1000006', 'Detective@2026', 'Det. M. Zulu',         'detective', 1, 'm.zulu@saps-dcms.demo',         '012 555 0106', 'Active'),
        ('1000007', 'Detective@2026', 'Det. L. Botha',        'detective', 1, 'l.botha@saps-dcms.demo',        '012 555 0107', 'Active'),
        ('1000008', 'Csc@2026',       'Const. P. Ndlovu',     'csc',       2, 'p.ndlovu@saps-dcms.demo',       '012 555 0108', 'Pending'),
    ]
    for p, pw, name, role, st, email, phone, status in users:
        db.execute('INSERT INTO users (persal, password_hash, full_name, role, station_id, email, phone, status, created_at) '
                   'VALUES (?,?,?,?,?,?,?,?,?)',
                   (p, generate_password_hash(pw), name, role, st, email, phone, status, ago(days=200)))
    uid = {r['persal']: r['id'] for r in db.execute('SELECT id, persal FROM users')}
    csc, cmd, naidoo, khumalo, zulu, botha = (uid['1000001'], uid['1000002'], uid['1000003'],
                                             uid['1000005'], uid['1000006'], uid['1000007'])

    # Waiting check-ins (kiosk)
    for i, (name, idn, reason, lang, mins) in enumerate([
            ('Lindiwe Khoza', '8807150234081', 'Report a crime', 'isiZulu', 24),
            ('Pieter Jacobs', '7503025123087', 'Follow up on a case', 'Afrikaans', 16),
            ('Aisha Moosa', '9510300456083', 'Report a crime', 'English', 9),
            ('Bongani Sithole', '0102035678089', 'Give a statement', 'isiZulu', 3)]):
        db.execute('INSERT INTO checkins (ref, full_name, id_no, reason, language, station_id, created_at) VALUES (?,?,?,?,?,?,?)',
                   (f'CHK-{year}-{40311 + i}', name, idn, reason, lang, 1, ago(minutes=mins)))

    # An old check-in that was never handled (shows as "unmatched")
    db.execute("INSERT INTO checkins (ref, full_name, id_no, reason, language, station_id, created_at) VALUES (?,?,?,?,?,?,?)",
               (f'CHK-{year}-40290', 'Samuel Maluleke', '8102145567083', 'Report a crime', 'Xitsonga', 1, ago(hours=26)))

    # A refused check-in
    db.execute("INSERT INTO checkins (ref, full_name, id_no, reason, language, station_id, status, handled_by, handled_at, created_at) "
               "VALUES (?,?,?,?,?,?,?,?,?,?)",
               (f'CHK-{year}-40280', 'Johan Pretorius', '6907075123089', 'Report a crime', 'Afrikaans', 1, 'Refused', csc, ago(days=1, hours=2), ago(days=1, hours=3)))
    refused_id = db.execute("SELECT id FROM checkins WHERE ref=?", (f'CHK-{year}-40280',)).fetchone()[0]
    db.execute('INSERT INTO refusals (checkin_id, reason, notes, officer_id, created_at) VALUES (?,?,?,?,?)',
               (refused_id, 'Referred to correct station (jurisdiction)',
                'Incident happened in Mabopane. Complainant given the station address.', csc, ago(days=1, hours=2)))

    dockets = [
        # crime, priority, complainant, id, contact, email, address, days_ago, status, detective, progress, desc, location
        ('Theft', 'High', 'Thabo Dlamini', '9001011234088', '082 345 6789', 'thabo.dlamini@email.com', '123 Block A, Soshanguve, Pretoria, 0152', 8, 'Under investigation', naidoo, 60,
         'Complainant states that his laptop and cellphone were stolen from his house between 20:00 and 21:00.', '123 Block A, Soshanguve'),
        ('Assault', 'Medium', 'Nomsa Nkosi', '9204120987084', '082 111 2222', '', '45 Block H, Soshanguve, 0152', 8, 'Unassigned', None, 0,
         'Complainant was assaulted by a known person outside a tavern and sustained a cut to the arm.', 'Outside tavern, Block H'),
        ('Burglary', 'High', 'Sipho Mahlangu', '8503155678081', '076 555 1212', '', '12 Block X, Soshanguve, 0152', 9, 'Unassigned', None, 0,
         'Garage door forced open; tools and a lawnmower stolen.', '12 Block X'),
        ('Robbery', 'High', 'Jane Smith', '8812120123085', '083 444 5566', 'jane.smith@email.com', '5 Mall Road, Soshanguve, 0152', 9, 'Unassigned', None, 0,
         'Complainant was robbed of her handbag at knifepoint near the taxi rank.', 'Taxi rank, Soshanguve Crossing'),
        ('Malicious Damage', 'Low', 'Pieter Jacobs', '7503025123087', '072 888 9900', '', '31 Block F, Soshanguve, 0152', 10, 'Unassigned', None, 0,
         'Car windows broken overnight while parked outside the house.', '31 Block F'),
        ('Fraud', 'Medium', 'Kevin Reddy', '8611075012086', '083 987 6543', 'k.reddy@email.com', '9 Protea Street, Soshanguve South, 0152', 7, 'Assigned', zulu, 10,
         "R4 500 was taken from the complainant's bank account after a phone call from someone claiming to be the bank.", 'Telephonic'),
        ('Burglary', 'High', 'Grace Mokoena', '7909230345082', '071 222 3344', '', '78 Block L, Soshanguve, 0152', 21, 'Under investigation', khumalo, 35,
         'Unknown suspects broke the kitchen window and stole a television and a microwave.', '78 Block L'),
        ('Housebreaking', 'Medium', 'Mpho Tau', '9306066789081', '079 123 4567', '', '14 Block V, Soshanguve, 0152', 18, 'Under investigation', botha, 25,
         'House broken into while the family was away for the weekend. Jewellery taken.', '14 Block V'),
        ('Theft', 'Low', 'Ruth Sibiya', '6508080234086', '078 654 3210', '', '2 Block K, Soshanguve, 0152', 30, 'Ready for closure', naidoo, 100,
         'Garden equipment stolen from yard. Items recovered and returned to the complainant.', '2 Block K'),
        ('Stock Theft', 'Medium', 'Lucas Masemola', '7004045123081', '082 777 1122', '', 'Plot 44, Soshanguve Ext, 0152', 45, 'Closed', botha, 100,
         'Two goats stolen from kraal. Suspect arrested and livestock recovered.', 'Plot 44'),
    ]
    for i, (crime, pr, name, idn, contact, email, addr, days, status, det, prog, desc, loc) in enumerate(dockets):
        number = f'DCMS-{year}-{i + 1:04d}'
        created = ago(days=days, hours=2)
        assigned_at = ago(days=days - 1) if det else None
        if status in ('Under investigation', 'Assigned'):
            updated = ago(days=21 if name == 'Grace Mokoena' else 16 if name == 'Mpho Tau' else 1)
        else:
            updated = ago(days=max(days - 2, 0))
        closed_at = ago(days=days - 5) if status == 'Closed' else None
        inc_date = (t - timedelta(days=days)).strftime('%Y-%m-%d')
        db.execute('INSERT INTO dockets (number, station_id, complainant, id_no, contact, email, address, incident_date, incident_time, '
                   'location, crime_type, priority, description, status, progress, registered_by, detective_id, assigned_at, closed_at, created_at, updated_at) '
                   'VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                   (number, 1, name, idn, contact, email, addr, inc_date, '21:30', loc, crime, pr, desc, status, prog,
                    csc, det, assigned_at, closed_at, created, updated))

    d1 = db.execute("SELECT id FROM dockets WHERE number=?", (f'DCMS-{year}-0001',)).fetchone()[0]
    for name, idn, st in [('Ivan Mbatha', '8803035678089', 'Person of Interest'), ('Sizwe Dlamini', '9104046789090', 'Under Investigation')]:
        db.execute('INSERT INTO suspects (docket_id, full_name, id_no, status, notes, added_by, created_at) VALUES (?,?,?,?,?,?,?)',
                   (d1, name, idn, st, 'Seen near the house on the evening of the incident.', naidoo, ago(days=7)))
    for name, contact, stmt in [('Nomsa Nkosi', '082 111 2222', 'I saw two men leaving the yard at about 20:40 carrying a black bag.'),
                                ('John Molefe', '083 333 4444', 'I heard the dog barking around 20:30 and saw a white Toyota Corolla parked outside.')]:
        db.execute('INSERT INTO witnesses (docket_id, full_name, contact, statement, statement_date, added_by, created_at) VALUES (?,?,?,?,?,?,?)',
                   (d1, name, contact, stmt, (t - timedelta(days=7)).strftime('%Y-%m-%d'), naidoo, ago(days=7)))
    for fn, desc, days in [('CCTV_Footage.mp4', 'Neighbour camera, 20:00–21:00', 7), ('Footprint_Photo.jpg', 'Footprint at back door', 7),
                           ('Recovered_Item_01.jpg', 'Phone box recovered from suspect', 6)]:
        db.execute('INSERT INTO evidence (docket_id, filename, stored_name, description, uploaded_by, created_at) VALUES (?,?,?,?,?,?)',
                   (d1, fn, None, desc, naidoo, ago(days=days)))
    db.execute('INSERT INTO case_notes (docket_id, note, author_id, created_at) VALUES (?,?,?,?)',
               (d1, 'Visited the scene. Back door lock damaged. Neighbour has a camera facing the street.', naidoo, ago(days=7)))
    db.commit()

    # Audit history (written through the hash chain)
    history = [
        (ago(days=10), csc, 'Const. J. Mokoena', 'CASE_REGISTER', f'DCMS-{year}-0001', 'Theft'),
        (ago(days=7, hours=5), cmd, 'Lt. C. van der Merwe', 'DOCKET_ASSIGN', f'DCMS-{year}-0001', 'Assigned to Det. A. Naidoo'),
        (ago(days=7, hours=2), naidoo, 'Det. A. Naidoo', 'WITNESS_ADD', f'DCMS-{year}-0001', 'Nomsa Nkosi'),
        (ago(days=7, hours=1), naidoo, 'Det. A. Naidoo', 'EVIDENCE_UPLOAD', f'DCMS-{year}-0001', 'CCTV_Footage.mp4'),
        (ago(days=1, hours=2), csc, 'Const. J. Mokoena', 'CHECKIN_REFUSE', f'CHK-{year}-40280', 'Referred to correct station (jurisdiction)'),
        (ago(hours=1), None, 'Kiosk – Soshanguve', 'CHECK_IN', f'CHK-{year}-40311', 'Report a crime'),
    ]
    for when, u, actor, action, record, details in history:
        audit(action, record, details, user_id=u, actor=actor, db=db, when=when)
    audit('SYSTEM_SETUP', '', 'Database created with demo data', user_id=None, actor='System', db=db)


def init_app(app):
    app.teardown_appcontext(close_db)

    @app.cli.command('reset-db')
    def reset_db_command():
        """Delete the database and start again with fresh demo data."""
        path = app.config['DATABASE']
        if os.path.exists(path):
            os.remove(path)
        _create(app)
        click.echo('Database reset with fresh demo data.')

    _create(app)


def _create(app):
    """Create the database file and demo data if it does not exist yet."""
    os.makedirs(os.path.dirname(app.config['DATABASE']), exist_ok=True)
    fresh = not os.path.exists(app.config['DATABASE'])
    with app.app_context():
        db = get_db()
        init_db(db)
        if fresh:
            with app.test_request_context():
                seed_demo_data(db)
        close_db()
