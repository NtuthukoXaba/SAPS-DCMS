# SAPS-DCMS – Digital Police Case Docket Management System

Flask + SQLite web application for Group 37 (DUT, Software Engineering 301 / Software Development 401).
Academic prototype – not an official SAPS system. All data is sample data.

---

## 1. Run it in VS Code (Windows)


```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```



## 2. Login details

| Role | Personnel number | Password |
|---|---|---|
| **System Administrator** | **1000004** | **Admin@2026** |
| CSC Official | 1000001 | Csc@2026 |
| Station Commander | 1000002 | Commander@2026 |
| Detective | 1000003 | Detective@2026 |
| Other detectives | 1000005, 1000006, 1000007 | Detective@2026 |
| CSC Official (pending approval) | 1000008 | Csc@2026 |

Change passwords on the **Profile** page after signing in. To hide the demo accounts box on the
login page, set `SHOW_DEMO_ACCOUNTS = False` in `config.py`.

Case tracking demo (homepage → **Track My Case**): docket `DCMS-<this year>-0001`, ID `9001011234088`.

---

## 3. What each user can do

**Public (no login)** – kiosk check-in (saved with a reference number), track a case with docket number + ID.

**CSC Official** – check-in queue, register cases (docket number created automatically), log refusals with
a required reason, my dockets, docket details, search, personal reports.

**Station Commander** – dashboard with escalation alerts (stalled cases and unmatched check-ins),
assign / reassign detectives, change priority, approve closure or send back, all dockets with filters,
detective workload, refusals & check-ins, station reports, station audit log.

**Detective** – assigned cases only; case workspace with suspects, witness statements, evidence upload
(SHA-256 fingerprint stored), notes, progress and submit-for-closure; cross-case lists.

**System Administrator** – users (create, edit, approve, unlock, deactivate, reset password), stations,
full audit log with filters, integrity check and CSV export, system health.

---

## 4. Security features

- Passwords stored as salted hashes (Werkzeug).
- Account locks after 5 wrong passwords (admin unlocks it).
- Role-based access on every page; detectives see only their own cases, station staff only their station.
- CSRF token on every form.
- **Append-only audit log**: SQLite triggers block every UPDATE and DELETE on `audit_log`, and each entry
  stores a SHA-256 hash of the previous one. The Admin dashboard re-checks the whole chain.
- Accounts are never deleted (only deactivated), so audit entries always point to a real person.

---

## 5. Project structure

```
saps-dcms/
├── app.py              ← start here (python app.py)
├── config.py           ← settings (stalled days, lockout, upload limits…)
├── database.py         ← SQLite schema, demo data, audit log
├── auth.py             ← login / role checks / CSRF
├── routes/             ← one file per user role
│   ├── public.py  common.py  csc.py  commander.py  detective.py  admin.py
├── templates/          ← HTML pages (Jinja2)
├── static/             ← CSS, JavaScript, logo, icons
└── instance/           ← created on first run: database, uploads, secret key
```

## 6. Start again with fresh demo data

Stop the app and delete the `instance` folder, then run `python app.py` again.
(Or run `flask --app app reset-db`.)

## 7. View the database

Install the VS Code extension **"SQLite Viewer"** and open `instance/saps_dcms.db`.
