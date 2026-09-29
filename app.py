"""
SAPS-DCMS – Digital Police Case Docket Management System
Run:  python app.py      then open  http://127.0.0.1:5000
"""
import os
from datetime import datetime

from flask import Flask, render_template, session

import database
from auth import csrf_protect, csrf_token
from config import Config


# Sidebar menu for each role: (label, icon, endpoint)
NAV = {
    'csc': [
        ('Dashboard', 'house', 'csc.dashboard'),
        ('Check-in Queue', 'users', 'csc.queue'),
        ('Register Case', 'square-pen', 'csc.register'),
        ('My Dockets', 'file-text', 'csc.dockets'),
        ('Search Dockets', 'search', 'csc.search'),
        ('Reports', 'file-bar-chart', 'csc.reports'),
    ],
    'commander': [
        ('Dashboard', 'house', 'commander.dashboard'),
        ('Unassigned Dockets', 'file-pen-line', 'commander.unassigned'),
        ('All Dockets', 'files', 'commander.dockets'),
        ('Detectives', 'users', 'commander.detectives'),
        ('Refusals & Check-ins', 'user-x', 'commander.refusals'),
        ('Reports', 'file-bar-chart', 'commander.reports'),
        ('Audit Log', 'fingerprint', 'commander.audit'),
    ],
    'detective': [
        ('Dashboard', 'house', 'detective.dashboard'),
        ('My Cases', 'folder-open', 'detective.cases'),
        ('Suspects', 'users', 'detective.suspects'),
        ('Witness Statements', 'file-signature', 'detective.witnesses'),
        ('Evidence', 'file-search', 'detective.evidence'),
    ],
    'admin': [
        ('Dashboard', 'house', 'admin.dashboard'),
        ('User Management', 'users', 'admin.users'),
        ('Stations', 'building-2', 'admin.stations'),
        ('Audit Log', 'fingerprint', 'admin.audit'),
    ],
}

STATUS_BADGE = {'Unassigned': 'badge-medium', 'Assigned': 'badge-assigned', 'Under investigation': 'badge-info',
                'Ready for closure': 'badge-purple', 'Closed': 'badge-closed',
                'Active': 'badge-assigned', 'Locked': 'badge-high', 'Pending': 'badge-medium', 'Inactive': 'badge-closed',
                'Waiting': 'badge-medium', 'Registered': 'badge-assigned', 'Refused': 'badge-high'}
PRIORITY_BADGE = {'High': 'badge-high', 'Medium': 'badge-medium', 'Low': 'badge-low'}


def create_app():
    app = Flask(__name__, instance_path=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance'))
    app.config.from_object(Config)
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    database.init_app(app)
    app.before_request(csrf_protect)

    from routes.public import bp as public_bp
    from routes.common import bp as common_bp
    from routes.csc import bp as csc_bp
    from routes.commander import bp as commander_bp
    from routes.detective import bp as detective_bp
    from routes.admin import bp as admin_bp
    for bp in (public_bp, common_bp, csc_bp, commander_bp, detective_bp, admin_bp):
        app.register_blueprint(bp)

    @app.context_processor
    def globals_for_templates():
        return {
            'csrf_token': csrf_token,
            'NAV': NAV,
            'STATUS_BADGE': STATUS_BADGE,
            'PRIORITY_BADGE': PRIORITY_BADGE,
            'ROLE_NAMES': database.ROLE_NAMES,
            'year': datetime.now().year,
            'now_date': datetime.now().strftime('%Y-%m-%d'),
            'me': {'name': session.get('name'), 'role': session.get('role'),
                   'station': session.get('station')},
        }

    @app.template_filter('dt')
    def format_datetime(value, fmt='%d %b %Y %H:%M'):
        if not value:
            return '—'
        try:
            return datetime.strptime(value[:19], database.TIME_FMT).strftime(fmt)
        except ValueError:
            return value

    @app.template_filter('ago')
    def time_ago(value):
        if not value:
            return '—'
        try:
            delta = datetime.now() - datetime.strptime(value[:19], database.TIME_FMT)
        except ValueError:
            return value
        mins = int(delta.total_seconds() // 60)
        if mins < 1:
            return 'just now'
        if mins < 60:
            return f'{mins} min ago'
        hours = mins // 60
        if hours < 24:
            return f'{hours} h ago'
        days = hours // 24
        return 'yesterday' if days == 1 else f'{days} days ago'

    @app.template_filter('idfmt')
    def format_id(value):
        v = (value or '').replace(' ', '')
        return f'{v[:6]} {v[6:10]} {v[10:]}' if len(v) == 13 else value

    @app.errorhandler(400)
    def bad_request(e):
        return render_template('error.html', code=400, message=getattr(e, 'description', 'Bad request.')), 400

    @app.errorhandler(403)
    def forbidden(_):
        return render_template('error.html', code=403, message='You do not have access to this page.'), 403

    @app.errorhandler(404)
    def not_found(_):
        return render_template('error.html', code=404, message='The page you are looking for does not exist.'), 404

    @app.errorhandler(413)
    def too_large(_):
        return render_template('error.html', code=413, message='That file is too large. The limit is 20 MB.'), 413

    return app


app = create_app()

if __name__ == '__main__':
    print('\n  SAPS-DCMS is running.  Open  http://127.0.0.1:5000  in your browser.\n')
    app.run(debug=True)
