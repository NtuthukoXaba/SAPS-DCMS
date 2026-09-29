import os
import secrets

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, 'instance')


def _secret_key():
    """Use SECRET_KEY from the environment, otherwise create one and keep it in instance/secret_key."""
    if os.environ.get('SECRET_KEY'):
        return os.environ['SECRET_KEY']
    os.makedirs(INSTANCE_DIR, exist_ok=True)
    path = os.path.join(INSTANCE_DIR, 'secret_key')
    if not os.path.exists(path):
        with open(path, 'w') as f:
            f.write(secrets.token_hex(32))
    with open(path) as f:
        return f.read().strip()


class Config:
    SECRET_KEY = _secret_key()
    DATABASE = os.path.join(INSTANCE_DIR, 'saps_dcms.db')
    UPLOAD_FOLDER = os.path.join(INSTANCE_DIR, 'uploads')
    MAX_CONTENT_LENGTH = 20 * 1024 * 1024            # 20 MB per upload
    ALLOWED_EVIDENCE = {'jpg', 'jpeg', 'png', 'gif', 'pdf', 'mp4', 'mov', 'mp3', 'wav', 'doc', 'docx', 'txt'}
    MAX_FAILED_LOGINS = 5                             # account locks after this many wrong passwords
    STALLED_DAYS = 14                                 # dockets with no activity for this long are escalated
    UNMATCHED_HOURS = 4                               # check-ins waiting longer than this are flagged
    SHOW_DEMO_ACCOUNTS = True                         # show demo logins on the login page (turn off for real use)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
