import hashlib
import datetime
from http.client import HTTPException

from flask import Flask, request, Blueprint
from flask_limiter.util import get_remote_address
from flask_limiter import Limiter

import lib.settings as settings
import lib.connectors.sql as sql
import lib.connectors.emails.send_emails as send_emails


app = Flask(__name__)
onlyvulns_v1 = Blueprint('onlyvulns', __name__, url_prefix='/api/v1')


def limit_requests():
    token = None
    if request.is_json:
        data = request.get_json(force=True) or {}
        token = data.get("token", None)
    if not token:
        token = request.args.get("token")
    if token:
        return f"tok:{token}"
    return f"ip:{get_remote_address()}"


conf = settings.load_env()
limiter = Limiter(
    app=app,
    key_func=limit_requests,
    default_limits=["50 per second"],
    storage_uri=f"redis://{conf['redis']['host']}:{conf['redis']['port']}/{conf['redis']['database']}",
    key_prefix="onlyvulns-limiter"
)


@app.errorhandler(429)
def handler_429():
    return settings.build_json_report(None, is_error=True, error_string="You have hit the request rate limit")


@app.errorhandler(Exception)
def handler_exception(error):
    if isinstance(error, HTTPException):
        return settings.build_json_report(
            None, is_error=True,
            error_string="Unhandled HTTP exception occurred"
        ), 400
    return settings.build_json_report(None, is_error=True, error_string="Internal server error"), 500


@app.route("/")
def public_home():
    return settings.build_json_report({
        "version": "0.1",
        "title": "OnlyVulns API"
    })


#
# CREATE RESEARCHER LOGIN
#

@onlyvulns_v1.route("/researcher/register", methods=["POST"])
def register_researcher():
    data = request.get_json(force=True)
    email = data.get("email", None)

    if email is None:
        return settings.build_json_report(None, is_error=True, error_string="No email provided")

    user_exists = sql.find_user_by_email(email)
    if user_exists:
        return settings.build_json_report(None, is_error=True, error_string="Unable to register user account")
    else:
        magic_link = send_emails.build_sign_in_link(email)
        success = sql.register_user(email, magic_link)
        if success:
            send_emails.send_email(email, magic_link['sign_in_link'])
            return settings.build_json_report({
                "ok": True,
                "note": "An email has been sent to your account containing your sign in link, if your account is not registered or verified within 7 days of creation it will be deleted"
            })
        else:
            return settings.build_json_report(None, is_error=True, error_string="Unable to register user account")


@onlyvulns_v1.route("/researcher/whoami", methods=["POST"])
def whoami_researcher():
    data = request.get_json(force=True)
    token = data.get("token", None)
    if token is None:
        return settings.build_json_report(None, is_error=True, error_string="Invalid token provided")
    else:
        good_token = settings.verify_token(token)
        if good_token:
            user_exists = sql.find_user_by_email(good_token)
            if not user_exists:
                return settings.build_json_report(None, is_error=True, error_string="Invalid token provided")
            return settings.build_json_report({
                "researcher_id": user_exists['user_id'],
                "is_verified": user_exists['is_verified'],
                "registration_date": user_exists['registered_at'],
                "researcher_reputation": user_exists['reputation'],
                "researcher_total_reports": user_exists['total_reports']
            })
        else:
            return settings.build_json_report(None, is_error=True, error_string="Invalid token provided")


@onlyvulns_v1.route("/researcher/magiclink", methods=["GET"])
def magiclink_researcher():
    token = request.args.get("token", None)
    email_address = request.args.get("rid", None)
    if token is None:
        return settings.build_json_report(None, is_error=True, error_string="No auth token provided")
    if email_address is None:
        return settings.build_json_report(None, is_error=True, error_string="No email address provided")
    user_data = sql.find_user_by_email(email_address)
    if not user_data:
        return settings.build_json_report(None, is_error=True, error_string="Unable to find user")
    passed_token_hash = hashlib.sha256(token.encode()).hexdigest()
    stored_token_hash = user_data['magic_link_info']['token_hash']
    expiration_date = user_data['magic_link_info']['expires_at']
    if passed_token_hash == stored_token_hash:
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        target_time = datetime.datetime.fromisoformat(expiration_date)
        if now > target_time:
            return settings.build_json_report(None, is_error=True, error_string="Unable to login with token, is it expired?")
        if not user_data['is_verified']:
            sql.verify_user(email_address)
        return settings.build_json_report({
            "token": settings.create_user_token(email_address)
        })
    else:
        return settings.build_json_report(None, is_error=True, error_string="Unable to login with token, is it expired?")


@onlyvulns_v1.route("/researcher/magiclink/refresh", methods=["POST"])
def refresh_magic_link():
    data = request.get_json(force=True)
    token = data.get("token", None)
    if token is None:
        return settings.build_json_report(None, is_error=True, error_string="Invalid token provided")
    good_token = settings.verify_token(token)
    if good_token is None:
        return settings.build_json_report(None, is_error=True, error_string="Invalid token provided")
    user_exists = sql.find_user_by_email(good_token)
    if user_exists is None:
        return settings.build_json_report(None, is_error=True, error_string="Invalid token provided")
    new_magic_link = send_emails.build_sign_in_link(good_token)
    sql.update_magic_link(good_token, new_magic_link)
    sent = send_emails.send_new_magic_link_email(good_token, new_magic_link['sign_in_link'])
    if sent:
        return settings.build_json_report({
            "ok": True,
            "note": "A new magic link was sent to your email"
        })
    else:
        return settings.build_json_report(None, is_error=True, error_string="Unable to refresh magic link try again later")


#
# END RESEARCHER LOGIN
#

