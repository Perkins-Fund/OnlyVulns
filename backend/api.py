import hashlib
import datetime

from flask import Flask, request, Blueprint
from flask_limiter.util import get_remote_address
from flask_limiter import Limiter
from werkzeug.utils import secure_filename

import lib.settings as settings
import lib.connectors.sql as sql
import lib.connectors.emails.send_emails as send_emails


app = Flask(__name__)
onlyvulns_v1 = Blueprint('onlyvulns', __name__, url_prefix='/api/v1')
onlyvulns_free = Blueprint('onlyvulns_free', __name__, url_prefix='/api/free')


def limit_free_requests():
    return f"ip:{settings.get_client_ip(request, get_remote_address)}"


def limit_requests():
    token = None
    if request.is_json:
        data = request.get_json(force=True) or {}
        token = data.get("token", None)
    if not token:
        token = request.args.get("token")
    if token:
        return f"tok:{token}"
    return f"ip:{settings.get_client_ip(request, get_remote_address)}"


conf = settings.load_env()
limiter = Limiter(
    app=app,
    key_func=limit_requests,
    default_limits=["50 per second"],
    storage_uri=f"redis://{conf['redis']['host']}:{conf['redis']['port']}/{conf['redis']['database']}",
    key_prefix="onlyvulns-limiter"
)


@app.errorhandler(429)
def handler_429(_):
    app.logger.warning("Hit request rate limit")
    return settings.build_json_report(None, is_error=True, error_string="You have been rate limited, 50 requests per 1 second.")


@app.errorhandler(Exception)
def handler_exception(error):
    app.logger.error(error)
    return settings.build_json_report(None, is_error=True, error_string="Internal server error"), 500


@app.route("/")
def public_home():
    return settings.build_json_report({
        "version": "0.1",
        "title": "OnlyVulns API"
    })


#
# START RESEARCHER LOGIN
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

#
# START REPORTS ENDPOINTS
#

@onlyvulns_v1.route("/reports/create", methods=["POST"])
def create_report():
    data = request.form
    token = data.get("token", None)
    if token is None:
        return settings.build_json_report(None, is_error=True, error_string="Invalid token provided")
    good_token = settings.verify_token(token)
    if good_token is None:
        return settings.build_json_report(None, is_error=True, error_string="Invalid token provided")
    user_exists = sql.find_user_by_email(good_token)
    if user_exists is None:
        return settings.build_json_report(None, is_error=True, error_string="Invalid token provided")
    wait_time = data.get("wait_time", 7)
    release_days = data.get("release_days", 30)
    report_title = data.get("report_title", None)
    report_cvss = data.get("report_cvss", None)
    report_vendor = data.get("report_vendor", None)
    report_write_up = data.get("report_write_up", None)
    report_id = settings.build_id(is_report_id=True)
    if report_write_up is None:
        return settings.build_json_report(None, is_error=True, error_string="Report write up is required")
    if len(report_write_up) < 250:
        return settings.build_json_report(None, is_error=True, error_string=f"Report write up needs to be at least 250 characters long, you are at {len(report_write_up)}")
    if len(report_write_up) > 20000:
        return settings.build_json_report(None, is_error=True, error_string="Report write up needs to be at less than 20,000 characters long")
    if report_title is None:
        return settings.build_json_report(None, is_error=True, error_string="Invalid title provided")
    if len(report_title) < 5:
        return settings.build_json_report(None, is_error=True, error_string="Report title needs to be at least 5 characters long")
    if len(report_title) > 45:
        return settings.build_json_report(None, is_error=True, error_string="Report title needs to be at less than 45 characters long")
    if report_cvss is None:
        report_cvss = "N/A"
    if report_vendor is None:
        report_vendor = "N/A"
    if not isinstance(wait_time, int):
        try:
            wait_time = int(wait_time)
        except:
            return settings.build_json_report(None, is_error=True, error_string="Invalid wait_time provided")
    if not isinstance(release_days, int):
        try:
            release_days = int(release_days)
        except:
            return settings.build_json_report(None, is_error=True, error_string="Invalid release_days provided")
    uploaded_files = request.files.getlist("files")
    ok, err_msg = settings.validate_file_upload(uploaded_files)
    if not ok:
        return settings.build_json_report(None, is_error=True, error_string=err_msg)
    file_reports = []
    for fh in uploaded_files:
        file_hash = settings.get_file_hash_from_stream(fh)
        fh.stream.seek(0)
        file_size = settings.get_uploaded_file_size(fh)
        fh.stream.seek(0)
        file_upload_name = secure_filename(fh.filename)
        file_content_type = fh.content_type or "application/octet-stream"
        file_id = settings.build_id(is_file_id=True)
        try:
            uploaded_file = sql.store_report_files(
                report_id, user_exists['user_id'], fh, file_upload_name, file_content_type,
                original_filename=fh.filename,
                file_size=file_size,
                file_integrity_hash=file_hash,
                file_id=file_id,
            )
            file_reports.append({
                "file_hash": file_hash,
                "uploaded": True,
                "upload_error": None,
                "content_type": file_content_type,
                "file_id": file_id,
                "file_upload_id": str(uploaded_file)
            })
        except Exception as e:
            file_reports.append({
                "file_hash": file_hash,
                "uploaded": False,
                "upload_error": str(e),
                "content_type": file_content_type,
                "file_id": file_id,
                "file_upload_id": None
            })
    is_report_created = sql.add_report(
        user_exists['user_id'],
        wait_time,
        release_days,
        report_title,
        report_cvss,
        report_vendor,
        file_reports,
        report_id,
        report_write_up
    )
    for report in file_reports:
        del report['file_upload_id']
        del report['upload_error']
    if is_report_created:
        return settings.build_json_report({
            "report_id": report_id,
            "files": file_reports
        })
    else:
        return settings.build_json_report(None, is_error=True, error_string="Unable to create report")


@onlyvulns_v1.route("/reports/delete", methods=["POST"])
def delete_report():
    pass


@onlyvulns_v1.route("/reports/edit", methods=["POST"])
def edit_report():
    pass

#
# END REPORTS ENDPOINTS
#

#
# START PUBLIC ENDPOINTS
#


@onlyvulns_free.route("/reports/search", methods=["POST"])
@limiter.limit("10 per second", key_func=limit_free_requests)
def search_report():
    data = request.get_json(force=True)
    report_id = data.get("report_id", None)
    if report_id is None:
        return settings.build_json_report(None, is_error=True, error_string="Invalid report ID provided")
    report_data = sql.get_report_by_report_id(report_id)
    if report_data is None:
        return settings.build_json_report(None, is_error=True, error_string="Invalid report ID provided")
    if report_data['current_status'] != "released":
        report_files = None
        file_status = "locked"
    else:
        report_files = sql.get_report_files(report_data)
        file_status = "unlocked"
    retval = {
        "report_information": {
            "title": report_data["report_title"],
            "report_id": report_id,
            "report_body": report_data["report_write_up"],
            "report_status": report_data['current_status'],
        },
        "attached_files": report_files,
        "report_metadata": {
            "report_release_date": report_data["metadata"]['wait_end_date'],
            "associated_researcher": report_data['associated_researcher'],
            "report_upload_date": report_data["metadata"]['date_reported_on'],
            "report_files_status": file_status,
        }
    }
    return settings.build_json_report(retval)



@onlyvulns_free.route("/reports", methods=["GET"])
@limiter.limit("10 per second", key_func=limit_free_requests)
def list_reports():
    return settings.build_json_report(sql.get_reports())


@onlyvulns_free.route("/feed", methods=["POST"])
@limiter.limit("10 per second", key_func=limit_free_requests)
def report_feed():
    pass


@onlyvulns_free.route("/vote", methods=["POST"])
@limiter.limit("5 per hour", key_func=limit_free_requests)
def vote_on_user():
    data = request.get_json(force=True)
    rid = data.get("rid", None)
    vote_type = data.get("type", None)
    if rid is None:
        return settings.build_json_report(None, is_error=True, error_string="No researcher ID supplied")
    if vote_type is None:
        return settings.build_json_report(None, is_error=True, error_string="No vote type provided")
    if vote_type not in ["up", "down"]:
        return settings.build_json_report(None, is_error=True, error_string="Invalid vote type provided")
    user_exists = sql.find_researcher_by_id(rid)
    if user_exists is None:
        return settings.build_json_report(None, is_error=True, error_string="Invalid researcher ID provided")
    associated_user_email = user_exists['email_address']
    if associated_user_email is None:
        return settings.build_json_report(None, is_error=True, error_string="Invalid researcher ID provided")
    success = sql.change_researcher_reputation(associated_user_email, downvote=True if vote_type == "down" else False)
    if success:
        return settings.build_json_report({"ok": True})
    else:
        return settings.build_json_report(None, is_error=True, error_string="Unable to change researcher reputation")


@onlyvulns_free.route("/researcher", methods=["POST"])
@limiter.limit("5 per second", key_func=limit_free_requests)
def get_researcher():
    pass


#
# END PUBLIC ENDPOINTS
#