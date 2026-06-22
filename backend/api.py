import time
import hashlib
import datetime

from flask import Flask, request, Blueprint, Response
from flask_limiter.util import get_remote_address
from flask_limiter import Limiter
from werkzeug.utils import secure_filename
from flask_limiter.errors import RateLimitExceeded

import lib.settings as settings
import lib.connectors.sql as sql
import lib.connectors.chat.rooms as chatrooms
import lib.connectors.emails.send_emails as send_emails


app = Flask(__name__)
onlyvulns_v1 = Blueprint('onlyvulns', __name__, url_prefix='/api/v1')
onlyvulns_free = Blueprint('onlyvulns_free', __name__, url_prefix='/api/free')
onlyvulns_chats = Blueprint('onlyvulns_chats', __name__, url_prefix='/api/rooms')


def limit_chat_sends():
    client_ip = settings.get_client_ip(request, get_remote_address)
    data = request.get_json(silent=True) or {}
    token = data.get("chat_token")
    if token:
        return f"chat:send:token:{token}:ip:{client_ip}"
    return f"chat:send:ip:{client_ip}:missing-token"


def limit_reputation_change():
    client_ip = settings.get_client_ip(request, get_remote_address)
    data = request.get_json(silent=True) or {}
    rid = data.get("rid", "missing")
    return f"vote:ip:{client_ip}:rid:{rid}"


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


@onlyvulns_chats.errorhandler(RateLimitExceeded)
def handle_chat_rate_limit(error):
    data = request.get_json(silent=True) or {}
    token = data.get("chat_token")

    if request.endpoint != "onlyvulns_chats.send_chat":
        return settings.build_json_report(
            None,
            is_error=True,
            error_string="Rate limit exceeded"
        ), 429

    result = chatrooms.register_send_rate_violation(token)

    if result["kicked"]:
        user = result.get("user")
        username = user.get("username") if user else "A user"

        now_ts = int(time.time())
        expires_at = now_ts + chatrooms.CHAT_TTL

        chatrooms.add_message({
            "type": "system",
            "author": "system",
            "message": f"{username} was kicked for spamming",
            "sent_at": now_ts,
            "expires": expires_at,
        }, expires_at)

        return settings.build_json_report({
            "kicked": True,
            "clear_token": True,
        }, is_error=True, error_string="You were kicked for exceeding the send rate limit"), 429

    return settings.build_json_report({
        "kicked": False,
        "clear_token": False,
        "violations": result["violations"],
    }, is_error=True, error_string="Rate limit exceeded. One more send-rate violation will remove your chat account"), 429


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
# START RESEARCHER ENDPOINTS
#

@onlyvulns_v1.route("/researcher/register", methods=["POST"])
@limiter.limit("1234234 per day", key_func=limit_free_requests)
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
                "researcher_total_reports": user_exists['total_reports'],
                "researcher_display_name": user_exists['display_name'],
                "researcher_tips": {
                    "onboarded": user_exists['researcher_tips']['stripe_onboarding_complete'],
                    "is_eligible": user_exists['researcher_tips']['is_researcher_eligible'],
                    "accepting_tips": user_exists['researcher_tips']['accepted_by_researcher'],
                    "last_payout_day": user_exists['researcher_tips']['last_payout_on'],
                }
            })
        else:
            return settings.build_json_report(None, is_error=True, error_string="Invalid token provided")


@onlyvulns_v1.route("/researcher/name/update", methods=["POST"])
@limiter.limit("1 per day")
def update_researcher_display_name():
    data = request.get_json(force=True)
    token  = data.get("token", None)
    researcher_id = data.get("rid", None)
    wanted_display_name = data.get("display_name", None)
    if token is None:
        return settings.build_json_report(None, is_error=True, error_string="Invalid token provided")
    if researcher_id is None:
        return settings.build_json_report(None, is_error=True, error_string="Invalid researcher ID provided")
    good_token = settings.verify_token(token)
    if good_token is None:
        return settings.build_json_report(None, is_error=True, error_string="Invalid token provided")
    if wanted_display_name is None:
        return settings.build_json_report(None, is_error=True, error_string="Invalid display name provided")
    if len(wanted_display_name) > 25:
        return settings.build_json_report(None, is_error=True, error_string="Display name cannot be more than 12 characters")
    if len(wanted_display_name) < 6:
        return settings.build_json_report(None, is_error=True, error_string="Display name must be at least 6 characters")
    user_exists = sql.find_user_by_email(good_token)
    if user_exists is None:
        return settings.build_json_report(None, is_error=True, error_string="Invalid researcher ID provided")
    real_researcher_id = user_exists['user_id']
    if real_researcher_id != researcher_id:
        return settings.build_json_report(None, is_error=True, error_string="Invalid researcher ID")
    redacted_display_name = settings.filter_language(wanted_display_name)
    updated = sql.update_display_name(redacted_display_name, researcher_id)
    if updated:
        return settings.build_json_report({"ok": True})
    else:
        return settings.build_json_report(None, is_error=True, error_string="Unable to update display name")


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
# END RESEARCHER ENDPOINTS
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
        sql.increase_researcher_report_count(user_exists['user_id'])
        sql.change_researcher_reputation(user_exists['user_id'])
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


@onlyvulns_v1.route("/reports/delay", methods=["POST"])
def delay_report_release():
    pass

#
# END REPORTS ENDPOINTS
#

#
# START PUBLIC ENDPOINTS
#


@onlyvulns_free.route("/reports/comment", methods=["POST"])
@limiter.limit("5 per hour", key_func=limit_reputation_change)
def comment_on_report():
    data = request.get_json(force=True)
    report_id = data.get("report_id", None)
    comment = data.get("comment", None)

    if report_id is None:
        return settings.build_json_report(None, is_error=True, error_string="Invalid report_id provided", is_free_request=True)
    if comment is None:
        return settings.build_json_report(None, is_error=True, error_string="Invalid comment provided", is_free_request=True)

    report_exists = sql.get_report_by_report_id(report_id)
    if report_exists is None:
        return settings.build_json_report(None, is_error=True, error_string="Invalid report_id provided", is_free_request=True)

    if len(comment) < 10:
        return settings.build_json_report(None, is_error=True, error_string="Comment must be greater than 10 characters", is_free_request=True)
    if len(comment) > 250:
        return settings.build_json_report(None, is_error=True, error_string="Comment must be less than 250 characters", is_free_request=True)
    filtered_comment = settings.filter_language(comment)
    is_accepted = sql.add_comment_to_report(report_id, filtered_comment)
    if is_accepted:
        return settings.build_json_report({"ok": True}, is_free_request=True)
    else:
        return settings.build_json_report(None, is_error=True, error_string="Unable to create report", is_free_request=True)


@onlyvulns_free.route("/reports/comment/find", methods=["POST"])
@limiter.limit("10 per second", key_func=limit_free_requests)
def get_report_comments():
    data = request.get_json(force=True)
    report_id = data.get("report_id", None)
    if report_id is None:
        return settings.build_json_report(None, is_error=True, error_string="Invalid report_id provided", is_free_request=True)
    data = sql.get_all_report_comments(report_id)
    return settings.build_json_report(data, is_free_request=True)

@onlyvulns_free.route("/abuse", methods=["POST"])
@limiter.limit("1 per minute", key_func=limit_free_requests)
def report_abuse():
    data = request.get_json(force=True)
    report_reason = data.get("report_reason", None)
    report_id = data.get("report_id", None)

    if report_reason is None:
        return settings.build_json_report(None, is_error=True, error_string="Invalid report_reason provided", is_free_request=True)
    if report_id is None:
        return settings.build_json_report(None, is_error=True, error_string="Invalid report_id provided", is_free_request=True)

    available_reasons = (
        "spam_or_fake_report",
        "malicious_or_weaponized_content",
        "contains_credentials_or_secrets",
        "contains_personal_data",
        "harassment_or_doxxing",
        "extortion_or_threats",
        "copyright_or_confidential_material",
        "incorrect_or_fraudulent_claim",
        "duplicate_or_low_quality",
        "other_policy_violation"
    )

    if report_reason not in list(available_reasons):
        return settings.build_json_report(None, is_error=True, error_string="Invalid report_reason provided", is_free_request=True)

    report = sql.get_report_by_report_id(report_id)
    if report is None:
        return settings.build_json_report(None, is_error=True, error_string="Invalid report ID provided", is_free_request=True)
    is_reported = sql.insert_audit_log(
        "reported", "user_reported_researcher", f"report came in for report ID: {report_id} (reported for: {report_reason})",
        actor_id="guest", actor_type="guest_user", target_type="report_researcher"
    )
    if is_reported:
        return settings.build_json_report({"ok": True})
    else:
        return settings.build_json_report(None, is_error=True, error_string="Unable to create report", is_free_request=True)


@onlyvulns_free.route("/reports/search", methods=["POST"])
@limiter.limit("10 per second", key_func=limit_free_requests)
def search_report():
    data = request.get_json(force=True)
    report_id = data.get("report_id", None)
    if report_id is None:
        return settings.build_json_report(None, is_error=True, error_string="Invalid report ID provided", is_free_request=True)
    report_data = sql.get_report_by_report_id(report_id)
    if report_data is None:
        return settings.build_json_report(None, is_error=True, error_string="Invalid report ID provided", is_free_request=True)
    file_status = report_data['report_files']['file_status']
    if file_status == "locked":
        report_files = None
    else:
        report_files = sql.get_report_files(report_data)
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
    return settings.build_json_report(retval, is_free_request=True)


@onlyvulns_free.route("/reports", methods=["GET"])
@limiter.limit("10 per second", key_func=limit_free_requests)
def list_reports():
    return settings.build_json_report(sql.get_reports(), is_free_request=True)


@onlyvulns_free.route("/feed", methods=["GET"])
@onlyvulns_free.route("/feed.<feed_format>", methods=["GET"])
@limiter.limit("10 per hour", key_func=limit_free_requests)
def report_feed(feed_format=None):
    requested_format = feed_format or request.args.get("format") or "json"
    print(requested_format)
    limit = request.args.get("limit", 200, type=int)
    limit = max(1, min(limit, 200))
    reports = sql.get_reports(limit=limit)
    if requested_format == "json":
        feed = settings.build_json_feed(reports)
        return settings.build_json_report(feed, is_free_request=True)
    elif requested_format == "xml":
        feed = settings.build_xml_feed(reports)
        return Response(feed, mimetype="application/xml; charset=utf-8")
    elif requested_format == "rss":
        feed = settings.build_rss_feed(reports)
        return Response(feed, mimetype="application/rss+xml; charset=utf-8")
    else:
        return settings.build_json_report(None, is_error=True, error_string="Invalid feed format", is_free_request=True)


@onlyvulns_free.route("/vote", methods=["POST"])
@limiter.limit("234234234234 per hour", key_func=limit_reputation_change)
def vote_on_user():
    data = request.get_json(force=True)
    rid = data.get("rid", None)
    vote_type = data.get("type", None)
    if rid is None:
        return settings.build_json_report(None, is_error=True, error_string="No researcher ID supplied", is_free_request=True)
    if vote_type is None:
        return settings.build_json_report(None, is_error=True, error_string="No vote type provided", is_free_request=True)
    if vote_type not in ["up", "down"]:
        return settings.build_json_report(None, is_error=True, error_string="Invalid vote type provided", is_free_request=True)
    user_exists = sql.find_researcher_by_id(rid)
    if user_exists is None:
        sql.add_researcher_vote_event(
            rid, None, "invalid_researcher",
            settings.get_string_hash(settings.get_client_ip(request, get_remote_address()))
        )
        return settings.build_json_report(None, is_error=True, error_string="Invalid researcher ID provided", is_free_request=True)
    if user_exists['reputation'] < settings.MAX_LEAST_REP:
        return settings.build_json_report(None, is_error=True, error_string="User reputation cannot be downvoted", is_free_request=True)
    associated_user_email = user_exists['email_address']
    if associated_user_email is None:
        return settings.build_json_report(None, is_error=True, error_string="Invalid researcher ID provided", is_free_request=True)
    success = sql.change_researcher_reputation(associated_user_email, downvote=True if vote_type == "down" else False)
    if success:
        sql.add_researcher_vote_event(
            rid,
            1 if vote_type == "up" else -1,
            "downvote" if vote_type == "down" else "upvote",
            settings.get_string_hash(settings.get_client_ip(request, get_remote_address()))
        )
        return settings.build_json_report({"ok": True}, is_free_request=True)
    else:
        sql.add_researcher_vote_event(
            rid,0,"unable_to_vote",
            settings.get_string_hash(settings.get_client_ip(request, get_remote_address()))
        )
        return settings.build_json_report(None, is_error=True, error_string="Unable to change researcher reputation", is_free_request=True)


@onlyvulns_free.route("/researcher", methods=["POST"])
@limiter.limit("5 per second", key_func=limit_free_requests)
def get_researcher():
    data = request.get_json(force=True)
    researcher_id = data.get("researcher_id", None)
    if researcher_id is None:
        return settings.build_json_report(None, is_error=True, error_string="No researcher ID supplied", is_free_request=True)
    user_exists = sql.get_researcher_by_researcher_id(researcher_id)
    if user_exists is None:
        return settings.build_json_report(None, is_error=True, error_string="Invalid researcher ID provided", is_free_request=True)
    user_reports = sql.get_reports_by_researcher_id(researcher_id)
    return settings.build_json_report({
        "researcher_id": researcher_id,
        "researcher_registration_date": user_exists['registered_at'],
        "researcher_reputation": user_exists['reputation'],
        "researcher_total_reports": user_exists['total_reports'],
        "is_researcher_verified": user_exists['is_verified'],
        "researcher_tips": {
            "is_researcher_eligible": user_exists['researcher_tips']['is_researcher_eligible'],
            "is_accepted_by_researcher": user_exists['researcher_tips']['accepted_by_researcher'],
        },
        "researcher_reports": user_reports,
        "researcher_badges": user_exists['badges'],
        "researcher_display_name": user_exists['display_name'],
    }, is_free_request=True)


@onlyvulns_free.route("/researcher/reputation", methods=["GET"])
@limiter.limit("5 per second", key_func=limit_free_requests)
def get_researcher_by_reputation():
    users = sql.get_users_by_highest_reputation()
    retval = []
    for user in users:
        retval.append({
            "researcher_id": user['user_id'],
            "researcher_reputation": user['reputation'],
            "researcher_total_reports": user['total_reports'],
            "researcher_eligible_for_tips": user['researcher_tips']['is_researcher_eligible']
        })
    return settings.build_json_report(retval, is_free_request=True)


#
# END PUBLIC ENDPOINTS
#

#
# START CHAT ROOM ENDPOINTS
#

@onlyvulns_chats.route("/enter", methods=["GET"])
@limiter.limit("2 per day", key_func=limit_chat_sends)
def enter_chat():
    user = chatrooms.create_chat_user()
    now_ts = int(time.time())
    expires_at = now_ts + chatrooms.CHAT_TTL
    chatrooms.add_message({
        "type": "system",
        "author": user['username'],
        "message": f"{user['username']} has entered the chat",
        "sent_at": now_ts,
        "expires": expires_at,
    }, expires_at)
    return settings.build_json_report({
        "username": user['username'],
        "chat_token": user['chat_token'],
        "expires_at": user['expires_at']
    })


@onlyvulns_chats.route("/send", methods=["POST"])
@limiter.limit("3 per second", key_func=limit_chat_sends)
def send_chat():
    data = request.get_json(force=True) or {}
    message = data.get("message", None)
    token = data.get("chat_token", None)
    if message is None:
        return settings.build_json_report(
            None,
            is_error=True,
            error_string="No message provided"
        )
    if token is None:
        return settings.build_json_report(
            None,
            is_error=True,
            error_string="No chat token provided"
        )

    user = chatrooms.get_chat_user(token)

    if not user:
        return settings.build_json_report(
            None,
            is_error=True,
            error_string="Invalid or expired chat token provided"
        )

    if not isinstance(message, str):
        return settings.build_json_report(
            None,
            is_error=True,
            error_string="Message must be a string"
        )

    message = message.strip()
    if not message:
        return settings.build_json_report(
            None,
            is_error=True,
            error_string="Message cannot be empty"
        )
    if len(message) > 15000:
        return settings.build_json_report(
            None,
            is_error=True,
            error_string="Message too long"
        )

    now_ts = int(time.time())
    expires_at = now_ts + chatrooms.CHAT_TTL
    chatrooms.add_message({
        "type": "message",
        "author": user["username"],
        "message": message,
        "sent_at": now_ts,
        "expires": expires_at,
    }, expires_at)
    return settings.build_json_report({"ok": True})


@onlyvulns_chats.route("/view", methods=["POST"])
@limiter.limit("10 per second", key_func=limit_chat_sends)
def view_chat():
    data = request.get_json(force=True)
    token = data.get("chat_token", None)
    if token is None:
        return settings.build_json_report(None, is_error=True, error_string="No chat token provided")
    user = chatrooms.get_chat_user(token)
    if not user:
        return settings.build_json_report(None, is_error=True, error_string="Invalid chat token provided")
    messages = chatrooms.get_messages()
    return settings.build_json_report({
        "username": user['username'],
        "messages": messages
    })

#
# END CHAT ROOM ENDPOINTS
#
