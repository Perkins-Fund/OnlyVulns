import os
import uuid
import json
import time
import hashlib
import ipaddress

from datetime import datetime, timezone
from email.utils import format_datetime
from html import escape

from itsdangerous import URLSafeTimedSerializer


MAX_FILES_PER_REPORT = 5
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
MAX_TOTAL_FILE_SIZE = 10 * 1024 * 1024  # 10MB total size
MAX_LEAST_REP = -10


def load_env():
    return json.load(open('env.json'))


def build_id(**kwargs):
    is_error = kwargs.get('is_error', False)
    is_user_id = kwargs.get('is_user_id', False)
    is_report_id = kwargs.get('is_report_id', False)
    is_file_id = kwargs.get('is_file_id', False)

    if is_error:
        template = "err_"
    elif is_file_id:
        template = "fle_"
    elif is_report_id:
        template = "rep_"
    elif is_user_id:
        template = ""
    else:
        template = "req_"
    return f"{template}{uuid.uuid4().hex}"


def build_json_report(output, **kwargs):
    is_error = kwargs.get('is_error', False)
    error_string = kwargs.get('error_string', None)
    is_free_request = kwargs.get("is_free_request", False)

    if output is None:
        output = {}
    retval = {
        "results": output,
        "error": {},
    }
    if is_error:
        success = False
        if error_string is None:
            retval["error"]['error_string'] = 'Failed to make request'
        else:
            retval['error']['error_string'] = error_string
        retval['error']['error_id'] = build_id(is_error=True)
    else:
        success = True
    retval['success'] = success
    retval['metadata'] = {
        "request_id": build_id(),
        "request_timestamp": int(time.time())
    }
    if is_free_request:
        retval['metadata']['note'] = "Made with <3 by PCEF; consider donating: https://perkinsfund.org/donations"
    return retval



def make_admin_serial():
    secret = load_env()['user_config']['user_secret']
    return URLSafeTimedSerializer(secret)


def make_serial():
    secret = load_env()['user_config']['admin_secret']
    return URLSafeTimedSerializer(secret)


def create_user_token(username, is_admin=False):
    if not is_admin:
        serializer = make_serial()
        return serializer.dumps({"token": username})
    else:
        serializer = make_admin_serial()
        return serializer.dumps({"token": username})


def verify_token(token, is_admin=False):
    try:
        if not is_admin:
            serial = make_serial()
            max_age = load_env()['user_config']['session_secrets']['user_max_age']
            data = serial.loads(token, max_age=max_age)
            return data['token']
        else:
            serial = make_admin_serial()
            max_age = load_env()['user_config']['session_secrets']['admin_max_age']
            data = serial.loads(token, max_age=max_age)
            return data['token']
    except:
        return None


def is_valid_ip(value):
    if not value:
        return False
    try:
        ipaddress.ip_address(value.strip())
        return True
    except:
        return False


def normalize_ip_value(value):
    if not value:
        return None
    value = value.strip()
    if value.startswith('[') and value.endswith(']'):
        value = value[1:-1]
    if is_valid_ip(value):
        return value
    return None


def valid_from_csv(value, delim=","):
    if not value:
        return None
    for item in value.split(delim):
        ip = normalize_ip_value(item)
        if ip:
            return ip
    return None


def get_client_ip(req, fallback_func):
    cf_headers = (
        "CF-Connecting-IP",
        "True-Client-IP",
        "CF-Pseudo-IPv4"
    )
    single_ip_headers = (
        "X-Real-IP",
        "X-Client-IP",
        "X-Forwarded",
        "Forwarded-For",
        "X-Cluster-Client-IP",
        "Fastly-Client-IP",
        "Fly-Client-IP",
        "X-Appengine-User-IP",
        "X-Azure-ClientIP",
        "X-Original-Forwarded-For",
    )
    for header in cf_headers:
        ip = normalize_ip_value(req.headers.get(header))
        if ip:
            return ip
    for header in single_ip_headers:
        ip = normalize_ip_value(req.headers.get(header))
        if ip:
            return ip
    forwarded = req.headers.get("Forwarded")
    ip = valid_from_csv(forwarded, delim=";")
    if ip:
        return ip
    ip = valid_from_csv(req.headers.get("X-Forwarded-For"), delim=",")
    if ip:
       return ip
    ip = normalize_ip_value(req.remote_addr)
    if ip:
        return ip
    ip = normalize_ip_value(fallback_func())
    if ip:
        return ip
    return None


def get_uploaded_file_size(fh):
    pos = fh.stream.tell()
    fh.stream.seek(0, os.SEEK_END)
    size = fh.stream.tell()
    fh.stream.seek(pos)
    return size


def get_file_hash_from_stream(storage, alg="sha256", chunk_size=1024*1024):
    stream = storage.stream
    pos = stream.tell()
    stream.seek(0)
    h = hashlib.new(alg)
    while True:
        chunk = stream.read(chunk_size)
        if not chunk:
            break
        h.update(chunk)
    stream.seek(pos)
    return h.hexdigest()


def validate_file_upload(files):
    files = [fh for fh in files if fh and fh.filename]
    if len(files) > MAX_FILES_PER_REPORT:
        return False, "Max files per report exceeded"
    total_size = 0
    for fh in files:
        size = get_uploaded_file_size(fh)
        if size <= 0:
            return False, "Empty files are not allowed"
        if size > MAX_FILE_SIZE:
            return False, "Max file size exceeded"
        total_size += size
        if total_size > MAX_TOTAL_FILE_SIZE:
            return False, "Max file size per report exceeded"
    return True, None


def generate_username():
    return hashlib.sha256(os.urandom(64)).hexdigest()[0:9]



def parse_feed_datetime(value):
    if not value:
        return datetime.now(timezone.utc)

    if isinstance(value, datetime):
        dt = value
    else:
        try:
            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return datetime.now(timezone.utc)

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt


def get_cvss_score_name(score):
    try:
        score = float(score)
    except:
        return "Unknown"
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0:
        return "Low"
    return "None"


def build_json_feed(reports):
    feed_reports = []

    for report in reports:
        print(report)
        if report.get("current_status") != "released":
            continue
        tmp = {
            "id": report.get("report_id"),
            "title": report.get("report_title"),
            "raw_cvss_score": report.get("cvss_score"),
            "readable_cvss_score": get_cvss_score_name(report.get("cvss_score")),
            "write_up": report.get("report_write_up"),
            "release_date": report.get("metadata", {}).get("wait_end_date"),
            "date_reported": report.get("metadata", {}).get("date_reported_on"),
            "link": f"https://onlyvulns.org/report?report_id={report.get('report_id')}",
            "vendor": report.get("associated_vendor"),
            "files": [],
        }
        attached_files = (
            report.get("report_files", {})
            .get("attached_files", [])
        )
        for file_ in attached_files:
            tmp["files"].append({
                "sha256": file_.get("file_hash"),
                "content_type": file_.get("content_type")
            })
        feed_reports.append(tmp)
    return feed_reports


def build_file_xml(report):
    attached_files = (
        report.get("report_files", {})
        .get("attached_files", [])
    )

    if not attached_files:
        return ""

    file_items = []

    for file_ in attached_files:
        sha256 = escape(str(file_.get("file_hash") or ""))
        content_type = escape(str(file_.get("content_type") or ""))

        file_items.append(f"""
                <onlyvulns:file>
                    <onlyvulns:sha256>{sha256}</onlyvulns:sha256>
                    <onlyvulns:content_type>{content_type}</onlyvulns:content_type>
                </onlyvulns:file>""")

    return f"""
            <onlyvulns:files>
                {''.join(file_items)}
            </onlyvulns:files>"""


def build_rss_feed(reports, is_xml=False):
    now = datetime.now(timezone.utc)
    last_build_date = format_datetime(now)

    items = []

    for report in reports:
        if report.get("current_status") != "released":
            continue
        report_id = str(report.get("report_id") or "")
        title = escape(str(report.get("report_title") or "Untitled Vulnerability Report"))
        link = escape(f"https://onlyvulns.com/reports?report_id={report_id}")
        guid = escape(report_id)
        metadata = report.get("metadata", {})
        release_date = parse_feed_datetime(
            report.get("published_at")
            or report.get("released_at")
            or metadata.get("wait_end_date")
        )
        pub_date = format_datetime(release_date)
        description = escape(
            str(
                report.get("public_summary")
                or report.get("report_write_up")
                or "A public vulnerability disclosure report has been released."
            )
        )
        write_up = escape(str(report.get("report_write_up") or ""))
        release_date_raw = escape(str(metadata.get("wait_end_date") or ""))
        date_reported_raw = escape(str(metadata.get("date_reported_on") or ""))
        cvss_score = escape(str(report.get("cvss_score") or ""))
        severity = escape(str(get_cvss_score_name(report.get("cvss_score"))))
        vendor = escape(str(report.get("associated_vendor") or ""))
        files_xml = build_file_xml(report)
        items.append(f"""
        <item>
            <title>{title}</title>
            <link>{link}</link>
            <guid isPermaLink="false">{guid}</guid>
            <pubDate>{pub_date}</pubDate>
            <description>{description}</description>
            <category>{severity}</category>

            <onlyvulns:id>{guid}</onlyvulns:id>
            <onlyvulns:vendor>{vendor}</onlyvulns:vendor>
            <onlyvulns:raw_cvss_score>{cvss_score}</onlyvulns:raw_cvss_score>
            <onlyvulns:readable_cvss_score>{severity}</onlyvulns:readable_cvss_score>
            <onlyvulns:write_up>{write_up}</onlyvulns:write_up>
            <onlyvulns:release_date>{release_date_raw}</onlyvulns:release_date>
            <onlyvulns:date_reported>{date_reported_raw}</onlyvulns:date_reported>
            {files_xml}
        </item>""")
        if is_xml:
            url = "https://onlyvulns.org/api/free/feed.xml"
        else:
            url = "https://onlyvulns.com/api/free/feed.rss"
    rss = f"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:onlyvulns="{url}">
    <channel>
        <title>OnlyVulns Free Vulnerability Feed</title>
        <link>https://onlyvulns.com</link>
        <description>Free public vulnerability disclosure reports from OnlyVulns.</description>
        <language>en-us</language>
        <lastBuildDate>{last_build_date}</lastBuildDate>
        <ttl>30</ttl>
        {''.join(items)}
    </channel>
</rss>
"""
    return rss


def build_xml_feed(reports):
    return build_rss_feed(reports, is_xml=True)
