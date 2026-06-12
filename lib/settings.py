import os
import uuid
import json
import time
import hashlib
import ipaddress

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
