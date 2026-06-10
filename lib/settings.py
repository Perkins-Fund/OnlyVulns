import uuid
import json
import time

from itsdangerous import URLSafeTimedSerializer


def load_env():
    return json.load(open('env.json'))


def build_id(**kwargs):
    is_error = kwargs.get('is_error', False)
    is_user_id = kwargs.get('is_user_id', False)

    if is_error:
        template = "err_"
    elif is_user_id:
        template = ""
    else:
        template = "req_"
    return f"{template}{uuid.uuid4().hex}"


def build_json_report(output, **kwargs):
    is_error = kwargs.get('is_error', False)
    error_string = kwargs.get('error_string', None)

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
    else:
        success = True
    retval['success'] = success
    retval['metadata'] = {
        "request_id": build_id(),
        "request_timestamp": int(time.time())
    }
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
