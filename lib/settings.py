import uuid
import json
import time

from flask import jsonify


def load_env():
    return json.load(open('env.json'))


def build_id(**kwargs):
    is_error = kwargs.get('is_error', False)

    if is_error:
        template = "err_"
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
    return jsonify(retval)


