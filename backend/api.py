from flask import Flask, request, Blueprint
from flask_limiter.util import get_remote_address
from flask_limiter import Limiter

import lib.settings as settings


app = Flask(__name__)
onlyvulns_v1 = Blueprint('onlyvulns', __name__, url_prefix='/api/v1')


def limit_requests():
    data = request.get_json(force=True)
    token = data.get("token", None)
    use_ip = False
    if token is None:
        use_ip = True
    if not use_ip:
        return f"tok:{token}"
    else:
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


@app.route("/")
def public_home():
    return settings.build_json_report({
        "version": "1.0",
        "title": "OnlyVulns API"
    })


#
# CREATE USER LOGIN
#


