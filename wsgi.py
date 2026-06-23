import backend.api as api

from flask_cors import CORS


app = api.app
app.register_blueprint(api.onlyvulns_v1)
app.register_blueprint(api.onlyvulns_free)
app.register_blueprint(api.onlyvulns_chats)


CORS(app, resources={r"/a*": {"origins": "*"}})