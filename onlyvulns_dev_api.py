import backend.api as api

from flask_cors import CORS


app = api.app
app.register_blueprint(api.onlyvulns_v1)
app.register_blueprint(api.onlyvulns_free)
CORS(app, resources={r"/a*": {"origins": "*"}})


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5132)
