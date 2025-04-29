from flask import Flask
from flask_cors import CORS

def create_app():
    app = Flask(__name__, template_folder='../templates')  # optional

    # ✅ Enable CORS (for all origins)
    CORS(app)

    from .routes import main
    app.register_blueprint(main)

    return app
