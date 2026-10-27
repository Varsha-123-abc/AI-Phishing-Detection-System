"""Flask application factory for the phishing analysis dashboard."""

from flask import Flask


def create_app(test_config=None):
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 1_100_000
    app.config["SECRET_KEY"] = "local-development-only-change-before-deployment"

    if test_config:
        app.config.update(test_config)

    from app.routes.main import main_bp
    app.register_blueprint(main_bp)

    return app
