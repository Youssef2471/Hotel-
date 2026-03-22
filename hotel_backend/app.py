from flask import Flask
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from prometheus_flask_exporter import PrometheusMetrics

import config
from database import init_db
from security.jwt_handler import token_blocklist
from routes.auth import auth_bp
from routes.rooms import rooms_bp
from routes.bookings import bookings_bp
from routes.payments import payments_bp


app = Flask(__name__)
CORS(app)  # allows Flutter to talk to Flask

from prometheus_client import Counter, generate_latest

REQUEST_COUNT = Counter('request_count', 'Total Requests')

@app.route('/metrics')
def metrics():
    return generate_latest()

PrometheusMetrics(app)

app.config["JWT_SECRET_KEY"] = config.JWT_SECRET_KEY
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = config.JWT_ACCESS_TOKEN_EXPIRES

jwt = JWTManager(app)


@jwt.token_in_blocklist_loader
def check_if_token_revoked(_jwt_header, jwt_payload):
    return jwt_payload["jti"] in token_blocklist


app.register_blueprint(auth_bp)
app.register_blueprint(rooms_bp)
app.register_blueprint(bookings_bp)
app.register_blueprint(payments_bp)


@app.route("/")
def home():
    return {"message": "Hotel Reservation API is running"}


with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=config.DEBUG)  # nosec B104

