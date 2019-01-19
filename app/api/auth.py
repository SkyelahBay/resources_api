import requests
from flask import request
from app.models import Key
from app.utils import standardize_response
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()


def authenticate(func):
    def wrapper(*args, **kwargs):
        apikey = request.headers.get('x-apikey')
        key = Key.query.filter_by(apikey=apikey).first()

        if not key:
            errors = [{"code": "not-authorized"}]
            return standardize_response(None, errors, "not authorized", 401)

        log_request(request, key)

        return func(*args, **kwargs)
    return wrapper


def check_user_with_oc(json):
    response = requests.post('https://api.operationcode.org/api/v1/sessions', json={
        "user": {
            "email": json.get('email'),
            "password": json.get('password')
        }
    })

    return bool(response.json().get('token'))


def log_request(request, key):
    method = request.method
    path = request.path
    user = key.email
    payload = request.json
    logger.info(f"User: {user} Route: {method} {path} Payload: {payload}")
