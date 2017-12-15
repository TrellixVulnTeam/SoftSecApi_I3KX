import json
from six.moves.urllib.request import urlopen
from functools import wraps

from flask import Flask, request, jsonify, _app_ctx_stack, Response
from flask_cors import cross_origin
from jose import jwt, JWTError
app = Flask(__name__)

AUTH0_DOMAIN = 'jentonic.eu.auth0.com'
API_AUDIENCE = 'https://jentonic.eu.auth0.com/api/v2/'
ALGORITHMS = ["RS256"]

APP = Flask(__name__)


# Error handler
def get_http_exception_handler(app):
    """Overrides the default http exception handler to return JSON."""
    handle_http_exception = app.handle_http_exception
    @wraps(handle_http_exception)
    def ret_val(exception):
        exc = handle_http_exception(exception)
        return jsonify({'code':exc.code, 'message':exc.description}), exc.code
    return ret_val

# Override the HTTP exception handler.
app.handle_http_exception = get_http_exception_handler(app)

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code

# @app.errorhandler(JWTError)
# def handle_auth_error(ex):
#     raise AuthError({"code": "invalid_header",
#                "description":
#                    "Unable to parse authentication"
#                    " token."}, 401)

@app.errorhandler(AuthError)
def handle_auth_error(ex):
    print(ex.error)
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


# Format error response and append status code

def get_token_auth_header():
    """Obtains the access token from the Authorization Header
    """
    auth = request.headers.get("Authorization", None)
    if not auth:
        raise AuthError({"code": "authorization_header_missing",
                         "description":
                             "Authorization header is expected"}, 401)

    parts = auth.split()

    if parts[0].lower() != "bearer":
        raise AuthError({"code": "invalid_header",
                         "description":
                             "Authorization header must start with"
                             " Bearer"}, 401)
    elif len(parts) == 1:
        raise AuthError({"code": "invalid_header",
                         "description": "Token not found"}, 401)
    elif len(parts) > 2:
        raise AuthError({"code": "invalid_header",
                         "description":
                             "Authorization header must be"
                             " Bearer token"}, 401)

    token = parts[1]
    return token


def requires_auth(f):
    """Determines if the access token is valid
    """

    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_token_auth_header()
        jsonurl = urlopen("https://" + AUTH0_DOMAIN + "/.well-known/jwks.json")
        jwks = json.loads(jsonurl.read())
        try:
            unverified_header = jwt.get_unverified_header(token)
        except(JWTError):
            raise AuthError({"code": "invalid_header",
                       "description":
                           "Unable to parse authentication"
                           " token."}, 401)
        rsa_key = {}
        for key in jwks["keys"]:
            if key["kid"] == unverified_header["kid"]:
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n": key["n"],
                    "e": key["e"]
                }
        if rsa_key:
            try:
                payload = jwt.decode(
                    token,
                    rsa_key,
                    algorithms=ALGORITHMS,
                    audience=API_AUDIENCE,
                    issuer="https://" + AUTH0_DOMAIN + "/"
                )
            except jwt.ExpiredSignatureError:
                raise AuthError({"code": "token_expired",
                                 "description": "token is expired"}, 401)
            except jwt.JWTClaimsError:
                raise AuthError({"code": "invalid_claims",
                                 "description":
                                     "incorrect claims,"
                                     "please check the audience and issuer"}, 401)
            except Exception:
                raise AuthError({"code": "invalid_header",
                                 "description":
                                     "Unable to parse authentication"
                                     " token."}, 400)

            _app_ctx_stack.top.current_user = payload
            return f(*args, **kwargs)
        raise AuthError({"code": "invalid_header",
                         "description": "Unable to find appropriate key"}, 400)

    return decorated

# Controllers API

# Geen authentication
@app.route('/api/public')
@cross_origin(headers=['Content-Type', 'Authorization'])
def publicApi():
    return 'Software Security - Public jAPI'

# Wel authentication
@app.route('/api/private')
@cross_origin(headers=['Content-Type', 'Authorization'])
@requires_auth
def privateApi():
    return 'Software Security - Private jAPI'

if __name__ == '__main__':
    app.run()
