from flask import Flask, request, jsnonify, send_file
from google.cloud import storage, datastore
import io
import requests
import json
from six.moves.urllib.request import urlopen
from jose import jwt

app = Flask(__name__)
client = datastore.Client()

# Constants.
PHOTO_BUCKET='___'
USER = '/users'
COURSES = '/courses'
ID = '/id'

#################################### AUTH0 AUTHENTICATION ####################################
# Code adapted from: 
# https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code

# Error handler for AuthError.
@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# Verify JWT in request Authorization header.
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        if len(auth_header) != 2 or auth_header[0].lower() != 'bearer':
            raise AuthError({"code": "invalid_header",
                             "description": "Authorization header must be Bearer token"}, 401)
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                            "description":
                                "Authorization header is missing"}, 401)
    
    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
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
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)


# API Endpoints.
#################################### USER LOGIN - JWT GENERATION ####################################
@app.route('/login', methods=['POST'])
def login_user():
    # Save JSON request.
    content = request.get_json()

    # Create token request body.
    username = content["username"]
    password = content["password"]
    body = {
        'grant_type': 'password',
        'username': username,
        'password': password,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'scope': 'openid profile email address phone'
    }
    headers = {'content-type': 'application/json'}
    url = 'https://' + DOMAIN + '/oauth/token'
    
    # Post token to Auth0.
    response = requests.post(url, json=body, headers=headers)
    
    # Return Auth0 response.
    return response.json(), response.status_code
    

##################################### DECODE A JWT #####################################
@app.route('/decode', methods=['GET'])
def decode_jwt():
    # Validate JWT.
    payload = verify_jwt(request)

    # Return decoded payload attributes. Success.
    return payload, 200 


@app.route('/images', methods=['POST'])
def store_image():
    # Any files in the request will be available in request.files object
    # Check if there is an entry in request.files with the key 'file'
    if 'file' not in request.files:
        return ('No file sent in request', 400)
    # Set file_obj to the file sent in the request
    file_obj = request.files['file']
    # If the multipart form data has a part with name 'tag', set the
    # value of the variable 'tag' to the value of 'tag' in the request.
    # Note we are not doing anything with the variable 'tag' in this
    # example, however this illustrates how we can extract data from the
    # multipart form data in addition to the files.
    if 'tag' in request.form:
        tag = request.form['tag']
    # Create a storage client
    storage_client = storage.Client()
    # Get a handle on the bucket
    bucket = storage_client.get_bucket(PHOTO_BUCKET)
    # Create a blob object for the bucket with the name of the file
    blob = bucket.blob(file_obj.filename)
    # Position the file_obj to its beginning
    file_obj.seek(0)
    # Upload the file into Cloud Storage
    blob.upload_from_file(file_obj)
    return ({'file_name': file_obj.filename},201)

@app.route('/images/<file_name>', methods=['GET'])
def get_image(file_name):
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(PHOTO_BUCKET)
    # Create a blob with the given file name
    blob = bucket.blob(file_name)
    # Create a file object in memory using Python io package
    file_obj = io.BytesIO()
    # Download the file from Cloud Storage to the file_obj variable
    blob.download_to_file(file_obj)
    # Position the file_obj to its beginning
    file_obj.seek(0)
    # Send the object as a file in the response with the correct MIME type and file name
    return send_file(file_obj, mimetype='image/x-png', download_name=file_name)


@app.route('/images/<file_name>', methods=['DELETE'])
def delete_image(file_name):
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(PHOTO_BUCKET)
    blob = bucket.blob(file_name)
    # Delete the file from Cloud Storage
    blob.delete()
    return '',204

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)