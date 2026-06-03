import io, json, os, requests, uuid
from urllib.request import urlopen
from dotenv import load_dotenv
from flask import Flask, request, jsonify, send_file
from google.cloud import storage, datastore
from google.cloud.datastore.query import PropertyFilter
from jose import jwt

app = Flask(__name__)
client = datastore.Client()
storage_client = storage.Client()
load_dotenv()

# Constant.
AVATAR_BUCKET = 'kevin-soup-avatar'
USER = '/users'
COURSE = '/courses'
ID = '/id'

# Auth0 Configuration.
CLIENT_ID = os.getenv("AUTH0_CLIENT_ID")
CLIENT_SECRET = os.getenv("AUTH0_CLIENT_SECRET")
DOMAIN = os.getenv("AUTH0_DOMAIN")
ALGORITHMS = ["RS256"]

# Auth0 - JWT Token Authentication.
# Code adapted from: https://auth0.com/docs/quickstart/backend/python
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
############################ USER LOGIN - JWT GENERATION #############################
@app.route(USER + '/login', methods=['POST'])
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
    

#################################### DECODE A JWT ####################################
@app.route('/decode', methods=['GET'])
def decode_jwt():
    # Validate JWT.
    payload = verify_jwt(request)

    # Return decoded payload attributes. Success.
    return payload, 200 


#################################### GET ALL USERS ####################################
@app.route(USER, methods=['GET'])
def get_all_users():
    # Validate JWT and extract sub.
    payload = verify_jwt(request)
    user_sub = payload.get("sub")

    # Identify user's role from Datastore.
    query = client.query(kind='users')
    query.add_filter(filter=PropertyFilter("sub", "=", user_sub))
    results = list(query.fetch())

    # Check for admin role. Failure.
    requesting_user = results[0]
    if requesting_user.get("role") != "admin":
        return {"Error": "The JWT is valid but doesn’t belong to an admin."}, 403

    # Get all users from Datastore.
    all_users_query = client.query(kind='users')
    all_users = list(all_users_query.fetch())
    output = []

    # Return array with all users. Success.
    for entity in all_users:
        user_data = {
            "id": entity.key.id,
            "role": entity.get("role"),
            "sub": entity.get("sub")
        }
        output.append(user_data)

    return jsonify(output), 200


###################################### GET A USER ########################################
@app.route(USER + '/<int:id>', methods=['GET'])
def get_user(id):
    # Validate JWT and extract sub.
    payload = verify_jwt(request)
    user_sub = payload.get("sub")

    # Find target with ID.
    user_key = client.key('users', id)
    target_user = client.get(key=user_key)

    # Handles non-existent target ID. Failure.
    if target_user is None:
        return {"Error": "The JWT is valid, but the user doesn’t exist."}, 403

    # Identify user's role from Datastore.
    query = client.query(kind='users')
    query.add_filter(filter=PropertyFilter("sub", "=", user_sub))
    results = list(query.fetch())

    # Check for admin role and user self access. Failure.
    requesting_user = results[0]
    if requesting_user.get("role") != "admin" and requesting_user.key.id != id:
        return {"Error": "The JWT is valid, and the user exists, but the JWT doesn’t belong to either an admin or to the user whose ID is in the path parameter."}, 403

    # Return target information. Success.
    user_data = {
        "id": id,
        "role": target_user.get("role"),
        "sub": target_user.get("sub")
    }

    # Check if target has avatar URL.
    if target_user.get("avatar_url"):
        user_data["avatar_url"] = target_user.get("avatar_url")

    # Check if target has courses.
    if user_data["role"] != "admin":
        user_data["courses"] = target_user.get("courses", [])

    return jsonify(user_data), 200


################################# CREATE & UPDATE AVATAR ###################################
@app.route(USER + '/<int:id>/avatar', methods=['POST'])
def update_avatar(id):
    # Check if file exists in request. Failure.
    if 'file' not in request.files:
        return {"Error": "The request doesn’t include the key “file.”"}, 400

    # Validate JWT and extract sub.
    payload = verify_jwt(request)
    user_sub = payload.get("sub")

    # Find target with ID.
    user_key = client.key('users', id)
    target_user = client.get(key=user_key)

    # Check for user self access. Failure.
    if target_user is None or target_user.get("sub") != user_sub:
        return {"Error": "The JWT is valid but doesn’t belong to the user whose ID is in the path parameter."}, 403

    # Save request file.
    file_obj = request.files['file']

    # Check if avatar exists. Remove old file from Cloud Storage.
    if target_user.get("avatar_blob_name"):
        bucket = storage_client.get_bucket(AVATAR_BUCKET)
        old_blob = bucket.blob(target_user["avatar_blob_name"])
        old_blob.delete()

    # Generate random file name for Cloud Storage.
    random_filename = f"{uuid.uuid4().hex}.png"

    # Get bucket handle.
    bucket = storage_client.get_bucket(AVATAR_BUCKET)
    
    # Create blob object with file name.
    blob = bucket.blob(random_filename)
    
    # Position file_obj to beginning.
    file_obj.seek(0)
    
    # Upload file into Cloud Storage.
    blob.upload_from_file(file_obj, content_type='image/png')

    # Update user information. Success.
    target_user["avatar_blob_name"] = random_filename
    target_user["avatar_url"] = f"{request.url_root.rstrip('/')}/users/{id}/avatar"
    client.put(target_user)

    return jsonify({"avatar_url": target_user["avatar_url"]}), 200


################################### GET AVATAR ###################################
@app.route(USER + '/<int:id>/avatar', methods=['GET'])
def get_avatar(id):
    # Validate JWT and extract sub.
    payload = verify_jwt(request)
    user_sub = payload.get("sub")

    # Find target with ID.
    user_key = client.key('users', id)
    target_user = client.get(key=user_key)

    # Check for user self access. Failure.
    if target_user is None or target_user.get("sub") != user_sub:
        return {"Error": "The JWT is valid but doesn’t belong to the user whose ID is in the path parameter."}, 403

    # Check if avatar exists. Failure.
    if not target_user.get("avatar_blob_name"):
        return {"Error": "The JWT is valid, belongs to the user whose ID is in the path parameter, but the user doesn’t have an avatar."}, 404

    # Get bucket handle.
    bucket = storage_client.get_bucket(AVATAR_BUCKET)
    
    # Create blob object with file name.
    blob = bucket.blob(target_user["avatar_blob_name"])
    
    # Download file into memory.
    file_obj = io.BytesIO()
    blob.download_to_file(file_obj)
    file_obj.seek(0)

    # Return file. Success.
    return send_file(file_obj, mimetype='image/png'), 200


################################## DELETE AVATAR ###################################
@app.route(USER + '/<int:id>/avatar', methods=['DELETE'])
def delete_avatar(id):
    # Validate JWT and extract sub.
    payload = verify_jwt(request)
    user_sub = payload.get("sub")

    # Find target with ID.
    user_key = client.key('users', id)
    target_user = client.get(key=user_key)

    # Check for user self access. Failure.
    if target_user is None or target_user.get("sub") != user_sub:
        return {"Error": "The JWT is valid but doesn’t belong to the user whose ID is in the path parameter."}, 403

    # Check if avatar exists. Failure.
    if not target_user.get("avatar_blob_name"):
        return {"Error": "The JWT is valid, belongs to the user whose ID is in the path parameter, but the user doesn’t have an avatar."}, 404

    # Get bucket handle.
    bucket = storage_client.get_bucket(AVATAR_BUCKET)
    
    # Create blob object with file name.
    blob = bucket.blob(target_user["avatar_blob_name"])
    
    # Delete file from Cloud Storage.
    blob.delete()

    # Update user information. Success.
    target_user["avatar_blob_name"] = None
    target_user["avatar_url"] = None
    client.put(target_user)

    return '', 204


################################### CREATE A COURSE ###################################
@app.route(COURSE, methods=['POST'])
def create_course():
    # Save JSON request.
    content = request.get_json()

    # Handles missing attributes. Failure.
    required_fields = ["subject", "number", "title", "term", "instructor_id"]
    if not content or not all(field in content for field in required_fields):
        return {"Error": "The request body is missing at least one of the required attributes"}, 400

    # Validate JWT and extract sub. 
    payload = verify_jwt(request)
    user_sub = payload.get("sub")

    # Identify user's role from Datastore.
    query = client.query(kind='users')
    query.add_filter(filter=PropertyFilter("sub", "=", user_sub))
    results = list(query.fetch())

    # Check for admin role. Failure.
    requesting_user = results[0]
    if requesting_user.get("role") != "admin":
        return {"Error": "The JWT is valid but doesn’t belong to an admin."}, 403

    # Check if instructor id exists and corresponds to a user with the role "instructor". Failure.
    instructor_key = client.key('users', int(content["instructor_id"]))
    instructor = client.get(key=instructor_key)

    if instructor is None or instructor.get("role") != "instructor":
        return {"Error": "The value of instructor_id is invalid"}, 409

    # Create new course entity. Success.
    new_course = datastore.Entity(key=client.key('courses'))
    new_course.update({
        "subject": content["subject"],
        "number": int(content["number"]),
        "title": content["title"],
        "term": content["term"],
        "instructor_id": int(content["instructor_id"]),
        "students": []  
    })
    client.put(new_course)

    # Return course information. Success. success response layout.
    course_id = new_course.key.id
    response_data = {
        "id": course_id,
        "instructor_id": new_course["instructor_id"],
        "number": new_course["number"],
        "self": f"{request.url_root.rstrip('/')}/courses/{course_id}",
        "subject": new_course["subject"],
        "term": new_course["term"],
        "title": new_course["title"]
    }

    return jsonify(response_data), 201





if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)