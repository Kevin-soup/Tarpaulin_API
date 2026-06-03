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

# Error messages.
ERROR_400 = {"Error": "The request body is invalid"}
ERROR_401 = {"Error": "Unauthorized"}
ERROR_403 = {"Error": "You don't have permission on this resource"}
ERROR_404 = {"Error": "Not found"}

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
            raise AuthError(ERROR_401, 401)
        token = auth_header[1]
    else:
        raise AuthError(ERROR_401, 401)

    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError(ERROR_401, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError(ERROR_401, 401)
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
            raise AuthError(ERROR_401, 401)
        except jwt.JWTClaimsError:
            raise AuthError(ERROR_401, 401)
        except Exception:
            raise AuthError(ERROR_401, 401)

        return payload
    else:
        raise AuthError(ERROR_401, 401)


# API Endpoints.
############################ USER LOGIN - JWT GENERATION #############################
@app.route(USER + '/login', methods=['POST'])
def login_user():
    # Save JSON request.
    content = request.get_json()

    # Handles missing attributes. Failure.
    required_fields = ["username", "password"]
    if not content or not all(field in content for field in required_fields):
        return jsonify(ERROR_400), 400
    
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

    # Validate password on Auth0.
    if response.status_code != 200:
        return jsonify(ERROR_401), 401
    
    # Return Auth0 response.
    return jsonify({"token": response.json().get("id_token")}), 200
    

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
        return jsonify(ERROR_403), 403

    # Get all users from Datastore.
    all_users_query = client.query(kind='users')
    all_users = list(all_users_query.fetch())
    output = []

    # Build and return array with all users. Success.
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

    # Find target on Datastore with ID.
    user_key = client.key('users', id)
    target_user = client.get(key=user_key)

    # Handles non-existent target ID. Failure.
    if target_user is None:
        return jsonify(ERROR_403), 403

    # Identify user's role from Datastore.
    query = client.query(kind='users')
    query.add_filter(filter=PropertyFilter("sub", "=", user_sub))
    results = list(query.fetch())

    # Check for admin role and user self access. Failure.
    requesting_user = results[0]
    if requesting_user.get("role") != "admin" and requesting_user.key.id != id:
        return jsonify(ERROR_403), 403

    # Build return information. Success.
    user_data = {
        "id": id,
        "role": target_user.get("role"),
        "sub": target_user.get("sub")
    }
    
    # Define base URL.
    base_url = request.url_root.rstrip('/')

    # Check if target has avatar URL.
    if target_user.get("avatar_file_name"):
            user_data["avatar_url"] = f"{base_url}/users/{id}/avatar"

    # Check if target has courses.
    if user_data["role"] != "admin":
        course_urls = []
        course_query = client.query(kind='courses')
        
        if user_data["role"] == "instructor":
            course_query.add_filter(filter=PropertyFilter("instructor_id", "=", id))
        elif user_data["role"] == "student":
            course_query.add_filter(filter=PropertyFilter("students", "=", id))
            
        courses_fetched = list(course_query.fetch())
        for course in courses_fetched:
            course_urls.append(f"{base_url}/courses/{course.key.id}")
            
        user_data["courses"] = course_urls

    return jsonify(user_data), 200


################################# CREATE & UPDATE AVATAR ###################################
@app.route(USER + '/<int:id>/avatar', methods=['POST'])
def update_avatar(id):
    # Check if file exists in request. Failure.
    if 'file' not in request.files:
        return jsonify(ERROR_400), 400

    # Validate JWT and extract sub.
    payload = verify_jwt(request)
    user_sub = payload.get("sub")

    # Find target on Datastore with ID.
    user_key = client.key('users', id)
    target_user = client.get(key=user_key)

    # Check for user self access. Failure.
    if target_user is None or target_user.get("sub") != user_sub:
        return jsonify(ERROR_403), 403

    # Save request file.
    file_obj = request.files['file']

    # Check if avatar exists. Remove old file from Cloud Storage.
    if target_user.get("avatar_file_name"):
        bucket = storage_client.get_bucket(AVATAR_BUCKET)
        old_blob = bucket.blob(target_user["avatar_file_name"])
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

    # Update user information.
    target_user["avatar_file_name"] = random_filename
    client.put(target_user)
    
    # Build return URL. Success.
    base_url = request.url_root.replace("http://", "https://").rstrip('/')

    return jsonify({"avatar_url": f"{base_url}/users/{id}/avatar"}), 200


################################### GET AVATAR ###################################
@app.route(USER + '/<int:id>/avatar', methods=['GET'])
def get_avatar(id):
    # Validate JWT and extract sub.
    payload = verify_jwt(request)
    user_sub = payload.get("sub")

    # Find target on Datastore with ID.
    user_key = client.key('users', id)
    target_user = client.get(key=user_key)

    # Check for user self access. Failure.
    if target_user is None or target_user.get("sub") != user_sub:
        return jsonify(ERROR_403), 403

    # Check if avatar exists. Failure.
    if not target_user.get("avatar_file_name"):
        return jsonify(ERROR_404), 404

    # Get bucket handle.
    bucket = storage_client.get_bucket(AVATAR_BUCKET)
    
    # Create blob object with file name.
    blob = bucket.blob(target_user["avatar_file_name"])
    
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

    # Find target on Datastore with ID.
    user_key = client.key('users', id)
    target_user = client.get(key=user_key)

    # Check for user self access. Failure.
    if target_user is None or target_user.get("sub") != user_sub:
        return jsonify(ERROR_403), 403

    # Check if avatar exists. Failure.
    if not target_user.get("avatar_file_name"):
        return jsonify(ERROR_404), 404

    # Get bucket handle.
    bucket = storage_client.get_bucket(AVATAR_BUCKET)
    
    # Create blob object with file name.
    blob = bucket.blob(target_user["avatar_file_name"])
    
    # Delete file from Cloud Storage.
    blob.delete()

    # Update user information. Success.
    target_user["avatar_file_name"] = None
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
        return jsonify(ERROR_400), 400

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
        return jsonify(ERROR_403), 403

    # Check instructor id and role. Failure.
    instructor_id = content["instructor_id"]
    instructor_key = client.key('users', instructor_id)
    instructor = client.get(key=instructor_key)

    if instructor is None or instructor.get("role") != "instructor":
        return {"Error": "The value of instructor_id is invalid"}, 409

    # Create new course entity. 
    new_course = datastore.Entity(key=client.key('courses'))
    new_course.update({
        "subject": content["subject"],
        "number": content["number"],
        "title": content["title"],
        "term": content["term"],
        "instructor_id": instructor_id,
        "students": []  
    })
    client.put(new_course)

    # Return course information. Success. 
    course_id = new_course.key.id
    response_data = {
        "id": course_id,
        "instructor_id": instructor_id,
        "number": content["number"],
        "self": f"{request.url_root.rstrip('/')}/courses/{course_id}",
        "subject": content["subject"],
        "term": content["term"],
        "title": content["title"]
    }

    return jsonify(response_data), 201


###################################### GET ALL COURSES ####################################
@app.route(COURSE, methods=['GET'])
def get_all_courses():
    # Query parameters.
    limit = int(request.args.get('limit', 3))
    offset = int(request.args.get('offset', 0))

    # Sort courses by subject from Datastore.
    course_query = client.query(kind='courses')
    course_query.order = ['subject']
    
    # Iterator pages for pagination.
    course_iterator = course_query.fetch(limit=limit, offset=offset)
    pages = course_iterator.pages
    try:
        results = list(next(pages))
    except StopIteration:
        results = []

    # Define base URL.
    base_url = request.url_root.rstrip('/')
    
    # Build return information. Success. 
    courses_list = []
    for course in results:
        course_id = course.key.id
        course_data = {
            "id": course_id,
            "instructor_id": course.get("instructor_id"),
            "number": course.get("number"),
            "self": f"{base_url}/courses/{course_id}",
            "subject": course.get("subject"),
            "term": course.get("term"),
            "title": course.get("title")
        }
        courses_list.append(course_data)

    response_data = {
        "courses": courses_list
    }

    # Add pagination.
    if course_iterator.next_page_token:
        next_offset = offset + limit
        response_data["next"] = f"{base_url}/courses?limit={limit}&offset={next_offset}"

    return jsonify(response_data), 200


###################################### GET A COURSE ######################################
@app.route(COURSE + '/<int:id>', methods=['GET'])
def get_course(id):
    # Find target on Datastore with ID.
    course_key = client.key('courses', id)
    target_course = client.get(key=course_key)

    # Handles non-existent target ID. Failure.
    if target_course is None:
        return jsonify(ERROR_404), 404

    # Define base URL.
    base_url = request.url_root.rstrip('/')

    # Build return information. Success. 
    course_data = {
        "id": id,
        "instructor_id": target_course.get("instructor_id"),
        "number": target_course.get("number"),
        "self": f"{base_url}/courses/{id}",
        "subject": target_course.get("subject"),
        "term": target_course.get("term"),
        "title": target_course.get("title")
    }

    return jsonify(course_data), 200


################################### UPDATE COURSE ###################################
@app.route(COURSE + '/<int:id>', methods=['PATCH'])
def update_course(id):
    # Save JSON request.
    content = request.get_json()

    # Validate JWT and extract sub. 
    payload = verify_jwt(request)
    user_sub = payload.get("sub")

    # Find target on Datastore with ID.
    course_key = client.key('courses', id)
    target_course = client.get(key=course_key)

    # Handles non-existent target ID or invalid permissions. Failure.
    if target_course is None:
        return jsonify(ERROR_403), 403

    # Identify user's role from Datastore.
    query = client.query(kind='users')
    query.add_filter(filter=PropertyFilter("sub", "=", user_sub))
    results = list(query.fetch())
    requesting_user = results[0]

    # Check for admin role. Failure.
    if requesting_user.get("role") != "admin":
        return jsonify(ERROR_403), 403

    # Check instructor id and role. Failure.
    if content and "instructor_id" in content:
        instructor_id = content["instructor_id"]
        instructor_key = client.key('users', instructor_id)
        instructor = client.get(key=instructor_key)

        if instructor is None or instructor.get("role") != "instructor":
            return {"Error": "The value of instructor_id is invalid"}, 409

    # Update course entity. Success.
    valid_fields = ["subject", "number", "title", "term", "instructor_id"]
    if content:
        for field in valid_fields:
            if field in content:
                target_course[field] = content[field]
        client.put(target_course)

    # Return course information. Success. 
    base_url = request.url_root.rstrip('/')
    response_data = {
        "id": id,
        "instructor_id": target_course.get("instructor_id"),
        "number": target_course.get("number"),
        "self": f"{base_url}/courses/{id}",
        "subject": target_course.get("subject"),
        "term": target_course.get("term"),
        "title": target_course.get("title")
    }

    return jsonify(response_data), 200


################################### DELETE COURSE ###################################
@app.route(COURSE + '/<int:id>', methods=['DELETE'])
def delete_course(id):
    # Validate JWT and extract sub. 
    payload = verify_jwt(request)
    user_sub = payload.get("sub")

    # Find target on Datastore with ID.
    course_key = client.key('courses', id)
    target_course = client.get(key=course_key)

    # Handles non-existent target ID. Failure.
    if target_course is None:
        return jsonify(ERROR_403), 403

    # Identify user's role from Datastore.
    query = client.query(kind='users')
    query.add_filter(filter=PropertyFilter("sub", "=", user_sub))
    results = list(query.fetch())
    requesting_user = results[0]

    # Check for admin role. Failure.
    if requesting_user.get("role") != "admin":
        return jsonify(ERROR_403), 403

    # Delete course. Success.
    client.delete(course_key)

    return '', 204


################################### UPDATE ENROLLMENT ###################################
@app.route(COURSE + '/<int:id>/students', methods=['PATCH'])
def update_enrollment(id):
    # Save JSON request.
    content = request.get_json()

    # Validate JWT and extract sub. 
    payload = verify_jwt(request)
    user_sub = payload.get("sub")

    # Find target on Datastore with ID.
    course_key = client.key('courses', id)
    target_course = client.get(key=course_key)

    # Handles non-existent target ID. Failure.
    if target_course is None:
        return jsonify(ERROR_403), 403

    # Identify user's role from Datastore.
    query = client.query(kind='users')
    query.add_filter(filter=PropertyFilter("sub", "=", user_sub))
    results = list(query.fetch())


    # Check for admin or course instructor role. Failure.
    requesting_user = results[0]
    is_admin = requesting_user.get("role") == "admin"
    is_instructor = requesting_user.get("role") == "instructor" and target_course.get("instructor_id") == requesting_user.key.id

    if not is_admin and not is_instructor:
        return jsonify(ERROR_403), 403

    # Save add and remove lists. 
    add_list = content.get("add", [])
    remove_list = content.get("remove", [])

    # Handles common values in lists.
    if set(add_list) & set(remove_list):
        return {"Error": "Enrollment data is invalid"}, 409

    # Check that IDs belong to users with student role.
    all_student_ids = list(set(add_list + remove_list))
    if all_student_ids:
        student_keys = [client.key('users', s_id) for s_id in all_student_ids]
        fetched_students = client.get_multi(student_keys)
        
        # Check that all users are students.
        if len(fetched_students) != len(all_student_ids) or any(s.get("role") != "student" for s in fetched_students):
            return {"Error": "Enrollment data is invalid"}, 409

    # Build new course entity.
    current_students = target_course.get("students", [])

    # Add students to course. 
    for student_id in add_list:
        if student_id not in current_students:
            current_students.append(student_id)

    # Remove students from course.
    for student_id in remove_list:
        if student_id in current_students:
            current_students.remove(student_id)

    # Update Datastore with new course entity. Success.
    target_course["students"] = current_students
    client.put(target_course)

    return '', 200


################################### GET ENROLLMENT ###################################
@app.route(COURSE + '/<int:id>/students', methods=['GET'])
def get_enrollment(id):
    # Validate JWT and extract sub. 
    payload = verify_jwt(request)
    user_sub = payload.get("sub")

    # Find target on Datastore with ID.
    course_key = client.key('courses', id)
    target_course = client.get(key=course_key)

    # Handles non-existent target ID. Failure.
    if target_course is None:
        return jsonify(ERROR_403), 403

    # Identify user's role from Datastore.
    query = client.query(kind='users')
    query.add_filter(filter=PropertyFilter("sub", "=", user_sub))
    results = list(query.fetch())

    # Check for admin or course instructor role. Failure.
    requesting_user = results[0]
    is_admin = requesting_user.get("role") == "admin"
    is_instructor = requesting_user.get("role") == "instructor" and target_course.get("instructor_id") == requesting_user.key.id

    if not is_admin and not is_instructor:
        return jsonify(ERROR_403), 403

    # Return course information. Success. 
    current_students = target_course.get("students", [])

    return jsonify(current_students), 200


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)