from google.cloud import datastore

def populate_initial_users():
    client = datastore.Client()
    
    initial_users = [
        {"role": "admin", "sub": "auth0|6a1fcf4b040f388adcca1434"},
        
        {"role": "instructor", "sub": "auth0|6a1fd015040f388adcca1494"},
        {"role": "instructor", "sub": "auth0|6a1fd02daf300457019d3e8e"},
        
        {"role": "student", "sub": "auth0|6a1fd042040f388adcca14ac"},
        {"role": "student", "sub": "auth0|6a1fd047af300457019d3e9c"},
        {"role": "student", "sub": "auth0|6a1fd04c040f388adcca14b1"},
        {"role": "student", "sub": "auth0|6a1fd05079e9ae8a08dfffef"},
        {"role": "student", "sub": "auth0|6a1fd053dedd4d17e91285da"},
        {"role": "student", "sub": "auth0|6a1fd05b79e9ae8a08dffff7"}
    ]
    
    print("Populating 9 users into Datastore...")
    
    for user in initial_users:
        key = client.key("users")
        user_entity = datastore.Entity(key=key)
        
        user_entity.update({
            "sub": user["sub"],
            "role": user["role"]
        })
        
        client.put(user_entity)
        print(f"Created {user['role']} entity with Datastore ID: {user_entity.key.id}")

if __name__ == "__main__":
    populate_initial_users()