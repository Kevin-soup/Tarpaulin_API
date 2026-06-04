# Tarpaulin API

## Overview

Tarpaulin API is a cloud-hosted backend course management system inspired by learning management platforms such as Canvas. The application provides secure RESTful endpoints for managing users, courses, enrollments, and profile avatars using role-based access control, cloud data storage, and JWT authentication.

This project focuses exclusively on backend development and demonstrates authentication, authorization, database management, file storage integration, and cloud deployment using Google Cloud Platform.

## UML Diagram - Workflow

The following sequence diagram illustrates the authentication, authorization, and avatar management workflows used by the application.

```mermaid
sequenceDiagram
    autonumber
    actor Client as Client
    participant API as Flask API
    participant Auth0 as Auth0 Service
    participant DS as Cloud Datastore
    participant GCS as Cloud Storage

    Note over Client, DS: User Authentication & Role Authorization
    Client->>API: POST /users/login
    API->>Auth0: Authenticate credentials
    Auth0-->>API: Return JWT
    API-->>Client: Return JWT

    Client->>API: GET /users/:id
    API->>Auth0: Verify JWT
    Auth0-->>API: Return validated payload
    API->>DS: Query user by sub
    DS-->>API: Return user entity
    API-->>Client: Return authorized user data

    Note over Client, GCS: Avatar Management
    Client->>API: POST /users/:id/avatar
    API->>DS: Fetch user record
    DS-->>API: Return user metadata
    API->>GCS: Upload avatar file
    API->>DS: Update avatar filename
    API-->>Client: Return avatar URL
```

## Cloud Services

### Auth0 Authentication

Auth0 handles user authentication and issues JSON Web Tokens (JWTs). Protected endpoints validate JWTs and enforce role-based permissions.

### Google Cloud Datastore

Datastore serves as the application's primary database, storing user records, course information, and enrollment data.

### Google Cloud Storage

Cloud Storage manages user avatar files and provides scalable object storage for uploaded media.


## Data Model

### Users

| Property         | Data Type | Required | Description                                 |
| ---------------- | --------- | -------- | ------------------------------------------- |
| id               | Integer   | No       | Datastore-generated user identifier.        |
| role             | String    | Yes      | User role (admin, instructor, student).     |
| sub              | String    | Yes      | Auth0 subject identifier.                   |
| avatar_file_name | String    | No       | Filename of avatar stored in Cloud Storage. |

### Courses

| Property      | Data Type | Required | Description                            |
| ------------- | --------- | -------- | -------------------------------------- |
| id            | Integer   | No       | Datastore-generated course identifier. |
| instructor_id | String    | Yes      | Assigned instructor identifier.        |
| number        | Integer   | Yes      | Course number.                         |
| students      | Array     | No       | Enrolled student identifiers.          |
| subject       | String    | Yes      | Course subject code.                   |
| term          | String    | Yes      | Academic term.                         |
| title         | String    | Yes      | Course title.                          |

## Objectives

* Design and implement a secure RESTful API.
* Integrate Auth0 authentication with JWT-based authorization.
* Store application data using Google Cloud Datastore.
* Manage user avatar files with Google Cloud Storage.
* Enforce role-based access control for administrators, instructors, and students.
* Deploy a cloud-hosted backend application using Google App Engine.


## Technologies Used

* Python
* Flask
* Google App Engine
* Google Cloud Datastore
* Google Cloud Storage
* Auth0
* JWT Authentication
* REST APIs
* Postman

## Notes

This project was developed as a portfolio project for Cloud Application Development and showcases secure backend API development using modern cloud-native technologies.
