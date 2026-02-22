# Mergington High School Activities API

A super simple FastAPI application that allows students to view and sign up for extracurricular activities.

## Features

- View all available extracurricular activities
- Register and log in teachers with access + refresh tokens
- Refresh and revoke sessions (logout)
- Sign up and unregister students for activities (protected endpoints)

## Getting Started

1. Install the dependencies:

   ```
   pip install -r ../requirements.txt
   ```

2. Run the application:

   ```
   uvicorn app:app --reload
   ```

3. Open your browser and go to:
   - API documentation: http://localhost:8000/docs
   - Alternative documentation: http://localhost:8000/redoc

## API Endpoints

| Method | Endpoint                                                              | Description                                                         |
| ------ | --------------------------------------------------------------------- | ------------------------------------------------------------------- |
| POST   | `/auth/register`                                                      | Register a teacher account                                          |
| POST   | `/auth/login`                                                         | Login and receive access + refresh tokens                           |
| POST   | `/auth/refresh`                                                       | Exchange a valid refresh token for a new access + refresh token     |
| POST   | `/auth/logout`                                                        | Revoke a refresh token session                                      |
| GET    | `/activities`                                                         | Get all activities with their details and current participant count |
| POST   | `/activities/{activity_name}/signup?email=student@mergington.edu`    | Protected: sign up for an activity                                  |
| DELETE | `/activities/{activity_name}/unregister?email=student@mergington.edu` | Protected: unregister from an activity                              |

## Authentication Notes

- Use `Authorization: Bearer <access_token>` for protected write endpoints.
- Access token expiration defaults to 15 minutes.
- Refresh token expiration defaults to 7 days.
- `POST /auth/refresh` rotates refresh tokens and revokes the previous session token.
- `POST /auth/logout` revokes the active refresh token.

## Default Teacher Account

For local development, a pre-seeded teacher user is available:

- Email: `teacher@mergington.edu`
- Password: `Teach3rPass!`

## Data Model

The application uses a simple data model with meaningful identifiers:

1. **Activities** - Uses activity name as identifier:

   - Description
   - Schedule
   - Maximum number of participants allowed
   - List of student emails who are signed up

2. **Students** - Uses email as identifier:
   - Name
   - Grade level

All data is stored in memory, which means data will be reset when the server restarts.
