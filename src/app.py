"""High School Management System API."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict
from uuid import uuid4
import base64
import hashlib
import hmac
import os

import jwt
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse

app = FastAPI(title="Mergington High School API",
              description="API for viewing and signing up for extracurricular activities")

SECRET_KEY = os.getenv(
    "AUTH_SECRET_KEY",
    "dev-only-change-me-please-set-auth-secret-key-32plus"
)
ACCESS_TOKEN_MINUTES = int(os.getenv("ACCESS_TOKEN_MINUTES", "15"))
REFRESH_TOKEN_DAYS = int(os.getenv("REFRESH_TOKEN_DAYS", "7"))

users: Dict[str, Dict[str, str]] = {}
refresh_sessions: Dict[str, Dict[str, Any]] = {}
bearer_scheme = HTTPBearer(auto_error=False)

# Mount the static files directory
current_dir = Path(__file__).parent
app.mount("/static", StaticFiles(directory=os.path.join(Path(__file__).parent,
          "static")), name="static")

# In-memory activity database
activities = {
    "Chess Club": {
        "description": "Learn strategies and compete in chess tournaments",
        "schedule": "Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 12,
        "participants": ["michael@mergington.edu", "daniel@mergington.edu"]
    },
    "Programming Class": {
        "description": "Learn programming fundamentals and build software projects",
        "schedule": "Tuesdays and Thursdays, 3:30 PM - 4:30 PM",
        "max_participants": 20,
        "participants": ["emma@mergington.edu", "sophia@mergington.edu"]
    },
    "Gym Class": {
        "description": "Physical education and sports activities",
        "schedule": "Mondays, Wednesdays, Fridays, 2:00 PM - 3:00 PM",
        "max_participants": 30,
        "participants": ["john@mergington.edu", "olivia@mergington.edu"]
    },
    "Soccer Team": {
        "description": "Join the school soccer team and compete in matches",
        "schedule": "Tuesdays and Thursdays, 4:00 PM - 5:30 PM",
        "max_participants": 22,
        "participants": ["liam@mergington.edu", "noah@mergington.edu"]
    },
    "Basketball Team": {
        "description": "Practice and play basketball with the school team",
        "schedule": "Wednesdays and Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["ava@mergington.edu", "mia@mergington.edu"]
    },
    "Art Club": {
        "description": "Explore your creativity through painting and drawing",
        "schedule": "Thursdays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["amelia@mergington.edu", "harper@mergington.edu"]
    },
    "Drama Club": {
        "description": "Act, direct, and produce plays and performances",
        "schedule": "Mondays and Wednesdays, 4:00 PM - 5:30 PM",
        "max_participants": 20,
        "participants": ["ella@mergington.edu", "scarlett@mergington.edu"]
    },
    "Math Club": {
        "description": "Solve challenging problems and participate in math competitions",
        "schedule": "Tuesdays, 3:30 PM - 4:30 PM",
        "max_participants": 10,
        "participants": ["james@mergington.edu", "benjamin@mergington.edu"]
    },
    "Debate Team": {
        "description": "Develop public speaking and argumentation skills",
        "schedule": "Fridays, 4:00 PM - 5:30 PM",
        "max_participants": 12,
        "participants": ["charlotte@mergington.edu", "henry@mergington.edu"]
    }
}


class AuthRequest(BaseModel):
    email: str
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


def hash_password(password: str, salt: bytes | None = None) -> str:
    if salt is None:
        salt = os.urandom(16)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, 120_000)
    return f"{base64.b64encode(salt).decode()}${base64.b64encode(password_hash).decode()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt_b64, hash_b64 = stored_hash.split("$", maxsplit=1)
    except ValueError:
        return False
    salt = base64.b64decode(salt_b64)
    expected_hash = base64.b64decode(hash_b64)
    computed_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, 120_000)
    return hmac.compare_digest(computed_hash, expected_hash)


def validate_password_rules(password: str) -> None:
    if len(password) < 8:
        raise HTTPException(
            status_code=400,
            detail="Password must be at least 8 characters long"
        )


def create_jwt_token(email: str, token_type: str, expires_delta: timedelta) -> tuple[str, str]:
    issued_at = datetime.now(timezone.utc)
    expires_at = issued_at + expires_delta
    token_id = str(uuid4())
    payload = {
        "sub": email,
        "type": token_type,
        "jti": token_id,
        "iat": issued_at,
        "exp": expires_at,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256"), token_id


def decode_jwt_token(token: str, expected_type: str) -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(status_code=401, detail="Token expired") from exc
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc

    if payload.get("type") != expected_type:
        raise HTTPException(status_code=401, detail="Invalid token type")

    email = payload.get("sub")
    if not isinstance(email, str) or email not in users:
        raise HTTPException(status_code=401, detail="Invalid token subject")

    return payload


def issue_token_pair(email: str) -> Dict[str, str]:
    access_token, _ = create_jwt_token(
        email, "access", timedelta(minutes=ACCESS_TOKEN_MINUTES))
    refresh_token, refresh_jti = create_jwt_token(
        email, "refresh", timedelta(days=REFRESH_TOKEN_DAYS))

    refresh_sessions[refresh_jti] = {
        "email": email,
        "revoked": False,
    }

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


def require_authenticated_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)
) -> str:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Missing bearer token")

    payload = decode_jwt_token(credentials.credentials, "access")
    return payload["sub"]


users["teacher@mergington.edu"] = {
    "password_hash": hash_password("Teach3rPass!"),
}


@app.get("/")
def root():
    return RedirectResponse(url="/static/index.html")


@app.get("/activities")
def get_activities():
    return activities


@app.post("/auth/register")
def register(auth_request: AuthRequest):
    email = auth_request.email.strip().lower()
    if not email:
        raise HTTPException(status_code=400, detail="Email is required")
    if email in users:
        raise HTTPException(status_code=400, detail="User already exists")

    validate_password_rules(auth_request.password)
    users[email] = {
        "password_hash": hash_password(auth_request.password),
    }
    return {"message": "Registration successful"}


@app.post("/auth/login")
def login(auth_request: AuthRequest):
    email = auth_request.email.strip().lower()
    user = users.get(email)
    if not user or not verify_password(auth_request.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    return issue_token_pair(email)


@app.post("/auth/refresh")
def refresh_tokens(refresh_request: RefreshRequest):
    payload = decode_jwt_token(refresh_request.refresh_token, "refresh")
    refresh_jti = payload["jti"]
    email = payload["sub"]

    session = refresh_sessions.get(refresh_jti)
    if not session or session.get("revoked") or session.get("email") != email:
        raise HTTPException(status_code=401, detail="Refresh token is invalid")

    session["revoked"] = True
    return issue_token_pair(email)


@app.post("/auth/logout")
def logout(refresh_request: RefreshRequest):
    payload = decode_jwt_token(refresh_request.refresh_token, "refresh")
    refresh_jti = payload["jti"]
    email = payload["sub"]
    session = refresh_sessions.get(refresh_jti)

    if not session or session.get("email") != email:
        raise HTTPException(status_code=401, detail="Refresh token is invalid")

    session["revoked"] = True
    return {"message": "Logged out successfully"}


@app.post("/activities/{activity_name}/signup")
def signup_for_activity(
    activity_name: str,
    email: str,
    current_user: str = Depends(require_authenticated_user)
):
    """Sign up a student for an activity"""
    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Get the specific activity
    activity = activities[activity_name]

    # Validate student is not already signed up
    if email in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is already signed up"
        )

    # Add student
    activity["participants"].append(email)
    return {
        "message": f"Signed up {email} for {activity_name}",
        "updated_by": current_user
    }


@app.delete("/activities/{activity_name}/unregister")
def unregister_from_activity(
    activity_name: str,
    email: str,
    current_user: str = Depends(require_authenticated_user)
):
    """Unregister a student from an activity"""
    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Get the specific activity
    activity = activities[activity_name]

    # Validate student is signed up
    if email not in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is not signed up for this activity"
        )

    # Remove student
    activity["participants"].remove(email)
    return {
        "message": f"Unregistered {email} from {activity_name}",
        "updated_by": current_user
    }
