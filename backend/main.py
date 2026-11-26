from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, EmailStr, Field

import functions as db

app = FastAPI(title="K-Pop Universe API")


class RegisterIn(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class LoginIn(BaseModel):
    username: str
    password: str = Field(min_length=1, max_length=128)


@app.post("/auth/register", status_code=201)
def register(data: RegisterIn):
    user_id = db.add_user(data.username, data.email, data.password)

    if not user_id:
        raise HTTPException(
            status_code=409,
            detail="Username or email already registered",
        )

    return {
        "id": user_id,
        "username": data.username,
        "email": data.email,
        "role": "fan",
    }


@app.post("/auth/login")
def login(data: LoginIn):
    user = db.verify_login(data.username, data.password)

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
        )

    return db.make_token_pair(user["id"], user["role"])

class RefreshIn(BaseModel):
    refresh_token: str = Field(min_length=1)


class OrganizerIn(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


def get_current_user(authorization: str | None = Header(None)):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Bearer access token required")

    token = authorization.split(" ", 1)[1]
    payload = db.verify_token(token, "access")

    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired access token")

    user = db.get_user(int(payload["sub"]))

    if not user:
        raise HTTPException(status_code=401, detail="Account unavailable")

    return user


def require_admin(user=Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")

    return user


def require_organizer(user=Depends(get_current_user)):
    if user["role"] != "organizer":
        raise HTTPException(status_code=403, detail="Organizer access required")

    return user


# Creates the first admin when ADMIN_USERNAME, ADMIN_EMAIL, and
# ADMIN_PASSWORD are set in the environment.
db.create_first_admin()


@app.post("/auth/refresh")
def refresh(data: RefreshIn):
    payload = db.verify_token(data.refresh_token, "refresh")

    if not payload:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired refresh token",
        )

    user = db.get_user(int(payload["sub"]))

    if not user:
        raise HTTPException(status_code=401, detail="Account unavailable")

    return {
        "access_token": db.create_token(user["id"], user["role"], "access"),
        "token_type": "bearer",
    }


@app.post("/organizers", status_code=201)
def create_organizer(data: OrganizerIn, admin=Depends(require_admin)):
    user_id = db.add_user(
        data.username,
        data.email,
        data.password,
        role="organizer",
    )

    if not user_id:
        raise HTTPException(
            status_code=409,
            detail="Username or email already registered",
        )

    return {
        "id": user_id,
        "username": data.username,
        "email": data.email,
        "role": "organizer",
    }


class ArtistIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(min_length=1)
    category: str = Field(min_length=1, max_length=40)


@app.post("/artists", status_code=201)
def create_artist(
    data: ArtistIn,
    organizer=Depends(require_organizer),
):
    artist = db.add_artist(
        data.name,
        data.description,
        data.category,
        organizer["id"],
    )

    if not artist:
        raise HTTPException(
            status_code=409,
            detail="Artist name already exists",
        )

    return artist


@app.get("/artists")
def get_artists():
    return db.get_artists()


@app.get("/fan-clubs")
def get_fan_clubs():
    return db.get_fan_clubs()
