from fastapi import FastAPI, HTTPException
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