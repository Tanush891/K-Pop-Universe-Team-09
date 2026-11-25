import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from sqlalchemy import Boolean, Column, DateTime, Integer, String, create_engine, or_
from sqlalchemy.orm import declarative_base, sessionmaker


DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./data/kpop_universe.db")

if DATABASE_URL.startswith("sqlite:///./"):
    db_path = DATABASE_URL.replace("sqlite:///./", "", 1)
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
    if DATABASE_URL.startswith("sqlite")
    else {},
)

SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()
password_hasher = PasswordHasher()

SECRET_KEY = os.getenv("SECRET_KEY", "change-this-secret-before-use")
ALGORITHM = "HS256"
ACCESS_TOKEN_MINUTES = 30
REFRESH_TOKEN_DAYS = 7


class Users(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(255), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(20), default="fan", nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


Base.metadata.create_all(engine)


def add_user(username, email, password):
    with SessionLocal() as session:
        email = email.lower()

        existing_user = session.query(Users).filter(
            or_(Users.email == email, Users.username == username)
        ).first()

        if existing_user:
            return False

        new_user = Users(
            username=username,
            email=email,
            hashed_password=password_hasher.hash(password),
            role="fan",
        )

        session.add(new_user)
        session.commit()
        session.refresh(new_user)

        return new_user.id


def verify_login(username, password):
    with SessionLocal() as session:
        user = session.query(Users).filter_by(username=username).first()

        if not user or not user.is_active:
            return False

        try:
            password_hasher.verify(user.hashed_password, password)
        except VerificationError:
            return False

        return {"id": user.id, "role": user.role}


def create_token(user_id, role, token_type):
    now = datetime.now(timezone.utc)

    if token_type == "refresh":
        expiry = now + timedelta(days=REFRESH_TOKEN_DAYS)
    else:
        expiry = now + timedelta(minutes=ACCESS_TOKEN_MINUTES)

    token_data = {
        "sub": str(user_id),
        "role": role,
        "type": token_type,
        "iat": now,
        "exp": expiry,
    }

    return jwt.encode(token_data, SECRET_KEY, algorithm=ALGORITHM)


def make_token_pair(user_id, role):
    return {
        "access_token": create_token(user_id, role, "access"),
        "refresh_token": create_token(user_id, role, "refresh"),
        "token_type": "bearer",
    }

def add_user(username, email, password, role="fan"):
    with SessionLocal() as session:
        email = email.lower()

        existing_user = session.query(Users).filter(
            (Users.email == email) | (Users.username == username)
        ).first()

        if existing_user:
            return False

        new_user = Users(
            username=username,
            email=email,
            hashed_password=password_hasher.hash(password),
            role=role,
        )
        session.add(new_user)
        session.commit()
        session.refresh(new_user)

        return new_user.id


def verify_token(token, expected_type):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        return False

    if payload.get("type") != expected_type:
        return False

    return payload


def get_user(user_id):
    with SessionLocal() as session:
        user = session.get(Users, user_id)

        if not user or not user.is_active:
            return None

        return {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
        }


def create_first_admin():
    username = os.getenv("ADMIN_USERNAME")
    email = os.getenv("ADMIN_EMAIL")
    password = os.getenv("ADMIN_PASSWORD")

    if not username or not email or not password:
        return

    with SessionLocal() as session:
        admin = session.query(Users).filter_by(role="admin").first()

        if not admin:
            new_admin = Users(
                username=username,
                email=email.lower(),
                hashed_password=password_hasher.hash(password),
                role="admin",
            )
            session.add(new_admin)
            session.commit()