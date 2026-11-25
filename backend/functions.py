
from datetime import datetime, timedelta, timezone
import os

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from sqlalchemy import Column, DateTime, Integer, String, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./data/kpop_universe.db")
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
    if DATABASE_URL.startswith("sqlite") else {},
)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()
password_hasher = PasswordHasher()

SECRET_KEY = os.getenv("SECRET_KEY", "development-secret-change-before-deployment")
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
    is_active = Column(Integer, default=1, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


Base.metadata.create_all(engine)


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

    payload = {
        "sub": str(user_id),
        "role": role,
        "type": token_type,
        "iat": now,
        "exp": expiry,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def make_token_pair(user_id, role):
    return {
        "access_token": create_token(user_id, role, "access"),
        "refresh_token": create_token(user_id, role, "refresh"),
        "token_type": "bearer",
    }