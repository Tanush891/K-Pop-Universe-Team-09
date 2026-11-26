import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    create_engine,
    or_,
)
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

class FanClubs(Base):
    __tablename__ = "fan_clubs"

    id = Column(Integer, primary_key=True)
    name = Column(String(120), unique=True, nullable=False)
    description = Column(Text, nullable=False)
    artist_id = Column(Integer, ForeignKey("artists.id"), nullable=False)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class ClubMembers(Base):
    __tablename__ = "club_members"
    __table_args__ = (UniqueConstraint("club_id", "user_id"),)

    id = Column(Integer, primary_key=True)
    club_id = Column(Integer, ForeignKey("fan_clubs.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    joined_at = Column(DateTime, default=datetime.utcnow)


class Posts(Base):
    __tablename__ = "posts"

    id = Column(Integer, primary_key=True)
    author_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    text = Column(Text, nullable=False)
    image_url = Column(String(2048), nullable=True)
    is_hidden = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class PostLikes(Base):
    __tablename__ = "post_likes"
    __table_args__ = (UniqueConstraint("post_id", "user_id"),)

    id = Column(Integer, primary_key=True)
    post_id = Column(Integer, ForeignKey("posts.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)


class Polls(Base):
    __tablename__ = "polls"

    id = Column(Integer, primary_key=True)
    artist_id = Column(Integer, ForeignKey("artists.id"), nullable=False)
    organizer_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    question = Column(String(500), nullable=False)
    options = Column(Text, nullable=False)
    opens_at = Column(DateTime, nullable=False)
    closes_at = Column(DateTime, nullable=False)


class PollVotes(Base):
    __tablename__ = "poll_votes"
    __table_args__ = (UniqueConstraint("poll_id", "user_id"),)

    id = Column(Integer, primary_key=True)
    poll_id = Column(Integer, ForeignKey("polls.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    option_index = Column(Integer, nullable=False)


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


class Artists(Base):
    __tablename__ = "artists"

    id = Column(Integer, primary_key=True)
    name = Column(String(120), unique=True, nullable=False)
    description = Column(Text, nullable=False)
    category = Column(String(40), nullable=False)
    created_by = Column(ForeignKey("users.id"), nullable=False)


Base.metadata.create_all(engine)


def add_artist(name, description, category, organizer_id):
    with SessionLocal() as session:
        existing_artist = session.query(Artists).filter_by(name=name).first()

        if existing_artist:
            return False

        artist = Artists(
            name=name,
            description=description,
            category=category,
            created_by=organizer_id,
        )
        session.add(artist)
        session.commit()
        session.refresh(artist)

        return {
            "id": artist.id,
            "name": artist.name,
            "description": artist.description,
            "category": artist.category,
            "created_by": artist.created_by,
        }


def get_artists():
    with SessionLocal() as session:
        artists = session.query(Artists).order_by(Artists.name).all()

        return [
            {
                "id": artist.id,
                "name": artist.name,
                "description": artist.description,
                "category": artist.category,
                "created_by": artist.created_by,
            }
            for artist in artists
        ]


def get_artist(artist_id):
    with SessionLocal() as session:
        artist = session.get(Artists, artist_id)

        if not artist:
            return None

        return {
            "id": artist.id,
            "name": artist.name,
            "description": artist.description,
            "category": artist.category,
            "created_by": artist.created_by,
        }


def get_fan_clubs():
    with SessionLocal() as session:
        clubs = session.query(FanClubs).order_by(FanClubs.name).all()

        return [
            {
                "id": club.id,
                "name": club.name,
                "description": club.description,
                "artist_id": club.artist_id,
                "created_by": club.created_by,
            }
            for club in clubs
        ]

def join_fan_club(club_id, fan_id):
    with SessionLocal() as session:
        club = session.get(FanClubs, club_id)

        if not club:
            return None

        existing_member = session.query(ClubMembers).filter_by(
            club_id=club_id,
            user_id=fan_id,
        ).first()

        if existing_member:
            return False

        member = ClubMembers(club_id=club_id, user_id=fan_id)
        session.add(member)
        session.commit()

        return {"joined": True, "club_id": club_id}


def add_post(author_id, text, image_url=None):
    with SessionLocal() as session:
        post = Posts(
            author_id=author_id,
            text=text,
            image_url=image_url,
        )
        session.add(post)
        session.commit()
        session.refresh(post)

        return {
            "id": post.id,
            "author_id": post.author_id,
            "text": post.text,
            "image_url": post.image_url,
            "created_at": post.created_at,
            "like_count": 0,
        }