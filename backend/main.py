"""FastAPI backend for K-Pop Universe."""

import json
from datetime import datetime, timezone

from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr, Field, HttpUrl, model_validator
from sqlalchemy.exc import IntegrityError

import functions as db


app = FastAPI(title="K-Pop Universe API", version="1.0.0")

db.create_first_admin()


# Time helper: convert any datetime to naive UTC (matches how SQLite stores it)
def to_utc_naive(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt
    return dt.astimezone(timezone.utc).replace(tzinfo=None)


# Request models
class RegisterIn(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class LoginIn(BaseModel):
    username: str
    password: str = Field(min_length=1, max_length=128)


class RefreshIn(BaseModel):
    refresh_token: str = Field(min_length=1)


class ArtistIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(min_length=1)
    category: str = Field(min_length=1, max_length=40)


class ClubIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    description: str = Field(min_length=1)
    artist_id: int


class PostIn(BaseModel):
    text: str = Field(min_length=1, max_length=5000)
    image_url: HttpUrl | None = None


class PollIn(BaseModel):
    artist_id: int
    question: str = Field(min_length=1, max_length=500)
    options: list[str] = Field(min_length=2, max_length=10)
    opens_at: datetime
    closes_at: datetime

    @model_validator(mode="after")
    def validate_poll(self):
        self.opens_at = to_utc_naive(self.opens_at)
        self.closes_at = to_utc_naive(self.closes_at)

        if self.closes_at <= self.opens_at:
            raise ValueError("Closing time must be after opening time")

        if any(not option.strip() for option in self.options):
            raise ValueError("Poll options cannot be empty")

        if len(set(option.strip().lower() for option in self.options)) != len(self.options):
            raise ValueError("Poll options must be unique")

        return self


class VoteIn(BaseModel):
    option_index: int = Field(ge=0)


# Authentication helpers
bearer_scheme = HTTPBearer(auto_error=False)


def get_current_user(credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme)):
    if not credentials:
        raise HTTPException(status_code=401, detail="Bearer access token required")

    payload = db.verify_token(credentials.credentials, "access")

    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired access token")

    user = db.get_user(int(payload["sub"]))

    if not user:
        raise HTTPException(status_code=401, detail="Account unavailable")

    return user


def require_role(*roles):
    def check_role(user=Depends(get_current_user)):
        if user["role"] not in roles:
            raise HTTPException(status_code=403, detail="You do not have permission for this action")
        return user

    return check_role


def save_or_conflict(session, message="This item already exists"):
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        raise HTTPException(status_code=409, detail=message)



# A1-A3: Login and registration
@app.post("/auth/register", status_code=201)
def register(data: RegisterIn):
    user_id = db.add_user(data.username, data.email, data.password)

    if not user_id:
        raise HTTPException(status_code=409, detail="Username or email already registered")

    return {
        "id": user_id,
        "username": data.username,
        "email": data.email.lower(),
        "role": "fan"
    }


@app.post("/auth/login")
def login(data: LoginIn):
    user = db.verify_login(data.username, data.password)

    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")

    return db.make_token_pair(user["id"], user["role"])


@app.post("/auth/refresh")
def refresh(data: RefreshIn):
    payload = db.verify_token(data.refresh_token, "refresh")

    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    user = db.get_user(int(payload["sub"]))

    if not user:
        raise HTTPException(status_code=401, detail="Account unavailable")

    access_token = db.create_token(user["id"], user["role"], "access")

    return {
        "access_token": access_token,
        "token_type": "bearer"
    }


# E1: Organizer accounts
@app.post("/organizers", status_code=201)
def create_organizer(data: RegisterIn, admin=Depends(require_role("admin"))):
    user_id = db.add_user(data.username, data.email, data.password, role="organizer")

    if not user_id:
        raise HTTPException(status_code=409, detail="Username or email already registered")

    return {
        "id": user_id,
        "username": data.username,
        "email": data.email.lower(),
        "role": "organizer"
    }


# E2-E4: Artists
def artist_dict(artist):
    return {
        "id": artist.id,
        "name": artist.name,
        "description": artist.description,
        "category": artist.category,
        "created_by": artist.created_by
    }


@app.post("/artists", status_code=201)
def create_artist(data: ArtistIn, organizer=Depends(require_role("organizer"))):
    with db.SessionLocal() as session:
        artist = db.Artists(
            **data.model_dump(),
            created_by=organizer["id"]
        )

        session.add(artist)
        save_or_conflict(session, "Artist name already exists")
        session.refresh(artist)

        return artist_dict(artist)


@app.get("/artists")
def get_artists():
    with db.SessionLocal() as session:
        artists = session.query(db.Artists).order_by(db.Artists.name).all()
        return [artist_dict(artist) for artist in artists]


@app.get("/artists/{artist_id}")
def get_artist(artist_id: int):
    with db.SessionLocal() as session:
        artist = session.get(db.Artists, artist_id)

        if not artist:
            raise HTTPException(status_code=404, detail="Artist not found")

        return artist_dict(artist)


# E5-E7: Fan clubs
def club_dict(club, member_count):
    return {
        "id": club.id,
        "name": club.name,
        "description": club.description,
        "artist_id": club.artist_id,
        "created_by": club.created_by,
        "member_count": member_count
    }


@app.post("/fan-clubs", status_code=201)
def create_club(data: ClubIn, fan=Depends(require_role("fan"))):
    with db.SessionLocal() as session:
        artist = session.get(db.Artists, data.artist_id)

        if not artist:
            raise HTTPException(status_code=404, detail="Artist not found")

        club = db.FanClubs(
            **data.model_dump(),
            created_by=fan["id"]
        )

        session.add(club)
        save_or_conflict(session, "Fan club name already exists")
        session.refresh(club)

        return club_dict(club, 0)


@app.get("/fan-clubs")
def get_clubs():
    with db.SessionLocal() as session:
        clubs = session.query(db.FanClubs).order_by(db.FanClubs.name).all()

        result = []

        for club in clubs:
            count = session.query(db.ClubMembers).filter_by(club_id=club.id).count()
            result.append(club_dict(club, count))

        return result


@app.post("/fan-clubs/{club_id}/join", status_code=201)
def join_club(club_id: int, fan=Depends(require_role("fan"))):
    with db.SessionLocal() as session:
        club = session.get(db.FanClubs, club_id)

        if not club:
            raise HTTPException(status_code=404, detail="Fan club not found")

        member = db.ClubMembers(
            club_id=club_id,
            user_id=fan["id"]
        )

        session.add(member)
        save_or_conflict(session, "You already joined this fan club")

        return {"joined": True, "club_id": club_id}


# E8-E10: Community posts
def post_dict(post, like_count):
    return {
        "id": post.id,
        "author_id": post.author_id,
        "text": post.text,
        "image_url": post.image_url,
        "created_at": post.created_at,
        "like_count": like_count
    }


@app.post("/posts", status_code=201)
def create_post(data: PostIn, fan=Depends(require_role("fan"))):
    with db.SessionLocal() as session:
        post = db.Posts(
            author_id=fan["id"],
            text=data.text,
            image_url=str(data.image_url) if data.image_url else None
        )

        session.add(post)
        session.commit()
        session.refresh(post)

        return post_dict(post, 0)


@app.get("/posts")
def get_posts(skip: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=100)):
    with db.SessionLocal() as session:
        posts = (
            session.query(db.Posts)
            .filter_by(is_hidden=False)
            .order_by(db.Posts.created_at.desc())
            .offset(skip)
            .limit(limit)
            .all()
        )

        result = []

        for post in posts:
            likes = session.query(db.PostLikes).filter_by(post_id=post.id).count()
            result.append(post_dict(post, likes))

        return result


@app.put("/posts/{post_id}/like")
def toggle_like(post_id: int, fan=Depends(require_role("fan"))):
    with db.SessionLocal() as session:
        post = session.get(db.Posts, post_id)

        if not post or post.is_hidden:
            raise HTTPException(status_code=404, detail="Post not found")

        like = session.query(db.PostLikes).filter_by(
            post_id=post_id,
            user_id=fan["id"]
        ).first()

        if like:
            session.delete(like)
            liked = False
        else:
            session.add(db.PostLikes(
                post_id=post_id,
                user_id=fan["id"]
            ))
            liked = True

        save_or_conflict(session, "Like already exists")

        return {"post_id": post_id, "liked": liked}


# E11-E12: Polls
def poll_dict(poll):
    return {
        "id": poll.id,
        "artist_id": poll.artist_id,
        "question": poll.question,
        "options": json.loads(poll.options),
        "opens_at": poll.opens_at,
        "closes_at": poll.closes_at
    }


@app.post("/polls", status_code=201)
def create_poll(data: PollIn, organizer=Depends(require_role("organizer"))):
    with db.SessionLocal() as session:
        artist = session.get(db.Artists, data.artist_id)

        if not artist:
            raise HTTPException(status_code=404, detail="Artist not found")

        poll = db.Polls(
            artist_id=data.artist_id,
            organizer_id=organizer["id"],
            question=data.question,
            options=json.dumps(data.options),
            opens_at=data.opens_at,
            closes_at=data.closes_at
        )

        session.add(poll)
        session.commit()
        session.refresh(poll)

        return poll_dict(poll)


@app.post("/polls/{poll_id}/vote", status_code=201)
def vote(poll_id: int, data: VoteIn, fan=Depends(require_role("fan"))):
    with db.SessionLocal() as session:
        poll = session.get(db.Polls, poll_id)

        if not poll:
            raise HTTPException(status_code=404, detail="Poll not found")

        now = datetime.now(timezone.utc).replace(tzinfo=None)

        if now < poll.opens_at or now >= poll.closes_at:
            raise HTTPException(status_code=400, detail="Poll is not open")

        options = json.loads(poll.options)

        if data.option_index >= len(options):
            raise HTTPException(status_code=422, detail="Invalid option index")

        poll_vote = db.PollVotes(
            poll_id=poll_id,
            user_id=fan["id"],
            option_index=data.option_index
        )

        session.add(poll_vote)
        save_or_conflict(session, "You have already voted in this poll")

        return {
            "poll_id": poll_id,
            "option_index": data.option_index
        }