# K-Pop-Universe-Team-09


# K-Pop Universe – Fan Community Platform

## Problem Statement

 A backend API for a K-Pop fan community. Fans can create and join fan clubs, publish and like posts, vote in polls, and register for events. Organizers manage artists, polls, and events. Administrators create organizer accounts and moderate users and posts.

The backend uses Python, FastAPI, Pydantic, SQLite, JWT access and refresh tokens, password hashing, and role-based access control. New registrations receive the `fan` role. Only admins can create organizer accounts.

## API Contracts

Protected endpoints require `Authorization: Bearer <access_token>`. JSON request bodies are validated by Pydantic. Responses are JSON. Authentication errors return `401`, insufficient role returns `403`, missing resources return `404`, duplicate actions return `409`, and invalid input returns `422`.

### Authentication

| Method | Endpoint | Request | Response |
|---|---|---|---|
| POST | `/auth/register` | `{ "username": "fan1", "email": "fan@example.com", "password": "password123" }` | Account ID, username, email, and `fan` role (`201`) |
| POST | `/auth/login` | `{ "username": "fan1", "password": "password123" }` | Access token, refresh token, and token type |
| POST | `/auth/refresh` | `{ "refresh_token": "<refresh-token>" }` | New access token and token type |

### Project APIs

| ID | Method | Endpoint | Access | Request and response contract |
|---|---|---|---|---|
| E1 | POST | `/organizers` | Admin | Body: registration fields `username`, `email`, `password`. Creates an organizer account; returns account ID, username, email, and role (`201`). |
| E2 | POST | `/artists` | Organizer | Body: `{ "name": "...", "description": "...", "category": "solo or group" }`. Returns the created artist (`201`). |
| E3 | GET | `/artists` | Public | Returns an array of artists. |
| E4 | GET | `/artists/{artist_id}` | Public | Returns the artist or `404`. |
| E5 | POST | `/fan-clubs` | Fan | Body: `{ "name": "...", "description": "...", "artist_id": 1 }`. Returns the created club (`201`). |
| E6 | GET | `/fan-clubs` | Public | Returns available clubs with member counts. |
| E7 | POST | `/fan-clubs/{club_id}/join` | Fan | No body. Adds the current fan and returns `{ "joined": true, "club_id": 1 }` (`201`); duplicate membership returns `409`. |
| E8 | POST | `/posts` | Fan | Body: `{ "text": "...", "image_url": "https://example.com/image.jpg" }`; `image_url` is optional. Returns the created post (`201`). |
| E9 | GET | `/posts?skip=0&limit=50` | Public | Returns the community feed with post and like-count data. `limit` is capped at 100. |
| E10 | PUT | `/posts/{post_id}/like` | Fan | No body. Toggles the current fan's like; returns `{ "post_id": 1, "liked": true }`. |
| E11 | POST | `/polls` | Organizer | Body: `{ "artist_id": 1, "question": "...", "options": ["A", "B"], "opens_at": "2026-12-01T10:00:00Z", "closes_at": "2026-12-08T10:00:00Z" }`. Returns the created poll (`201`). Must have at least two unique options and closing time after opening time. |
| E12 | POST | `/polls/{poll_id}/vote` | Fan | Body: `{ "option_index": 0 }`. Returns poll ID and chosen option index (`201`); each fan may vote once while the poll is open. |
| E13 | GET | `/polls/{poll_id}/results` | Public | Returns poll question, dates, total votes, and vote counts for each option. |
| E14 | POST | `/events` | Organizer | Body: `{ "title": "...", "description": "...", "starts_at": "2026-12-20T10:00:00Z", "venue": "...", "participant_limit": 100 }`. Returns the created event (`201`). |
| E15 | POST | `/events/{event_id}/register` | Fan | No body. Registers the current fan and returns `{ "event_id": 1, "registered": true }` (`201`); duplicate registration or a full event returns `409`. |



## Database Tables Created

- `users`
- `artists`
- `fan_clubs`
- `club_members`
- `posts`
- `post_likes`
- `polls`
- `poll_votes`
- `fan_events`
- `event_registrations`

## Main Python Files

functions.py
main.py
