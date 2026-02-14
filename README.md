# 🎯 Roleplay Circles v2

Sales roleplay matching for teams. Create a circle, invite your team, find practice partners instantly — especially when calls no-show.

## Features

- **Google OAuth** — Sign in with Google, calendar integration
- **Circles** — Create invite-only circles for your team
- **Availability Toggle** — One tap to say "I'm free for roleplay"
- **No-Show Detection** — Google Calendar integration flags meetings that started 10+ min ago
- **Session Tracking** — Log sessions, rate them, track streaks
- **Leaderboard** — See who's putting in the reps
- **Mobile-First** — Dark theme UI built for phones between calls

## Quick Start

```bash
# Clone and run
./run.sh

# Or manually:
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open http://localhost:5050

## Google OAuth Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a project → APIs & Services → Credentials
3. Create OAuth 2.0 Client ID (Web application)
4. Set authorized redirect URI: `http://localhost:5050/auth/callback`
5. Enable Google Calendar API
6. Copy `.env.example` to `.env` and fill in credentials:

```bash
cp .env.example .env
# Edit .env with your client ID and secret
```

**Without OAuth configured**, the app runs in dev mode with a simple name/email login (no Google features).

## Tech Stack

- **Backend:** Flask + SQLite
- **Auth:** Google OAuth 2.0 (google-auth-oauthlib)
- **Calendar:** Google Calendar API
- **Frontend:** Vanilla HTML/CSS/JS (no framework)
- **Database:** SQLite (data/roleplay_circles.db)

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Landing page |
| GET | `/login` | Login page |
| GET | `/auth/google` | Start OAuth flow |
| GET | `/auth/callback` | OAuth callback |
| POST | `/auth/logout` | Logout |
| GET | `/dashboard` | User dashboard |
| POST | `/circles/create` | Create circle |
| GET | `/join/<code>` | Join page |
| POST | `/join/<code>/submit` | Join circle |
| GET | `/c/<code>` | Circle view |
| GET | `/settings` | Settings page |
| GET | `/api/circle/<code>/status` | Team status |
| POST | `/api/circle/<code>/available` | Toggle availability |
| POST | `/api/circle/<code>/noshow` | Mark no-show |
| POST | `/api/circle/<code>/log-session` | Log session |
| GET | `/api/circle/<code>/stats` | Stats + leaderboard |
| GET | `/api/circle/<code>/calendar` | Today's calendar |
| GET | `/api/circle/<code>/recent-sessions` | Recent sessions |
| POST | `/api/settings` | Update settings |

## Database Schema

SQLite with tables: `users`, `circles`, `circle_members`, `availability`, `sessions`, `noshow_events`
