# CHAT APPLICATION


## Quick start
1. Copy `.env.example` to `.env` and fill secrets.
2. Start Docker: `docker-compose up -d`.
3. Install deps: `npm install`.
4. Run dev server: `npm run dev`.


Endpoints:
- POST /auth/signup { username, password }
- POST /auth/login { username, password }
- POST /auth/refresh (cookie-based)
- POST /auth/logout
- GET /profile (protected)


Notes: In production set `secure: true` for cookies and serve over HTTPS.