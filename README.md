# Media Microservice (Node.js + Express + MinIO + PostgreSQL)

Production-ready media service for upload, private storage, metadata persistence, and secure retrieval.

## Features

- Upload support for image/audio/video/docs via `multipart/form-data`
- Private object storage in MinIO with folder partitioning:
  - `images/`
  - `audio/`
  - `video/`
  - `docs/`
- UUID + timestamp object naming strategy
- Metadata storage in PostgreSQL (`media_files` table)
- JWT auth from `Authorization: Bearer <token>` **or** `accessToken` cookie
- Authorization rule: user must be in the file's `chatId`
- Secure retrieval using server-side generated short-lived MinIO pre-signed URLs
- Batch access endpoint for multiple file IDs
- Upload endpoint rate limiting
- Structured logging + centralized error middleware

## API Endpoints

- `GET /health` - service health check
- `POST /upload` - upload media
- `GET /file/:id` - authorized file access (HTTP 302 redirect)
- `POST /files/batch` - authorized batch URL resolution

## Project Structure

```txt
src/
  config/
    minio.ts
  logger/
    logger.ts
  media/
    controllers/
    middleware/
    repositories/
    routes/
    services/
    utils/
```

## Environment Variables

Copy `.env.example` to `.env` and fill values.

Required media-specific variables:

```env
MINIO_ENDPOINT=localhost
MINIO_PORT=9000
MINIO_USE_SSL=false
MINIO_ACCESS_KEY=minioadmin
MINIO_SECRET_KEY=minioadmin
MINIO_BUCKET_NAME=chat-media
MINIO_PRESIGNED_EXPIRY_SECONDS=60
MEDIA_MAX_UPLOAD_BYTES=26214400
UPLOAD_RATE_LIMIT_PER_MINUTE=20
```

## MinIO Setup (Local)

### Option 1: Docker (recommended)

```bash
docker run -d --name minio \
  -p 9000:9000 -p 9001:9001 \
  -e MINIO_ROOT_USER=minioadmin \
  -e MINIO_ROOT_PASSWORD=minioadmin \
  quay.io/minio/minio server /data --console-address ":9001"
```

- MinIO API: `http://localhost:9000`
- MinIO Console: `http://localhost:9001`

> Bucket creation is auto-handled at app startup (`chat-media` by default) and is kept private.

## Run

```bash
npm install
npx prisma migrate deploy
npx prisma generate
npm run dev
```

## Metadata Schema

`media_files` table stores:

- `id`
- `file_name`
- `object_key`
- `file_type`
- `mime_type`
- `size`
- `chat_id`
- `sender_id`
- `created_at`

Indexes:

- `idx_media_files_chat_id`
- `idx_media_files_file_name`

## Request Examples (curl)

### 1) Health

```bash
curl -X GET http://localhost:3000/health
```

### 2) Upload

```bash
curl -X POST http://localhost:3000/upload \
  -H "Authorization: Bearer <JWT_ACCESS_TOKEN>" \
  -F "chatId=<chat-uuid>" \
  -F "file=@/absolute/path/to/photo.jpg"
```

Sample response:

```json
{
  "success": true,
  "message": "File uploaded",
  "data": {
    "fileId": "23a3c6f0-....",
    "proxyUrl": "/file/23a3c6f0-...."
  }
}
```

### 3) Secure Access

```bash
curl -i -X GET \
  -H "Authorization: Bearer <JWT_ACCESS_TOKEN>" \
  http://localhost:3000/file/<file-id>
```

Returns `302 Found` with a short-lived signed MinIO URL in `Location`.

### 4) Batch Access

```bash
curl -X POST http://localhost:3000/files/batch \
  -H "Authorization: Bearer <JWT_ACCESS_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"fileIds": ["<file-id-1>", "<file-id-2>"]}'
```

## Security Notes

- MinIO bucket access is private.
- Only the API mints short-lived signed object URLs.
- Client-facing URLs should always use `/file/:id` proxy path.
- Access control enforces chat membership via `ConversationParticipant` lookup.

## Production Notes

- Put service behind TLS/HTTPS + reverse proxy.
- Tune `MEDIA_MAX_UPLOAD_BYTES` and rate limits per traffic profile.
- Add virus scanning/content moderation pipeline as needed.
- Consider async thumbnail/transcoding jobs for heavy media workloads.
