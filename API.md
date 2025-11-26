# Lucky Proxy Vend Finder API

Base URL: `http://localhost:3000`

All CRUD routes require the header `x-api-key: <your_key>`. Obtain the key via the admin portal or `/owner/api-key` after logging in.

## Auth & Sessions
- Cookies: Login sets `auth_token` (HTTP-only, 30-day expiry by default). Subsequent owner/user routes use this cookie.
- Passwords are stored hashed (PBKDF2), tokens are stored hashed (SHA-256) with expiry.

### POST /auth/login
Authenticate and create a session.
```json
{ "username": "admin", "password": "secret" }
```
Response: `200 OK`
```json
{ "username": "admin", "role": "owner", "expiresAt": 1730000000000 }
```
Notes: Cookie is set automatically; include credentials in Thunder Client/HTTP client to store it.

### POST /auth/logout
Clears the session cookie.
Response: `200 OK` `{ "ok": true }`

### GET /auth/me
Returns current session user (requires `auth_token` cookie).
Response: `200 OK`
```json
{ "username": "admin", "role": "owner" }
```

### POST /auth/register
Submit a registration (owner must approve).
```json
{ "username": "newuser", "password": "secret" }
```
Response: `201 Created`
```json
{ "message": "Registration submitted, waiting for owner approval" }
```

## Owner Routes (require owner login cookie)

### GET /owner/pending
List pending registrations.
Response: `200 OK`
```json
[ { "username": "newuser" } ]
```

### POST /owner/pending/:username/approve
Approve a pending user.
Response: `200 OK`
```json
{ "username": "newuser", "role": "user" }
```

### GET /owner/api-key
Return current API key (any logged-in user).
Response: `200 OK`
```json
{ "apiKey": "AbCd1234..." }
```

### POST /owner/api-key/rotate
Rotate and return a new API key (owner only).
Response: `200 OK`
```json
{ "apiKey": "NewKey..." }
```

## Vends CRUD (require `x-api-key`)
Field requirements:
- `worldName` (string)
- `itemName` (string)
- `id` (string, unique)
- `perEach` (boolean)
- `price` (integer, non-negative)
- `lastUpdate` (ISO datetime string)
 - `x` (optional, number) — X coordinate for the vend position (stored as number or `null`)
 - `y` (optional, number) — Y coordinate for the vend position (stored as number or `null`)

### GET /api/vends
List all entries.
Response: `200 OK`
```json
[ { "worldName": "Gaia", "itemName": "Lucky Blade", "id": "LB-1001", "perEach": true, "price": 125000, "lastUpdate": "2024-04-01T10:00:00Z", "x": 100, "y": 200 } ]
```

### POST /api/vends
Create a new entry.
Request body example:
```json
{
  "worldName": "Gaia",
  "itemName": "Lucky Blade",
  "id": "LB-1001",
  "perEach": true,
  "price": 125000,
  "lastUpdate": "2024-04-01T10:00:00Z",
  "x": 100,
  "y": 200
}
```
Responses:
- `201 Created` with created entry.
- `400 Bad Request` if fields missing/invalid (price must be integer >= 0).
- `409 Conflict` if `id` already exists.

### PUT /api/vends/:id
Update an existing entry (same fields as POST).
Responses:
- `200 OK` with updated entry.
- `400 Bad Request` for invalid fields.
- `404 Not Found` if id missing.

Notes:
- `x` and `y` are optional. If present they must be numeric; empty or missing values are stored as `null`.
- The public listing (`/`) reads the API key from `localStorage.vendApiKey`. Use the admin page `/admin` and click **Save to Browser** to store the key in your browser for the public page to load data.

### DELETE /api/vends/:id
Delete by id.
Responses:
- `200 OK` with removed entry.
- `404 Not Found` if id missing.

## Error Format
All errors return JSON:
```json
{ "error": "message" }
```
