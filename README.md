# Lucky Proxy Vend Finder

Express app with a CRUD API (API key protected), a view-only landing page, and an admin page with login/registration + owner approvals.

## Stack
- Node.js + Express
- JSON file storage at `data/vends.json`
- Vanilla HTML/JS frontend served from `public/`

## Getting Started
1. Install dependencies:
  ```powershell
  npm install
  ```
2. Run the server (defaults to `http://localhost:3000`):
  ```powershell
  npm start
  ```
3. Open the app in your browser:
  - Public listing: `http://localhost:3000`
  - Admin panel: `http://localhost:3000/admin` (login required)

Tip: The server binds to `127.0.0.1` by default so it's only reachable from your machine. If you need to expose it on the network, run with a different host/port (see notes).

## API
All routes require header `x-api-key: <your key>`.
- `GET /api/vends` — list all entries.
- `POST /api/vends` — create a new entry. Body fields:
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
- `PUT /api/vends/:id` — update an existing entry; same body fields as POST.
  
Validation: `x` and `y` are optional numeric fields (integers or floats). If provided they must parse as numbers; if omitted they will be stored as `null` in the saved object.
- `DELETE /api/vends/:id` — remove an entry by its `id`.

Responses return JSON with the entry or `{ "error": "message" }` on failure.

## Notes
- Data persists in `data/vends.json`; sample entries are pre-seeded.
- Auth + API key state lives in `data/auth.json` (auto-created). API key is auto-generated (10–15 random chars). Owner can rotate it; any logged-in user can load it and save to localStorage.
- A default owner user is created on first boot and stored only in `data/auth.json` (not shown in the UI). Registrations are stored as pending and must be approved by the owner before they can log in.
- Landing page reads the API key from `localStorage.vendApiKey`; set it from the admin page after login to keep both pages in sync.
 - Landing page reads the API key from `localStorage.vendApiKey`; set it from the admin page after login (use the **Save to Browser** button in `/admin`) so the public page can load data without showing the key.
- Swap the storage layer in `server.js` if you move to a database later.

Notes on network exposure
- By default the server listens on `127.0.0.1:3000`. To listen on all interfaces (e.g. `0.0.0.0`) set the `PORT` env var and run node directly:
  ```powershell
  $env:PORT=1337; node server.js
  ```
