# Lucky Proxy Vend Finder

Express app with a CRUD API (API key protected), a view-only landing page, and an admin page with login/registration + owner approvals.

## Stack
- Node.js + Express
- JSON file storage at `data/vends.json`
- Vanilla HTML/JS frontend served from `public/`

## Getting Started
1. Install dependencies:
   ```bash
   npm install
   ```
2. Run the server:
   ```bash
   npm start
   ```
3. Open http://localhost:3000 for the view-only list, or http://localhost:3000/admin to manage (login required).

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
    "lastUpdate": "2024-04-01T10:00:00Z"
  }
  ```
- `PUT /api/vends/:id` — update an existing entry; same body fields as POST.
- `DELETE /api/vends/:id` — remove an entry by its `id`.

Responses return JSON with the entry or `{ "error": "message" }` on failure.

## Notes
- Data persists in `data/vends.json`; sample entries are pre-seeded.
- Auth + API key state lives in `data/auth.json` (auto-created). API key is auto-generated (10–15 random chars). Owner can rotate it; any logged-in user can load it and save to localStorage.
- A default owner user is created on first boot and stored only in `data/auth.json` (not shown in the UI). Registrations are stored as pending and must be approved by the owner before they can log in.
- Landing page reads the API key from `localStorage.vendApiKey`; set it from the admin page after login to keep both pages in sync.
- Swap the storage layer in `server.js` if you move to a database later.
