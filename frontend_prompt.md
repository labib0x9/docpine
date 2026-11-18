# Frontend Prompt: Docpine Console

Build the browser console for Docpine, a GitHub-authenticated lab runner. The console lets a user sign in with GitHub, save a repository, browse seeded labs, start lab runs, and watch live output streamed over Server-Sent Events.

Treat [`openapi.yaml`](openapi.yaml) as the API contract and [`docs/architecture.md`](docs/architecture.md) as the system model.

## Product scope

Build a Next.js application with these routes:

- `/` — dashboard: auth guard, current user, saved repository status, labs, recent runs.
- `/login` — GitHub login page with optional Cloudflare Turnstile widget.
- `/labs` — list available labs.
- `/labs/[id]` — lab detail, repository input, start-run action.
- `/runs` — run history, grouped or filtered by lab.
- `/runs/[runID]` — live run detail with SSE output and final result.
- `/settings` — profile and saved GitHub repository management.

Do not add lab creation/editing screens. Labs are seeded server-side and exposed read-only through `GET /v1/labs`.

Do not use WebSockets. Live output is SSE only.

## Technical requirements

- Next.js App Router with TypeScript.
- `package.json`, `next.config.mjs`, and `public/` must exist because the provided `Dockerfile.frontend` runs `npm ci`, `npm run build`, and `npx next start`.
- Use Tailwind CSS or a small custom CSS system; either is acceptable.
- Use React Context or a lightweight store for auth/session state.
- Use a typed API client built on `fetch` with `credentials: "include"`.
- Support the existing Docker build behavior: `NEXT_PUBLIC_*` variables are inlined at build time.

Environment variables:

```dotenv
NEXT_PUBLIC_API_BASE=http://localhost:8080
NEXT_PUBLIC_SSE_BASE=http://localhost:8080
NEXT_PUBLIC_TURNSTILE_SITE_KEY=
```

If `NEXT_PUBLIC_TURNSTILE_SITE_KEY` is empty, skip Turnstile entirely. Never request or expose `TURNSTILE_SECRET` or `COOKIE_SECRET` in the frontend.

## Auth flow

The backend owns GitHub OAuth and sets an HttpOnly `session` cookie. The frontend never stores tokens in localStorage.

1. On app load, call `GET /v1/me`.
2. If it returns `401`, show the login page or redirect to `/login`.
3. If it returns `200`, store the user in React state and render the console shell.
4. Logout calls `POST /v1/auth/logout` with credentials included, clears local state, then redirects to `/login`.

Login behavior:

- When Turnstile is disabled, render a link to `GET {NEXT_PUBLIC_API_BASE}/v1/auth/login`.
- When Turnstile is enabled, render a native HTML form that POSTs to `{NEXT_PUBLIC_API_BASE}/v1/auth/login` with a hidden `cf-turnstile-response` field. Use a real form navigation so the GitHub redirect works; do not use `fetch` for login navigation.
- After callback, the backend redirects to `/`; the frontend re-fetches `/v1/me`.

Handle global `401` responses by redirecting to `/login`.

## API client

Base URL: `NEXT_PUBLIC_API_BASE`. Always include cookies. Parse JSON errors shaped as `{ "error": string }`.

Implement methods for:

| Method | Path | Use |
| --- | --- | --- |
| `GET` | `/v1/me` | Current user |
| `POST` | `/v1/auth/logout` | Logout |
| `GET` | `/v1/me/repo` | Saved repo |
| `PUT` | `/v1/me/repo` | Save repo |
| `GET` | `/v1/labs` | List labs |
| `POST` | `/v1/labs/{id}/runs` | Create run |
| `GET` | `/v1/labs/{id}/runs` | List runs for one lab |
| `GET` | `/v1/labs/{id}/runs/{runID}` | Run detail |
| `GET` | `/v1/labs/{id}/runs/{runID}/result` | Final output |
| `GET` | `/healthz` | Optional backend status badge |

Create-run requests must send:

```json
{ "github_repo": "owner/repo" }
```

and, when Turnstile is enabled, header:

```text
CF-Turnstile-Response: <token>
```

Map these errors visibly:

- `400` — validation or invalid repository.
- `401` — redirect to login.
- `404` — not found or not owned by the user.
- `428` — Turnstile token missing; re-render widget.
- `500`/`502` — generic error with retry action.

## TypeScript models

Use these shapes:

```ts
type User = {
  id: number;
  github_id: number;
  login: string;
  avatar_url: string;
  created_at: string;
  updated_at: string;
};

type Lab = {
  id: number;
  name: string;
  tests: string[];
  created_at: string;
  updated_at: string;
};

type RunStatus = "queued" | "running" | "passed" | "failed";

type LabRun = {
  id: number;
  user_id: number;
  lab_id: number;
  github_repo: string;
  status: RunStatus;
  created_at: string;
  updated_at: string;
  started_at?: string | null;
  finished_at?: string | null;
};

type LabResult = {
  id: number;
  run_id: number;
  user_id: number;
  github_repo: string;
  lab_id: number;
  results: string;
  created_at: string;
};

type RepoResponse = { github_repo: string };
```

## SSE live output

On `/runs/[runID]`, open:

```ts
new EventSource(
  `${NEXT_PUBLIC_SSE_BASE}/v1/labs/${labId}/runs/${runId}/events`,
  { withCredentials: true },
);
```

Register listeners for:

| Event | Payload | UI action |
| --- | --- | --- |
| `status` | plain text status | Update status badge and timeline |
| `output` | output chunk | Append to terminal view |
| `result` | final output | Append, mark passed, close stream |
| `error` | final output | Append, mark failed, close stream |
| `ping` | keepalive | Ignore or update "connected" indicator |

Implementation details:

- The API replays hub history first, so clear the terminal when mounting and let replay repopulate it.
- Keep output append-only and auto-scroll only when the user is already near the bottom.
- Close `EventSource` on unmount, terminal events, or navigation.
- Add reconnect/backoff UI if the stream errors before a terminal event.
- SSE uses cookies, not custom headers; Turnstile is only required when creating the run.
- Fetch `GET /v1/labs/{id}/runs/{runID}/result` after a terminal event to reconcile final persisted output.

## UI requirements

Create a consistent console shell:

- Left sidebar: Dashboard, Labs, Runs, Settings.
- Top bar: page title, backend health indicator, user avatar/login, logout.
- Dark developer-tool aesthetic with clear status colors:
  - queued: gray
  - running: blue/amber
  - passed: green
  - failed: red
- Responsive layout for narrow screens.
- Loading skeletons, empty states, and error states for every data view.
- Toast notifications for save/start/logout actions.

Dashboard:

- Show welcome message with GitHub login/avatar.
- Show saved repository and a "Change repository" action.
- Show up to 6 labs as cards.
- Show recent runs: fetch labs first, then `GET /v1/labs/{id}/runs` for each lab and sort by `created_at` descending.

Labs list:

- Table or card grid with lab name, number of tests, and "Open lab".
- Include the command list in an expandable detail area.

Lab detail:

- Show lab name and test commands.
- Repository field pre-filled from `GET /v1/me/repo`.
- Validate input client-side but accept the backend's normalized forms: `owner/repo`, `github.com/owner/repo`, HTTPS URLs, and `git@github.com:owner/repo.git`.
- Start-run button calls `POST /v1/labs/{id}/runs`, then navigates to `/runs/[runID]`.
- Disable the button while submitting and show Turnstile errors inline.

Runs list:

- Lab selector filter, because the API lists runs per lab.
- Columns: run id, status, repository, lab, created, finished.
- Clicking a row opens `/runs/[runID]`.

Run detail:

- Header: status badge, lab name, repository, timestamps.
- Terminal panel with monospace output.
- Controls: copy output, download output as `.txt`, refresh result.
- Timeline: queued → running → passed/failed.
- Show a "Live" indicator while streaming and "Completed" after terminal event.
- On `failed`, surface the final `error` payload prominently.

Settings:

- Show profile fields from `/v1/me`.
- Repository form using `GET/PUT /v1/me/repo`.
- Show which vars are public/client-side and warn against pasting secrets.

## Turnstile integration

If `NEXT_PUBLIC_TURNSTILE_SITE_KEY` is set:

- Load the Cloudflare Turnstile script once.
- Render a widget on `/login` and on each lab detail page before starting a run.
- Store only the short-lived token in component state.
- Include the token as:
  - hidden form field `cf-turnstile-response` for login navigation.
  - `CF-Turnstile-Response` header for create-run fetch.
- On `428`, reset the widget and ask the user to retry.

If the key is empty, hide all Turnstile UI and omit the token.

## Suggested structure

```text
app/
  layout.tsx
  page.tsx
  login/page.tsx
  labs/page.tsx
  labs/[id]/page.tsx
  runs/page.tsx
  runs/[runID]/page.tsx
  settings/page.tsx
components/
  ConsoleShell.tsx
  Sidebar.tsx
  TopBar.tsx
  AuthProvider.tsx
  ApiError.tsx
  StatusBadge.tsx
  LabCard.tsx
  RunTable.tsx
  RunTerminal.tsx
  RepoForm.tsx
  TurnstileWidget.tsx
lib/
  api.ts
  types.ts
  sse.ts
  format.ts
  env.ts
```

## Acceptance criteria

- `npm ci && npm run build` succeeds.
- A fresh user can log in, see `/v1/me`, save a repo, open a lab, start a run, watch live SSE output, and read the final result.
- No frontend code imports server packages or tries to read Postgres, RabbitMQ, Docker, or secrets.
- No hardcoded API URL outside `lib/env.ts`.
- All requests use the exact paths in `openapi.yaml`.
- The UI still works when Turnstile is disabled.
- The app never uses WebSockets.
- 401 responses consistently redirect to `/login`.
- SSE is closed cleanly on terminal events and unmount.

## Implementation order

1. Scaffold Next.js + TypeScript + build config and base layout.
2. Add env helpers, typed models, and API client with error handling.
3. Add `AuthProvider` and route guard using `/v1/me`.
4. Build `/login` with Turnstile-aware native form submission.
5. Build console shell, dashboard, settings, labs, lab detail.
6. Build runs list and run detail with `RunTerminal`.
7. Implement SSE event handling, replay clearing, terminal close, and result reconciliation.
8. Add loading, empty, and error states.
9. Run `npm run build` and fix type/build errors.
10. Verify against a local backend started with `docker compose up -d --build`.
