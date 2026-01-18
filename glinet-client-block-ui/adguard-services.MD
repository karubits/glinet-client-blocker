

````markdown
# AI Coder Agent Prompt: GL.iNet AdGuard Home Service Blocking (Firmware-Accurate)

## Role
You are an experienced **Python backend and network automation engineer**.

You are extending an existing system that manages **GL.iNet routers** and **AdGuard Home**, with a focus on **accuracy to real GL.iNet firmware behavior** (verified via browser DevTools).

---

## Architecture Overview

GL.iNet routers expose **two independent services**:

### 1️⃣ GL.iNet Router API
- URL: `https://<router>:443/rpc`
- Auth: JSON-RPC session token
- Certificate: self-signed
- Purpose: client (MAC-based) blocking

### 2️⃣ AdGuard Home (GL.iNet–customized)
- URL: `http(s)://<router>:3000`
- Auth: **cookie-based (`Admin-Token`)**
- UI and API are the same service
- Purpose: **network-wide service blocking**

🚫 Auth, cookies, and sessions are **NOT shared** between these services.

---

## Existing Codebase (Do Not Break)
- A `GLiNetRouter` class already exists
- It handles router login and MAC-based blocking
- A Flask web UI orchestrates routers and operations

You must **add AdGuard Home support without modifying existing router logic**.

---

## Objective

Implement **network-wide service blocking** (e.g. YouTube) using the **actual GL.iNet AdGuard Home API**, matching exactly what the web UI does.

---

## Required Implementation

### 1️⃣ Create a new client class

Create a **new, separate client**:

```python
class AdGuardHomeClient:
    ...
````

Do NOT subclass or modify `GLiNetRouter`.

---

### 2️⃣ Authentication (GL.iNet specific)

* Login endpoint:

  ```http
  POST /control/login
  ```

* Credentials:

  ```json
  {"name": "admin", "password": "<router password>"}
  ```

* Auth result:

  * `Admin-Token` cookie is set
  * Must be stored via `requests.Session`

Rules:

* ❌ No Basic Auth
* ❌ No reuse of router RPC tokens
* ✅ Cookie-based session only

---

### 3️⃣ Read current blocked services (IMPORTANT)

Current service state is retrieved via:

```http
GET /control/tls/status
```

Response example:

```json
{
  "ids": ["youtube", "netflix"],
  "schedule": {
    "time_zone": "Asia/Tokyo"
  }
}
```

This endpoint is **authoritative**.

---

### 4️⃣ Update blocked services (CRITICAL)

Updates must use:

```http
PUT /control/blocked_services/update
```

Payload schema:

```json
{
  "ids": ["youtube", "netflix"],
  "schedule": {
    "time_zone": "Asia/Tokyo"
  }
}
```

Rules:

* This is a **replace-all** operation
* Always:

  1. Fetch current state
  2. Modify `ids`
  3. PUT full payload back
* Preserve `schedule` unless explicitly changed

---

### 5️⃣ Scheduling (future-proofing)

* `schedule` is **mandatory**
* At minimum, preserve:

  ```json
  {"time_zone": "<router time zone>"}
  ```

Do not hardcode time windows unless instructed.

---

### 6️⃣ TLS / Certificates

* Routers use self-signed certificates
* SSL verification must be configurable
* Default:

  ```python
  verify_ssl = False
  ```

Suppress warnings safely.

---

## Flask Integration

Add new API endpoints such as:

```http
POST /api/adguard/service
```

Payload example:

```json
{
  "service": "youtube",
  "enable": true,
  "router": "all"
}
```

Behavior:

* Authenticate to AdGuard per router
* Preserve existing blocked services
* Apply change across selected routers
* Return per-router success/failure results

---

## Explicit Non-Goals

* ❌ Editing AdGuard YAML directly
* ❌ Using undocumented endpoints
* ❌ Sharing auth state between services
* ❌ TLS MITM / HTTPS inspection

---

## Quality Expectations

* Production-grade code
* Clear separation of concerns
* Defensive error handling
* Idempotent operations
* Readable logging
* No breaking changes


---

## Success Criteria

* Matches GL.iNet AdGuard UI behavior exactly
* No 403 errors
* Works on stock GL.iNet firmware
* Supports multiple routers
* Safe to automate

---

## Mindset

Assume:


* Routers may be offline
* APIs may change subtly
* Accuracy matters more than assumptions

Code accordingly.

```

---



In the webapp/data directory, you will see a services.yml file that the UI will reference. 

Below is a **Cursor-ready prompt**, written exactly as you’d give it to an AI coding agent inside Cursor, instructing it to **add a Service Blocking section** that fits your existing UI, architecture, and backend direction.

I’ll assume:

* Frontend is already structured (React / templates / components)
* Backend APIs exist or will exist for AdGuard Home
* You want **status visibility + enable/disable controls**
* Style should match the existing dark, card-based UI

---

````markdown
## Task: Add "Service Block Control" Section to Client Block Control UI

### Context
We already have a working **Client Block Control** dashboard that:
- Lists clients by category
- Supports block/unblock actions
- Uses a dark, card-based UI
- Supports multiple routers (including "All Routers")

We now want to add **network-wide Service Blocking** using AdGuard Home
(e.g. YouTube, Netflix, Twitch), with clear visibility into:
- Which services are currently blocked
- Ability to enable/disable services
- Consistent UI/UX with the existing page

This section is **service-based**, not client-based.

---

## UI Requirements

### 1. New Section Placement
Add a new section **below "All Clients" and category sections**:

**Title:**  
`Service Block Control`

**Description (small, muted text):**  
> Block or allow internet services across the entire network using AdGuard Home.

---

### 2. Section Layout

Use a **card/grid layout**, similar to client cards.

Each service should be displayed as a **Service Card** with:

- Service name (human-friendly)
- Service ID (small, muted, optional)
- Current status indicator
- Toggle button (Block / Unblock)

---

### 3. Service Card Design

Each card should contain:

**Header**
- Service name (e.g. “YouTube”)
- Status badge:
  - 🟥 Blocked
  - 🟩 Allowed

**Body**
- Optional subtitle:
  - “Blocked network-wide”
  - “Allowed network-wide”

**Actions**
- Single toggle button:
  - If blocked → `Unblock`
  - If allowed → `Block`

Button colors must match existing UI:
- Red = Block
- Green = Unblock

---

### 4. Bulk Controls (Top Right)

Add bulk actions at the top of the Service section:

- 🔴 **Block All Services**
- 🟢 **Unblock All Services**

These should behave like the existing “Block All / Unblock All” client buttons.

---

### 5. Router Scope Awareness

The Service section must respect the currently selected router:

- If **All Routers** is selected:
  - Apply actions to all routers
  - Status is “Blocked if blocked on all routers”
  - Show warning icon if router states differ
- If a single router is selected:
  - Show exact state for that router

---

### 6. Status Source of Truth

Service status must come from backend state, not UI assumptions.

Expected backend shape (example):

```json
{
  "schedule": { "time_zone": "Asia/Tokyo" },
  "ids": ["youtube", "netflix", "twitch"]
}
````

Blocked services = those present in `ids`.

---

### 7. API Integration (Frontend)

Assume the following endpoints exist or will exist:

* `GET /api/services/status`
* `POST /api/services/block`
* `POST /api/services/unblock`

Payload example:

```json
{
  "service": "youtube",
  "router": "all"
}
```

Bulk example:

```json
{
  "services": ["youtube", "netflix"],
  "router": "all"
}
```

---

### 8. State Management

* Fetch service status on page load
* Refresh status after every action
* Disable buttons while requests are in-flight
* Show toast notifications on success/failure

---

### 9. Visual Consistency

Match existing UI:

* Same card spacing
* Same shadows
* Same rounded corners
* Same typography scale
* Same button styles

Do NOT introduce a new visual language.

---

### 10. Future-Proofing (Do Not Implement Yet)

Design should allow future expansion for:

* Schedules (time windows)
* Profiles (Kids / Work / Night)
* Per-category service blocking

Structure components accordingly, but do not implement these features now.

---

## Deliverables

* New `ServiceBlockSection` component
* Reusable `ServiceCard` component
* Wiring into existing router selector
* API integration hooks
* No breaking changes to existing client blocking logic

---

## Success Criteria

* User can clearly see which services are blocked
* User can block/unblock services with one click
* Behavior matches AdGuard Home state exactly
* UI feels like a natural extension of the current page

Proceed with implementation.

```

---

If you want next, I can also:
- Design the **exact component tree**
- Propose **service iconography**
- Suggest **UX for partial router mismatch**
- Draft the **backend API contract** in detail

Just say what you want Cursor to do next.
```
