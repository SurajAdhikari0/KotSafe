# Chapter 6: In-App HTTP Repeater & Security Analysis

[⬅️ Chapter 5: TLS Decryption & Inspection](05_TLS_DECRYPTION_AND_INSPECTION.md) | [🏠 Table of Contents](README.md) | [➡️ Chapter 7: App Permissions & Privacy Audit](07_APP_PERMISSIONS_AND_PRIVACY.md)

---

Historically, security researchers, mobile penetration testers, and API developers had to tether their Android devices to desktop interception proxies like Burp Suite or OWASP ZAP to inspect and tamper with HTTP requests. 

KotSafe eliminates this cumbersome tethering by incorporating **HTTP Repeater** (`HttpRepeaterActivity.java`) — an on-device API tampering and replay workbench directly inside the application.

---

## 1. What is the KotSafe HTTP Repeater?

The HTTP Repeater allows you to capture any HTTP or HTTPS request initiated by any application on your device, modify its headers, URL query parameters, or payload body, and resend it to the target server in real time.

```
┌──────────────────────────────────────────────────────────────┐
│  HTTP Repeater                                       [SEND]  │
├──────────────────────────────────────────────────────────────┤
│  METHOD: [ POST ▼ ]                                          │
│  URL: https://api.targetservice.com/v2/user/profile          │
├──────────────────────────────────────────────────────────────┤
│  Headers:                                                    │
│  Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpX...   │
│  Content-Type: application/json                              │
│  User-Agent: KotSafe-Security-Audit/2.0                      │
├──────────────────────────────────────────────────────────────┤
│  Request Body:                               [Format JSON]   │
│  {                                                           │
│    "user_id": "10482",                                       │
│    "role": "admin"                                           │
│  }                                                           │
├──────────────────────────────────────────────────────────────┤
│  Response: [ 200 OK ]  •  148 ms  •  1.4 KB                  │
│  {                                                           │
│    "status": "success",                                      │
│    "message": "Profile updated"                              │
│  }                                                           │
└──────────────────────────────────────────────────────────────┘
```

---

## 2. Launching and Using the Repeater

There are two primary ways to initiate a repeater session:

### Method A: Direct from Live Captured Traffic (Recommended)
1. Navigate to the **Connections** tab or **HTTP Details** screen.
2. Select any captured HTTP or decrypted HTTPS transaction.
3. In the top action bar, tap the **Send to Repeater** icon (or tap the three-dots menu $\rightarrow$ **Replay in Repeater**).
4. KotSafe automatically populates the HTTP Method, URL, all captured Request Headers (including cookies and bearer tokens), and the exact payload body.

### Method B: Manual Request Crafting
1. Open the KotSafe navigation drawer $\rightarrow$ Tap **Tools & Diagnostics** $\rightarrow$ **HTTP Repeater**.
2. Select your desired HTTP verb from the **Method** dropdown:
   * `GET`, `POST`, `PUT`, `DELETE`, `PATCH`, `HEAD`, `OPTIONS`
3. Enter the target destination URL.
4. Add your custom request headers (one per line, format: `Header-Name: value`).
5. Type or paste your payload into the **Request Body** area.

---

## 3. Features & Controls

### JSON Formatter & Beautifier
When inspecting or editing compressed or minified JSON payloads:
* Tap **Format JSON** above the request or response pane.
* KotSafe automatically pretty-prints the JSON structure with 2-space indentation, making nested structures and arrays instantly readable.

### Status Code Telemetry & Latency Indicator
When you tap **Send Request**:
* KotSafe executes the network transaction asynchronously in the background via a worker thread pool.
* The response status code is rendered with standard security color-coding:
  * 🟢 **2xx Success** (e.g., `200 OK`, `201 Created`): Normal server execution.
  * 🔵 **3xx Redirection** (e.g., `301 Moved`, `302 Found`): Displays the redirected `Location` header.
  * 🟠 **4xx Client Error** (e.g., `400 Bad Request`, `401 Unauthorized`, `403 Forbidden`): Authentication or authorization failure.
  * 🔴 **5xx Server Error** (e.g., `500 Internal Server Error`, `502 Bad Gateway`): Potential unhandled exception or backend crash.
* **Latency Counter**: Displays round-trip execution duration in milliseconds (e.g., `124 ms`).
* **Payload Size**: Displays byte and kilobyte counts for transferred headers and response body.

---

## 4. Mobile Penetration Testing Workflows

The built-in Repeater allows security engineers to execute critical security assessments directly on mobile hardware:

### Workflow 1: Broken Object Level Authorization (BOLA / IDOR)
1. Intercept a user profile update request in an app:
   ```json
   {
     "account_id": "84120",
     "email": "user@example.com"
   }
   ```
2. Send the request to **HTTP Repeater**.
3. Modify the `account_id` to an adjacent ID (`84121`).
4. Tap **Send Request**.
5. If the server responds with `200 OK` and exposes or modifies data belonging to another user, an IDOR vulnerability is confirmed.

### Workflow 2: Authentication Token Invalidation Testing
1. Copy an active OAuth/JWT `Authorization: Bearer <token>` header into Repeater.
2. In the target app, log out of the account.
3. Resend the original request from KotSafe Repeater.
4. A secure server must respond with `401 Unauthorized`. If it still responds with `200 OK`, the server fails to invalidate tokens upon logout.

### Workflow 3: Privilege Escalation Probing
1. Capture a standard user registration or profile edit request.
2. Inject administrative parameters into the JSON body:
   ```json
   {
     "role": "administrator",
     "is_admin": true,
     "membership_level": 99
   }
   ```
3. Send the request and analyze the response body to determine if mass assignment vulnerabilities exist.

---

[⬅️ Chapter 5: TLS Decryption & Inspection](05_TLS_DECRYPTION_AND_INSPECTION.md) | [🏠 Table of Contents](README.md) | [➡️ Chapter 7: App Permissions & Privacy Audit](07_APP_PERMISSIONS_AND_PRIVACY.md)
