# Service Token Pre-Authenticated Login - Docker Deployment & Testing Guide

This guide covers how to configure and test the service token pre-authenticated login feature in Docker.

## Table of Contents
- [Quick Reference Commands](#quick-reference-commands)
- [Configuration](#configuration)
- [How It Works](#how-it-works)
- [Step-by-Step Deployment](#step-by-step-deployment)
- [Generating Service Tokens](#generating-service-tokens)
- [Testing](#testing)
- [Integration with Multi-Tenant Mode](#integration-with-multi-tenant-mode)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)

---

## Quick Reference Commands

```bash
# In-place upgrade (preserves data, no new migrations needed)
docker compose -f deploy/docker-compose/quickstart.yaml -p "hanko-quickstart" down
docker compose -f deploy/docker-compose/quickstart.yaml -p "hanko-quickstart" up --build

# Fresh start (clears database)
docker compose -f deploy/docker-compose/quickstart.yaml -p "hanko-quickstart" down -v
docker compose -f deploy/docker-compose/quickstart.yaml -p "hanko-quickstart" up --build

# Restart Hanko only (config changes, no code changes)
docker compose -f deploy/docker-compose/quickstart.yaml -p "hanko-quickstart" restart hanko

# View logs
docker compose -f deploy/docker-compose/quickstart.yaml -p "hanko-quickstart" logs -f hanko
```

---

## Configuration

### Config Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `service_token.secret` | string | `""` (empty) | Shared HMAC secret for JWT validation. Min 32 chars recommended. If empty, the feature is disabled. |
| `service_token.issuer` | string | `""` (empty) | Expected JWT `iss` claim. If set, tokens must include a matching issuer. If empty, issuer validation is skipped. |

### Hanko Configuration (`config.yaml`)

Add to `deploy/docker-compose/config.yaml`:

```yaml
service_token:
  secret: "k8sP2xQ7mN4vR9wF3jL6hT1yB5cA0eD"   # Shared HMAC secret with clinic-os-backend
  issuer: "clinic-os-backend"                     # Expected JWT issuer (validated if set)
```

### Shared Secret

Both **Hanko** and the **calling backend** must use the exact same secret string. Generate a strong random string (minimum 32 characters):

```bash
openssl rand -base64 32
```

Example shared secret: `k8sP2xQ7mN4vR9wF3jL6hT1yB5cA0eD`

#### Hanko side (`config.yaml`)

```yaml
service_token:
  secret: "k8sP2xQ7mN4vR9wF3jL6hT1yB5cA0eD"
  issuer: "clinic-os-backend"
```

#### Backend side (`.env` or config)

```env
HANKO_SERVICE_TOKEN_SECRET=k8sP2xQ7mN4vR9wF3jL6hT1yB5cA0eD
HANKO_SERVICE_TOKEN_ISSUER=clinic-os-backend
```

> **Important:** If the secrets don't match, JWT validation will fail with a signature error.

> **Note:** If `service_token.secret` is empty or not configured, the `preauthenticated_continue` action is automatically suspended (hidden from the login flow). The normal login flow works unchanged.

---

## How It Works

### Flow Diagram

```
Calling Backend                       Hanko Auth Service
       |                                      |
       |  1. Generate JWT (signed with         |
       |     shared HMAC secret)               |
       |                                      |
       |  2. Return JWT to frontend            |
       |     (or call Hanko API directly)      |
       |                                      |
       |               ---- service_token --> |
       |                                      |  3. Validate JWT signature (HMAC-256)
       |                                      |  4. Extract user_id from "sub" claim
       |                                      |  5. Verify issuer if configured
       |                                      |  6. Load user from database
       |                                      |  7. Populate session stash
       |                                      |  8. Continue flow (skip password/OTP)
       |               <-- session cookie --- |
       |                                      |
```

### Step-by-Step

1. **Backend generates a JWT** signed with HMAC-256 using the shared secret.
2. The JWT is sent to Hanko's login flow via the `preauthenticated_continue` action.
3. Hanko validates:
   - JWT signature (HMAC SHA-256)
   - `sub` claim contains a valid user UUID
   - `iss` claim matches configured issuer (if `service_token.issuer` is set)
   - Standard JWT expiry (`exp`)
4. Hanko loads the user from the database and populates the session stash.
5. The flow continues, **bypassing password, passkey, and OTP verification**.
6. If MFA is required and the user hasn't set it up yet, the flow advances to MFA setup.
7. A session cookie is issued as usual.

### JWT Payload Structure

```json
{
  "sub": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "tenant_id": "clinic-123",
  "iss": "clinic-os-backend",
  "exp": 1700000000,
  "iat": 1699999700
}
```

| Claim | Required | Description |
|-------|----------|-------------|
| `sub` | Yes | Hanko user UUID - the user to authenticate |
| `tenant_id` | No | Tenant context (for multi-tenant mode) |
| `iss` | Conditional | Must match `service_token.issuer` if configured |
| `exp` | Yes | Token expiry - should be short-lived (30-60 seconds) |
| `iat` | Recommended | Token issued-at timestamp |

---

## Step-by-Step Deployment

Service token configuration requires **no database migrations** - it is purely a config change. However, you need to rebuild the Docker image if you're updating from a version that didn't include the `preauthenticated_continue` action code.

### Step 1: Update Configuration

Edit `deploy/docker-compose/config.yaml` and add the `service_token` section:

```yaml
service_token:
  secret: "k8sP2xQ7mN4vR9wF3jL6hT1yB5cA0eD"
  issuer: "clinic-os-backend"
```

### Step 2: Rebuild and Run

```bash
# Stop, rebuild, and start
docker compose -f deploy/docker-compose/quickstart.yaml -p "hanko-quickstart" down
docker compose -f deploy/docker-compose/quickstart.yaml -p "hanko-quickstart" up --build
```

### Step 3: Verify

Check the logs to ensure Hanko started without errors:

```bash
docker compose -f deploy/docker-compose/quickstart.yaml -p "hanko-quickstart" logs -f hanko
```

---

## Generating Service Tokens

### Go Example

```go
package main

import (
    "fmt"
    "os"
    "time"

    "github.com/golang-jwt/jwt/v5"
)

func main() {
    secret := os.Getenv("HANKO_SERVICE_TOKEN_SECRET")   // "k8sP2xQ7mN4vR9wF3jL6hT1yB5cA0eD"
    issuer := os.Getenv("HANKO_SERVICE_TOKEN_ISSUER")   // "clinic-os-backend"

    claims := jwt.MapClaims{
        "sub":       "a1b2c3d4-e5f6-7890-abcd-ef1234567890", // Hanko user UUID
        "tenant_id": "clinic-123",                            // Optional
        "iss":       issuer,
        "exp":       time.Now().Add(30 * time.Second).Unix(),
        "iat":       time.Now().Unix(),
    }
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    tokenString, err := token.SignedString([]byte(secret))
    if err != nil {
        panic(err)
    }
    fmt.Println(tokenString)
}
```

### Node.js Example

```bash
# Requires: npm install jsonwebtoken
node -e "
const jwt = require('jsonwebtoken');
const token = jwt.sign(
  { sub: 'USER_UUID_HERE', tenant_id: 'test-tenant', iss: 'clinic-os-backend' },
  'k8sP2xQ7mN4vR9wF3jL6hT1yB5cA0eD',
  { expiresIn: '60s' }
);
console.log(token);
"
```

### Python Example

```python
# Requires: pip install PyJWT
import jwt, time

token = jwt.encode(
    {
        "sub": "USER_UUID_HERE",
        "tenant_id": "test-tenant",
        "iss": "clinic-os-backend",
        "exp": int(time.time()) + 60,
        "iat": int(time.time()),
    },
    "k8sP2xQ7mN4vR9wF3jL6hT1yB5cA0eD",
    algorithm="HS256",
)
print(token)
```

---

## Testing

### Prerequisites

- Hanko running on `http://localhost:8000` (public API)
- `service_token.secret` configured in `config.yaml`
- A test user registered in Hanko (note their UUID)

### Test 1: Normal Login Still Works (Backward Compatibility)

```bash
# Initialize login flow without service token
curl -s -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -d '{}'
```

This should return the normal login flow with email/password actions. The `preauthenticated_continue` action should also be listed (with `service_token` as a hidden input).

### Test 2: Pre-Authenticated Login With Valid Token

```bash
# 1. Generate a service token (replace USER_UUID with actual user ID)
TOKEN=$(node -e "
const jwt = require('jsonwebtoken');
const token = jwt.sign(
  { sub: 'USER_UUID', iss: 'clinic-os-backend' },
  'k8sP2xQ7mN4vR9wF3jL6hT1yB5cA0eD',
  { expiresIn: '60s' }
);
process.stdout.write(token);
")

# 2. Initialize login flow and call preauthenticated_continue
curl -s -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -c cookies.txt \
  -d '{}'

# 3. Continue with service token
curl -s -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -b cookies.txt -c cookies.txt \
  -d "{
    \"action\": \"preauthenticated_continue\",
    \"input\": { \"service_token\": \"$TOKEN\" }
  }"
```

On success, the response should advance the flow (to MFA if required, or to session creation).

### Test 3: Invalid Token Returns Error

```bash
curl -s -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -b cookies.txt -c cookies.txt \
  -d '{
    "action": "preauthenticated_continue",
    "input": { "service_token": "invalid.jwt.token" }
  }'
```

Should return a `form_data_invalid` error.

### Test 4: Expired Token Returns Error

```bash
# Generate an already-expired token
TOKEN=$(node -e "
const jwt = require('jsonwebtoken');
const token = jwt.sign(
  { sub: 'USER_UUID', iss: 'clinic-os-backend' },
  'k8sP2xQ7mN4vR9wF3jL6hT1yB5cA0eD',
  { expiresIn: '0s' }
);
process.stdout.write(token);
")

# Wait 1 second then try
sleep 1
curl -s -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -b cookies.txt -c cookies.txt \
  -d "{
    \"action\": \"preauthenticated_continue\",
    \"input\": { \"service_token\": \"$TOKEN\" }
  }"
```

Should return a `form_data_invalid` error (token expired).

### Test 5: Issuer Mismatch Returns Error

```bash
# Generate a token with wrong issuer
TOKEN=$(node -e "
const jwt = require('jsonwebtoken');
const token = jwt.sign(
  { sub: 'USER_UUID', iss: 'wrong-issuer' },
  'k8sP2xQ7mN4vR9wF3jL6hT1yB5cA0eD',
  { expiresIn: '60s' }
);
process.stdout.write(token);
")

curl -s -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -b cookies.txt -c cookies.txt \
  -d "{
    \"action\": \"preauthenticated_continue\",
    \"input\": { \"service_token\": \"$TOKEN\" }
  }"
```

Should return a `form_data_invalid` error (issuer mismatch).

### Test 6: Verify Session Cookie Is Set

After a successful pre-authenticated login (Test 2), check that the session cookie was set:

```bash
cat cookies.txt | grep clinicos-2fa
```

Should show the `clinicos-2fa` session cookie.

---

## Integration with Multi-Tenant Mode

Service token pre-authentication works with multi-tenant mode. When both features are enabled:

1. The JWT can include a `tenant_id` claim.
2. The `X-Tenant-ID` header should be sent with the login request.
3. The user is looked up within the specified tenant scope.

### Example: Pre-Auth With Tenant

```bash
TOKEN=$(node -e "
const jwt = require('jsonwebtoken');
const token = jwt.sign(
  { sub: 'USER_UUID', tenant_id: 'TENANT_UUID', iss: 'clinic-os-backend' },
  'k8sP2xQ7mN4vR9wF3jL6hT1yB5cA0eD',
  { expiresIn: '60s' }
);
process.stdout.write(token);
")

curl -s -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: TENANT_UUID" \
  -b cookies.txt -c cookies.txt \
  -d "{
    \"action\": \"preauthenticated_continue\",
    \"input\": { \"service_token\": \"$TOKEN\" }
  }"
```

---

## Security Considerations

| Concern | Recommendation |
|---------|----------------|
| Secret strength | Use at least 32 random characters. Generate with `openssl rand -base64 32`. |
| Token lifetime | Keep JWTs short-lived (30-60 seconds). They are single-use for establishing a session. |
| Secret storage | Store the secret in environment variables or a secrets manager. Never commit it to git. |
| Secret rotation | Rotate the secret periodically. Update both Hanko and the backend simultaneously. |
| Issuer validation | Always set `service_token.issuer` in production to prevent cross-service token reuse. |
| Access control | Anyone with the shared secret can authenticate as any user. Limit access to the secret. |

---

## Troubleshooting

### "preauthenticated_continue" Action Not Visible

If the action doesn't appear in the login flow response:

- Verify `service_token.secret` is set and not empty in `config.yaml`
- Restart Hanko after config changes:
  ```bash
  docker compose -f deploy/docker-compose/quickstart.yaml -p "hanko-quickstart" restart hanko
  ```

### "form_data_invalid" Error

Check the Hanko logs for the specific error:

```bash
docker compose -f deploy/docker-compose/quickstart.yaml -p "hanko-quickstart" logs -f hanko
```

Common causes:
- **Signature mismatch** - The secret in `config.yaml` doesn't match the one used to sign the JWT
- **Token expired** - The JWT `exp` claim has passed
- **Issuer mismatch** - The JWT `iss` claim doesn't match `service_token.issuer`
- **User not found** - The `sub` claim contains a UUID that doesn't exist in Hanko's database
- **Invalid UUID** - The `sub` claim is not a valid UUID format

### "service token secret not configured" in Logs

The `service_token.secret` is empty. Add it to `config.yaml` and restart.

### Build Errors

```bash
# Clean rebuild
docker compose -f deploy/docker-compose/quickstart.yaml -p "hanko-quickstart" build --no-cache hanko
docker compose -f deploy/docker-compose/quickstart.yaml -p "hanko-quickstart" up
```

### View Real-time Logs

```bash
# All services
docker compose -f deploy/docker-compose/quickstart.yaml -p "hanko-quickstart" logs -f

# Hanko only
docker compose -f deploy/docker-compose/quickstart.yaml -p "hanko-quickstart" logs -f hanko
```
