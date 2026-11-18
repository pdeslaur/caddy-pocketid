# caddy-pocketid

A [Caddy](https://caddyserver.com) middleware plugin that protects sites with [PocketID](https://github.com/stonith404/pocket-id) OIDC authentication.

## What

`caddy-pocketid` intercepts incoming HTTP requests and enforces authentication via your PocketID instance before passing them to the backend. Unauthenticated requests are redirected through the OpenID Connect authorization code flow with PKCE. Once authenticated, a signed session token is stored in a secure cookie; subsequent requests are validated locally without additional round-trips to PocketID.

## Why

PocketID is a lightweight, self-hosted identity provider built for home labs and small teams. If you already run Caddy as your reverse proxy, this plugin lets you add SSO in front of any upstream service without deploying a separate auth proxy or modifying the application itself. The entire auth flow — discovery, PKCE, token exchange, and JWT validation — is handled by the plugin using the standard `coreos/go-oidc` library, so there is nothing extra to operate.

## Getting started

### 1. Build Caddy with the plugin

```bash
xcaddy build --with github.com/pdeslaur/caddy-pocketid
```

### 2. Register an OIDC application in PocketID

In your PocketID admin panel, create an application and note the **Client ID** and **Client Secret**. Set the redirect URI to:

```
https://<your-domain>/auth/callback
```

### 3. Configure your Caddyfile

```caddyfile
example.com {
    pocketid_auth {
        issuer        https://id.example.com
        client_id     {$POCKETID_CLIENT_ID}
        client_secret {$POCKETID_CLIENT_SECRET}
    }

    reverse_proxy localhost:8080
}
```

### Exempting paths from authentication

Use Caddy's native matchers to apply `pocketid_auth` only where needed.

**Exempt specific paths** (e.g. a health check and a public API prefix):

```caddyfile
example.com {
    @protected {
        not path /healthz /api/public/*
    }

    handle @protected {
        pocketid_auth {
            issuer        https://id.example.com
            client_id     {$POCKETID_CLIENT_ID}
            client_secret {$POCKETID_CLIENT_SECRET}
        }
        reverse_proxy localhost:8080
    }

    handle {
        reverse_proxy localhost:8080
    }
}
```

**Exempt requests with a specific query parameter** (e.g. an API key):

```caddyfile
example.com {
    @protected {
        not query apikey=s3cr3t
    }

    handle @protected {
        pocketid_auth {
            issuer        https://id.example.com
            client_id     {$POCKETID_CLIENT_ID}
            client_secret {$POCKETID_CLIENT_SECRET}
        }
        reverse_proxy localhost:8080
    }

    handle {
        reverse_proxy localhost:8080
    }
}
```

See the [Caddy matcher documentation](https://caddyserver.com/docs/caddyfile/matchers) for the full list of available matchers.

### Refreshing sessions

With `refresh`, the plugin keeps the refresh token PocketID issues with the id_token in a second cookie, `pocketid_refresh`, for 30 days, PocketID's default refresh token lifetime. Once the id_token has expired, or its cookie is gone after the browser restarts, the plugin redeems the refresh token, authenticating the client as it does for a login, and serves the request without a redirect. This keeps `fetch` requests, form posts and WebSockets working past the id_token's lifetime, which a redirect to PocketID would break. PocketID rotates the refresh token and checks again that the user is allowed the client on each refresh. A refresh token PocketID rejects is cleared, and the request redirects to log in.

```caddyfile
example.com {
    pocketid_auth {
        issuer        https://id.example.com
        client_id     {$POCKETID_CLIENT_ID}
        client_secret {$POCKETID_CLIENT_SECRET}
        refresh
    }

    reverse_proxy localhost:8080
}
```

Neither session cookie is forwarded to the backend.

### Clients without a secret

With `client_assertion spiffe` and no `client_secret`, each code exchange and refresh authenticates the client with a JWT-SVID (RFC 7523), fetched from the [SPIFFE Workload API](https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/#spiffe-workload-api) at `SPIFFE_ENDPOINT_SOCKET` with the issuer as its audience. In PocketID, give the client a federated identity whose issuer is your SPIRE server's JWT issuer, whose subject is the workload's SPIFFE ID, and whose audience is the issuer URL here. A login fails with 502 when the Workload API can't be reached.

```caddyfile
example.com {
    pocketid_auth {
        issuer           https://id.example.com
        client_id        {$POCKETID_CLIENT_ID}
        client_assertion spiffe
    }

    reverse_proxy localhost:8080
}
```

With neither `client_secret` nor `client_assertion`, the plugin is a public client, relying on PKCE alone.

Without a secret, the OAuth2 state is signed with a random key made at startup, so restarting Caddy fails only the logins in flight.

## Configuration reference

| Option | Required | Default | Description |
|---|---|---|---|
| `issuer` | Yes | — | Base URL of your PocketID instance (e.g. `https://id.example.com`). |
| `client_id` | Yes | — | OAuth2 client ID registered in PocketID. |
| `client_secret` | No | — | OAuth2 client secret. Use `{$VAR}` to avoid hardcoding. Exclusive with `client_assertion`. |
| `client_assertion` | No | — | `spiffe` authenticates the client with a JWT-SVID instead of a secret; see [Clients without a secret](#clients-without-a-secret). |
| `callback_path` | No | `/auth/callback` | Path Caddy listens on for the OIDC redirect. Must match the redirect URI configured in PocketID. |
| `cookie_domain` | No | — | Domain to scope the session cookie to (e.g. `example.com`). Useful when protecting multiple subdomains with a single login. |
| `prompt` | No | — | OIDC [`prompt` parameter](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest) sent on every authorization request. Common values: `login` (force re-authentication), `consent` (force consent screen), `select_account`, `none`. |
| `refresh` | No | off | Renew expired sessions with PocketID's refresh token instead of redirecting; see [Refreshing sessions](#refreshing-sessions). |
| `set_header key value` | No | — | Inject a static header into every authenticated request before it reaches the backend. Can be repeated. Use `{$VAR}` for secrets (e.g. a shared Basic Auth credential). |
| `forward_claim claim header` | No | — | Forward a JWT claim from the session token as a request header. Can be repeated. Common claims: `sub`, `email`, `name`, `preferred_username`. |
