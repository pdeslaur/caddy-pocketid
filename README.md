# caddy-pocketid

A [Caddy](https://caddyserver.com) middleware plugin that protects sites with [PocketID](https://github.com/stonith404/pocket-id) OIDC authentication.

## What

`caddy-pocketid` intercepts incoming HTTP requests and enforces authentication via your PocketID instance before passing them to the backend. Unauthenticated requests are redirected through the OpenID Connect authorization code flow with PKCE. Once authenticated, a signed session token is stored in a secure cookie; subsequent requests are validated locally without additional round-trips to PocketID. The plugin supports exempting specific paths or query parameters from authentication for webhooks, health checks, or API keys.

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
        client_id     {env.POCKETID_CLIENT_ID}
        client_secret {env.POCKETID_CLIENT_SECRET}
    }

    reverse_proxy localhost:8080
}
```

A more complete example with optional settings:

```caddyfile
app.example.com {
    pocketid_auth {
        issuer         https://id.example.com
        client_id      {env.POCKETID_CLIENT_ID}
        client_secret  {env.POCKETID_CLIENT_SECRET}
        cookie_domain  example.com
        callback_path  /auth/callback
        bypass_paths   /healthz /api/public/*
        bypass_query   apikey s3cr3t
    }

    reverse_proxy localhost:8080
}
```

## Configuration reference

| Option | Required | Default | Description |
|---|---|---|---|
| `issuer` | Yes | — | Base URL of your PocketID instance (e.g. `https://id.example.com`). |
| `client_id` | Yes | — | OAuth2 client ID registered in PocketID. |
| `client_secret` | Yes | — | OAuth2 client secret. Use `{env.VAR}` to avoid hardcoding. |
| `callback_path` | No | `/auth/callback` | Path Caddy listens on for the OIDC redirect. Must match the redirect URI configured in PocketID. |
| `cookie_domain` | No | — | Domain to scope the session cookie to (e.g. `example.com`). Useful when protecting multiple subdomains with a single login. |
| `bypass_paths` | No | — | Space-separated list of paths that skip authentication. Append `/*` to match a prefix (e.g. `/api/*` matches `/api/` and all sub-paths). Exact matches are also supported (e.g. `/ping`). |
| `bypass_query` | No | — | Space-separated key-value pairs. Requests whose query string contains a matching pair bypass authentication (e.g. `apikey s3cr3t` bypasses requests with `?apikey=s3cr3t`). Multiple pairs can be provided; any match is sufficient. |
