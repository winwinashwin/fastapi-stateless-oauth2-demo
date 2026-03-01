# FastAPI Stateless OAuth2 Demo

A stateless OAuth2 client implementation for FastAPI using Authlib

## Overview

Authlib's Starlette client implementation rely on `SessionMiddleware` to store OAuth state in server-side sessions via cookies. This project provides a **stateless alternative** that uses cryptographically signed JWT tokens to manage OAuth state, removing the dependency on session middleware entirely.

## Key Features

- **JWT-Based State Management**: OAuth state encoded and verified using signed JWT tokens
- **Drop-in Replacement**: Extends Authlib's OAuth client with minimal API changes
- **Security**: Configurable JWT signing algorithm, secret key, and token expiration
- **FastAPI Native**: Built specifically for FastAPI applications

## Example Usage

See `fastapi-google-login/` for a complete working example implementing Google OAuth2 login.
This example is an adapted version of [authlib's fastapi-google-login demo](https://github.com/authlib/demo-oauth-client/blob/master/fastapi-google-login/app.py)

### Quick Start

1. **Set up environment variables** (`.env`):

```bash
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
JWT_SECRET_KEY=your_random_secret_key
```

2. **Register OAuth client**:

```python
from fastapi_oauth_client.fastapi_client import OAuth

oauth = OAuth(config)

oauth.register(
    name="google",
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={
        "scope": "openid email profile",
        "code_challenge_method": "S256",
        "jwt_key": config.get("JWT_SECRET_KEY"),
        "jwt_algorithm": "HS256",
        "jwt_ttl_secs": 300,  # 5 minutes
    },
)
```

3. **Implement OAuth endpoints**:

```python
@app.get("/login")
async def login(request: Request):
    redirect_uri = request.url_for("auth")
    return await oauth.google.authorize_redirect(request, redirect_uri)

@app.get("/auth")
async def auth(request: Request):
    token = await oauth.google.authorize_access_token(request)
    user = token.get("userinfo")

    # ... Handle authenticated user

    return RedirectResponse(url="/")
```

## Running the Demo

```bash
cd fastapi-google-login
cp .env.sample .env
# Edit .env with your Google OAuth credentials
python app.py
```

Visit http://127.0.0.1:8000 to test the OAuth flow.
