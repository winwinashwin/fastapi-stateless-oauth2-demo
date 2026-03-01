import datetime
import json
import typing as t
import uuid

import jwt
from authlib.integrations.starlette_client import OAuthError
from fastapi import Cookie, FastAPI, Response
from starlette.config import Config
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse

from fastapi_oauth_client.fastapi_client import OAuth

app = FastAPI()


config = Config(".env")
oauth = OAuth(config)

CONF_URL = "https://accounts.google.com/.well-known/openid-configuration"
oauth.register(
    name="google",
    server_metadata_url=CONF_URL,
    client_kwargs={
        "scope": "openid email profile",
        "code_challenge_method": "S256",  # Require PKCE
        # JWT settings used for oauth state
        "jwt_key": config.get("JWT_SECRET_KEY"),
        "jwt_algorithm": "HS256",
        "jwt_ttl_secs": int(datetime.timedelta(minutes=3).total_seconds()),
    },
)


@app.get("/")
async def homepage(refresh_token: t.Annotated[str | None, Cookie()] = None) -> HTMLResponse:
    login_response = HTMLResponse('<a href="/login">login</a>')
    if not refresh_token:
        return login_response

    try:
        payload = jwt.decode(
            refresh_token,
            config.get("JWT_SECRET_KEY"),
            algorithms=["HS256"],
        )
    except jwt.InvalidTokenError:
        return login_response

    data = json.dumps(payload["identity"])
    html = f'<pre>{data}</pre><a href="/logout">logout</a>'
    return HTMLResponse(html)


@app.get("/login")
async def login(request: Request) -> Response:
    redirect_uri = request.url_for("auth")
    return await oauth.google.authorize_redirect(request, redirect_uri)


@app.get("/auth")
async def auth(request: Request) -> Response:
    """OAuth callback endpoint that completes the OAuth flow and issues a refresh token.

    Note: In a real-world production scenario, the backend should provide
    an API endpoint where the frontend can exchange the refresh token for a short-lived
    access token.

    For demonstration purposes, this example only uses the refresh token to maintain a simple
    user session like experience.
    """
    try:
        token = await oauth.google.authorize_access_token(request)
    except OAuthError as error:
        return HTMLResponse(f"<h1>{error.error}</h1>")
    user = token.get("userinfo")
    response = RedirectResponse(url=request.url_for("homepage"))

    if user:
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        token_data = {
            "iat": now,
            "jti": str(uuid.uuid4()),
            "type": "refresh",
            "identity": user,
            "nbf": now,
            "exp": now + datetime.timedelta(hours=6),
        }
        refresh_token = jwt.encode(
            payload=token_data,
            key=config.get("JWT_SECRET_KEY"),
            algorithm="HS256",
        )
        response.set_cookie("refresh_token", refresh_token, max_age=None, httponly=True)
    return response


@app.get("/logout")
async def logout(request: Request) -> RedirectResponse:
    response = RedirectResponse(url=request.url_for("homepage"))
    response.delete_cookie("refresh_token", httponly=True)
    return response


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
