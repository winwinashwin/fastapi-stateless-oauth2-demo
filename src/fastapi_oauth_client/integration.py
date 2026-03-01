import datetime
import typing as t

import jwt
import typing_extensions as te
from authlib.integrations.base_client import BaseApp
from authlib.integrations.base_client.async_app import AsyncOAuth2Mixin
from authlib.integrations.base_client.async_openid import AsyncOpenIDMixin
from authlib.integrations.base_client.errors import OAuthError
from authlib.integrations.httpx_client import AsyncOAuth2Client
from authlib.integrations.starlette_client.apps import StarletteAppMixin
from fastapi import HTTPException, Request, Response, status
from fastapi.datastructures import URL
from fastapi.responses import RedirectResponse


class ExtraClientKwargs(te.TypedDict, total=False):
    jwt_key: str
    jwt_algorithm: str
    jwt_ttl_secs: int


class FastAPIOAuth2App(StarletteAppMixin, AsyncOAuth2Mixin, AsyncOpenIDMixin, BaseApp):
    """A FastAPI native OAuth2 app without relying on Starlette's SessionMiddleware.

    Adapted from: https://github.com/authlib/authlib/blob/a769f343ae8d43236448e3e74445980861812e82/authlib/integrations/starlette_client/apps.py#L60

    The only extra logic here compared to authlib's starlette client is removing all references to request.session
    and encoding/decoding the state using PyJWT.
    """

    client_cls = AsyncOAuth2Client

    client_kwargs: ExtraClientKwargs

    async def encode_signed_state(self, url: str | URL, **state_data) -> URL:
        if isinstance(url, str):
            url = URL(url)

        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

        data = {
            "iat": now,
            "nbf": now,
            "exp": now + datetime.timedelta(seconds=self.client_kwargs["jwt_ttl_secs"]),
            "state": state_data,
        }
        return url.include_query_params(
            state=jwt.encode(
                data,
                self.client_kwargs["jwt_key"],
                algorithm=self.client_kwargs["jwt_algorithm"],
            ),
        )

    async def decode_signed_state(self, state: str) -> dict[str, t.Any]:
        try:
            data = jwt.decode(
                state,
                self.client_kwargs["jwt_key"],
                algorithms=[self.client_kwargs["jwt_algorithm"]],
            )
        except jwt.ExpiredSignatureError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "OAuth state expired") from exc
        except jwt.InvalidTokenError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid OAuth state") from exc

        return data["state"]

    async def authorize_redirect(self, request: Request, redirect_uri: str | None = None, **kwargs) -> Response:  # noqa: ARG002
        """Create a HTTP Redirect for Authorization Endpoint.

        :param request: HTTP request instance from Starlette view.
        :param redirect_uri: Callback or redirect URI for authorization.
        :param kwargs: Extra parameters to include.
        :return: A HTTP redirect response.
        """
        # Handle Starlette >= 0.26.0 where redirect_uri may now be a URL and not a string
        if redirect_uri and isinstance(redirect_uri, URL):
            redirect_uri = str(redirect_uri)
        rv = await self.create_authorization_url(redirect_uri, **kwargs)
        url = await self.encode_signed_state(
            rv["url"],
            redirect_uri=redirect_uri,
            **{k: v for k, v in rv.items() if k not in ("url", "state")},
        )
        return RedirectResponse(url, status_code=status.HTTP_302_FOUND)

    async def authorize_access_token(self, request: Request, **kwargs) -> dict[str, t.Any]:
        if request.scope.get("method", "GET") == "GET":
            error = request.query_params.get("error")
            if error:
                description = request.query_params.get("error_description")
                raise OAuthError(error=error, description=description)

            params = {
                "code": request.query_params.get("code"),
                "state": request.query_params.get("state"),
            }
        else:
            async with request.form() as form:
                params = {
                    "code": form.get("code"),
                    "state": form.get("state"),
                }

        state_data = await self.decode_signed_state(t.cast("str", params["state"]))
        params = self._format_state_params(state_data, params)

        claims_options = kwargs.pop("claims_options", None)
        claims_cls = kwargs.pop("claims_cls", None)
        leeway = kwargs.pop("leeway", 120)
        token = await self.fetch_access_token(**params, **kwargs)

        if "id_token" in token and "nonce" in state_data:
            userinfo = await self.parse_id_token(
                token,
                nonce=state_data["nonce"],
                claims_options=claims_options,
                claims_cls=claims_cls,
                leeway=leeway,
            )
            token["userinfo"] = userinfo
        return token
