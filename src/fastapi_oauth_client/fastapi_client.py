from authlib.integrations.starlette_client import OAuth as BaseOAuth

from fastapi_oauth_client.integration import FastAPIOAuth2App


class OAuth(BaseOAuth):
    oauth2_client_cls = FastAPIOAuth2App
