# keycloak_auth.py

import requests
from jose import jwt
from jose.exceptions import JWTError
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.models import AnonymousUser
from django.conf import settings
KEYCLOAK_URL = "http://host.docker.internal:8080"
REALM = "my-kong"
JWKS_URL = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/certs"

# Download JWKS once
JWKS = requests.get(JWKS_URL).json()

def get_signing_key(kid):
    for jwk in JWKS["keys"]:
        if jwk["kid"] == kid:
            return jwk
    raise Exception(f"No matching key found for kid: {kid}")

class KeycloakAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return None

        token = auth_header.split(" ")[1]

        try:
            unverified_header = jwt.get_unverified_header(token)
            jwk_key = get_signing_key(unverified_header["kid"])

            # Now decode using the JWK directly
            payload = jwt.decode(token, jwk_key, algorithms=["RS256"], options={"verify_aud": False})

            user = AnonymousUser()
            user.username = payload.get("preferred_username", "unknown")
            user.roles = payload.get("realm_access", {}).get("roles", [])
            print("role",user.roles)

            return (user, token)

        except JWTError as e:
            raise AuthenticationFailed(f"Token validation failed: {e}")
