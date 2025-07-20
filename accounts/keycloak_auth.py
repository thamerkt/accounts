import requests
from jose import jwt
from jose.exceptions import JWTError
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.models import AnonymousUser
from django.conf import settings

KEYCLOAK_URL = settings.KEYCLOAK_URL
REALM = "master"
JWKS_URL = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/certs"

# Global cache
JWK_CACHE = {}

def fetch_jwks():
    try:
        resp = requests.get(JWKS_URL)
        resp.raise_for_status()
        keys = resp.json().get("keys", [])
        return {key["kid"]: key for key in keys}
    except Exception as e:
        raise Exception(f"Failed to fetch JWKS from Keycloak: {e}")

def get_signing_key(kid):
    global JWK_CACHE

    # Try from cache
    if kid in JWK_CACHE:
        return JWK_CACHE[kid]

    # Refresh cache
    JWK_CACHE = fetch_jwks()

    if kid in JWK_CACHE:
        return JWK_CACHE[kid]

    raise Exception(f"No matching key found for kid: {kid}")

class SimpleUser:
    def __init__(self, username, roles):
        self.username = username
        self.roles = roles
        self.is_authenticated = True

    def __str__(self):
        return self.username

class KeycloakAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return None

        token = auth_header.split(" ")[1]

        try:
            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header.get("kid")
            if not kid:
                raise AuthenticationFailed("No 'kid' found in token header.")

            jwk_key = get_signing_key(kid)
            payload = jwt.decode(token, jwk_key, algorithms=["RS256"], options={"verify_aud": False})

            username = payload.get("preferred_username", "unknown")
            roles = payload.get("realm_access", {}).get("roles", [])

            user = SimpleUser(username=username, roles=roles)

            return (user, token)

        except JWTError as e:
            raise AuthenticationFailed(f"Token validation failed: {e}")
        except Exception as e:
            raise AuthenticationFailed(f"Authentication error: {e}")
