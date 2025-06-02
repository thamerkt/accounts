from keycloak import KeycloakOpenID
from django.conf import settings

# Initialize Keycloak connection
keycloak_openid = KeycloakOpenID(
    server_url=settings.KEYCLOAK_SERVER_URL,
    client_id=settings.KEYCLOAK_CLIENT_ID,
    realm_name=settings.KEYCLOAK_REALM,
    client_secret_key=settings.KEYCLOAK_CLIENT_SECRET,
)

def get_access_token(username, password):
    try:
        token = keycloak_openid.token(username, password)
        return token["access_token"]
    except Exception as e:
        return {"error": str(e)}
