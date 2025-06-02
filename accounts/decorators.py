# decorators.py

from functools import wraps
from django.http import JsonResponse
from keycloak import KeycloakOpenID

# Initialize Keycloak client
keycloak_openid = KeycloakOpenID(
    server_url="http://localhost:8080",
    client_id="kong",
    client_secret_key="isqTqqyS1SdqCg7klUtAWnZtDoC7dnFs",
    realm_name="kong-app"
)

def keycloak_login_required(view_func):
    """
    Custom decorator to check if the user is authenticated using Keycloak.
    """
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        # Get the Authorization token from the request header
        token = request.headers.get('Authorization')
        
        if not token:
            return JsonResponse({"message": "Authorization token missing"}, status=401)
        
        # Extract the token from the 'Bearer' scheme
        token = token.split()[1] if token.startswith('Bearer ') else token
        
        try:
            # Decode the token and verify its validity
            user_info = keycloak_openid.decode_token(token)

            # Optionally check for roles in the token
            if 'client' in user_info['realm_access']['roles']:
                request.user_info = user_info  # Attach the user info to the request object
                return view_func(request, *args, **kwargs)  # Proceed with the view
            else:
                return JsonResponse({"message": "Forbidden: You don't have access"}, status=403)
        except Exception as e:
            return JsonResponse({"message": f"Unauthorized: {str(e)}"}, status=401)

    return _wrapped_view
