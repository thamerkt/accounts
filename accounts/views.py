from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings
from django.contrib.auth import authenticate
from django.core.mail import send_mail
import requests
from django.core.cache import cache
import redis
import random
import jwt
import json
from .models import CustomUser
from .serializers import CustomUserSerializer
from django.utils.timezone import now, timedelta
from rest_framework.permissions import AllowAny, IsAuthenticated
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from dj_rest_auth.registration.views import SocialLoginView
from django.contrib.auth.hashers import make_password
from .util import get_user_attributes, initialize_registration_session
import pika
from logging import getLogger
from django.utils import timezone
from rest_framework.permissions import AllowAny
import threading
import os
from datetime import datetime
from .util import create_keycloak_user, get_keycloak_admin_token, get_keycloak_user_id, login_user, assign_role_to_user, revoke_user_sessions, generate_and_store_otp, get_keycloak_user_info, add_user_to_keycloak,delete_keycloak_user,get_all_keycloak_users,get_user_attributes,update_keycloak_user_attributes,verify_user_email_by_id
from django.conf import settings
from rest_framework.decorators import api_view, permission_classes
from .permissions import IsAdmin, IsClient
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from jose import jwt, JWTError
from jose.exceptions import ExpiredSignatureError
from django.conf import settings
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from .permissions import AllowAnyRole
# CloudAMQP URL
CLOUDAMQP_URL = 'amqps://dxapqekt:BbFWQ0gUl1O8u8gHIUV3a4KLZacyrzWt@possum.lmq.cloudamqp.com/dxapqekt'

class UserSuspendView(APIView):
    """
    API endpoint to suspend or unsuspend a Keycloak user.
    Only accessible by admin users.
    """
    permission_classes = [AllowAnyRole]  # Adjust based on your needs

    def post(self, request, user_id):
        try:
            action = request.data.get('action', 'suspend')  # 'suspend' or 'unsuspend'
            token = get_keycloak_admin_token()
            
            if not token:
                print("Error: Failed to get Keycloak admin token.")
                return Response({"error": "Failed to get Keycloak admin token."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            user = get_keycloak_user_info(user_id, token)
            if not user:
                print(f"Warning: User with ID {user_id} not found in Keycloak.")
                return Response({"error": "User not found in Keycloak."}, status=status.HTTP_404_NOT_FOUND)

            attributes = user.get("attributes", {})

            if action == 'suspend':
                attributes["is_suspended"] = ["true"]
                attributes["suspended_at"] = [str(int(timezone.now().timestamp()))]
                message = f"User {user.get('email')} has been suspended"
                event_type = 'user.suspended'
            elif action == 'unsuspend':
                attributes["is_suspended"] = ["false"]
                attributes["suspended_at"] = [""]
                message = f"User {user.get('email')} has been unsuspended"
                event_type = 'user.unsuspended'
            else:
                print(f"Warning: Invalid action '{action}' received for user {user_id}.")
                return Response({"error": f"Invalid action '{action}'. Use 'suspend' or 'unsuspend'."}, status=status.HTTP_400_BAD_REQUEST)

            print(f"Info: Updating user {user_id} attributes: {attributes}")
            try:
                success = update_keycloak_user_attributes(user_id, token, attributes)
            except Exception as e:
                print(f"Error: Exception during update_keycloak_user_attributes for user {user_id}: {str(e)}")
                return Response({"error": f"Exception during user update: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            if not success:
                print(f"Error: update_keycloak_user_attributes returned False for user {user_id}.")
                return Response({"error": "Failed to update user in Keycloak."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            # Publish event to RabbitMQ (optional errors logged but do not fail request)
            self.publish_rabbitmq_event(event_type, user.get('email'))

            return Response({"message": message}, status=status.HTTP_200_OK)

        except Exception as e:
            print(f"Error: Unexpected error in UserSuspendView: {str(e)}")
            return Response({"error": f"Unexpected error: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

def publish_rabbitmq_event(self, event_type, email):
    connection = None
    try:
        amqp_url = 'amqps://poqribhv:LzwYFbmBXeyiQI0GveEEe-YQyDeH126c@kebnekaise.lmq.cloudamqp.com/poqribhv'
        parameters = pika.URLParameters(amqp_url)

        connection = pika.BlockingConnection(parameters)
        channel = connection.channel()

        exchange_name = 'user_events'
        channel.exchange_declare(exchange=exchange_name, exchange_type='topic', durable=True)

        message = {
            'event': event_type,
            'payload': {
                'email': email
            }
        }

        channel.basic_publish(
            exchange=exchange_name,
            routing_key=event_type,
            body=json.dumps(message),
            properties=pika.BasicProperties(
                delivery_mode=2  # Make message persistent
            )
        )
        print(f"Info: Published RabbitMQ event '{event_type}' for {email}")

    except Exception as e:
        print(f"Error: Failed to publish RabbitMQ message: {e}")

    finally:
        if connection and connection.is_open:
            try:
                connection.close()
            except Exception as e:
                print(f"Warning: Failed to close RabbitMQ connection: {e}")



class ActiveUsersView(APIView):
    """
    API endpoint to list all active (not suspended) users from Keycloak.
    Only accessible by admin users.
    """
    permission_classes = [AllowAnyRole]

    def get(self, request):
        token = get_keycloak_admin_token()
        print("TOKEN:", token)
        if not token:
            return Response({"error": "Failed to get Keycloak admin token."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        users = get_all_keycloak_users()
        if users is None:
            return Response({"error": "Failed to fetch users from Keycloak."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        active_users = []
        for user in users:
            attributes = user.get("attributes", {})
            is_suspended = attributes.get("is_suspended", ["false"])[0].lower() == "true"

            if not is_suspended:
                active_users.append({
                    "id": user.get("id"),
                    "username": user.get("username"),
                    "email": user.get("email"),
                    "firstName": user.get("firstName"),
                    "lastName": user.get("lastName"),
                    "emailVerified": user.get("emailVerified"),
                    "createdTimestamp": user.get("createdTimestamp"),
                })

        return Response(active_users, status=status.HTTP_200_OK)

class SuspendedUsersView(APIView):
    permission_classes =[AllowAnyRole]
    
    permission_classes = [AllowAny]

    def get(self, request):
        token = get_keycloak_admin_token()
        print("TOKEN:", token)
        if not token:
            return Response({"error": "Failed to get Keycloak admin token."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        users = get_all_keycloak_users()
        if users is None:
            return Response({"error": "Failed to fetch users from Keycloak."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        active_users = []
        for user in users:
            attributes = user.get("attributes", {})
            is_suspended = attributes.get("is_suspended", ["true"])[0].lower() == "true"

            if not is_suspended:
                active_users.append({
                    "id": user.get("id"),
                    "username": user.get("username"),
                    "email": user.get("email"),
                    "firstName": user.get("firstName"),
                    "lastName": user.get("lastName"),
                    "emailVerified": user.get("emailVerified"),
                    "createdTimestamp": user.get("createdTimestamp"),
                })

        return Response(active_users, status=status.HTTP_200_OK)


class UserListView(APIView):
    """
    API endpoint to get all users from Keycloak (excluding password),
    and include their assigned roles.
    """
    permission_classes = [AllowAnyRole]

    def get(self, request):
        try:
            print(">>> Entered UserListView GET")
            token = get_keycloak_admin_token()
            print("TOKEN:", token)
        except Exception as e:
            print("Error while getting token:", e)
            return Response({"error": str(e)}, status=500)

        if not token:
            return Response({"error": "Failed to obtain Keycloak admin token."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        base_url = settings.KEYCLOAK_URL
        realm = "my-kong"
        url = f"{base_url}/admin/realms/{realm}/users"
        headers = {"Authorization": f"Bearer {token}"}

        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            return Response({"error": "Failed to fetch users from Keycloak."}, status=response.status_code)

        users = response.json()
        clean_users = []

        for user in users:
            user_id = user.get("id")

            # Récupération des rôles de l'utilisateur
            role_url = f"{base_url}/admin/realms/{realm}/users/{user_id}/role-mappings/realm"
            role_response = requests.get(role_url, headers=headers)

            if role_response.status_code != 200:
                user_roles = []
            else:
                role_data = role_response.json()
                user_roles = [role["name"] for role in role_data]

            clean_users.append({
                "id": user_id,
                "username": user.get("username"),
                "email": user.get("email"),
                "first_name": user.get("firstName"),
                "last_name": user.get("lastName"),
                "email_verified": user.get("emailVerified"),
                "enabled": user.get("enabled"),
                "attributes": user.get("attributes", {}),
                "created": user.get("createdTimestamp"),
                "roles": user_roles
            })

        return Response(clean_users, status=status.HTTP_200_OK)

class UserDetailView(APIView):
    """
    Retrieve a single user by Keycloak ID (excluding sensitive fields).
    """
    permission_classes =[AllowAnyRole]

    def get(self, request, keycloak_id):
        token = get_keycloak_admin_token()
        if not token:
            return Response({"error": "Failed to get Keycloak admin token."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        user = get_keycloak_user_info(keycloak_id, token)
        if not user:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        attributes = user.get("attributes", {})

        user_data = {
            "id": user.get("id"),
            "username": user.get("username"),
            "email": user.get("email"),
            "firstName": user.get("firstName"),
            "lastName": user.get("lastName"),
            "emailVerified": user.get("emailVerified"),
            "createdTimestamp": user.get("createdTimestamp"),
            "is_suspended": attributes.get("is_suspended", ["false"])[0].lower() == "true",
            "is_verified": attributes.get("is_verified", ["false"])[0].lower() == "true",
        }

        return Response(user_data, status=status.HTTP_200_OK)

class UserUpdateView(APIView):
    """
    Update a user by Keycloak ID.
    """
    permission_classes =[AllowAnyRole]

    def put(self, request, keycloak_id):
        try:
            user = CustomUser.objects.get(keycloak_id=keycloak_id)
        except CustomUser.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        
        serializer = CustomUserSerializer(user, data=request.data, partial=True)
        
        if serializer.is_valid():
            # Handle password hashing separately
            if 'password' in serializer.validated_data:
                serializer.validated_data['password'] = make_password(serializer.validated_data['password'])
            
            serializer.save()
            data = serializer.data
            data.pop('password', None)  # Do not expose password in response
            return Response(data, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserDeleteView(APIView):
    """
    Delete a user by Keycloak ID.
    """
    permission_classes =[AllowAnyRole]

    def delete(self, request, keycloak_id):
        token = get_keycloak_admin_token()
        if not token:
            return Response({"error": "Failed to obtain Keycloak admin token."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        url = f"{settings.KEYCLOAK_URL}/admin/realms/{settings.KEYCLOAK_REALM}/users/{keycloak_id}"
        headers = {"Authorization": f"Bearer {token}"}

        response = requests.delete(url, headers=headers)

        if response.status_code == 204:
            return Response({"message": "User deleted successfully."}, status=status.HTTP_204_NO_CONTENT)
        elif response.status_code == 404:
            return Response({"error": "User not found in Keycloak."}, status=status.HTTP_404_NOT_FOUND)
        else:
            return Response(
                {"error": f"Failed to delete user: {response.text}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

SECRET_KEY = 'your-secret-key'
from django.http import JsonResponse
from django.conf import settings
import jwt  # This is PyJWT
from jwt import InvalidTokenError


def generate_jwt(user):
    payload = {
        "user_id": user.id,
        "email": user.email,
        "exp": now() + timedelta(days=7)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

class GoogleLogin(SocialLoginView):
    adapter_class = GoogleOAuth2Adapter

class SendOTPView(APIView):
    """
    Generates and sends an OTP to the given email address.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email")
        if not email:
            return Response({"error": "Email is required."}, status=status.HTTP_400_BAD_REQUEST)

        return Response({"message": "OTP sent successfully!"}, status=status.HTTP_200_OK)

from django.views.decorators.csrf import csrf_exempt
from rest_framework.views import APIView
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

class GoogleAuth(APIView):
    permission_classes = [AllowAnyRole]
    @csrf_exempt
    def post(self, request):
        try:
            # Extract the JWT credential from the request body
            data = json.loads(request.body)
            credential = data.get('credential')  # Extract the JWT credential
            role=data.get('role')

            if not credential:
                return JsonResponse({'error': 'JWT credential is required'}, status=400)

            # Verify the JWT credential
            try:
                client_id = os.environ.get('GOOGLE_CLIENT_ID')
                id_info = id_token.verify_oauth2_token(credential, google_requests.Request(), client_id)

                # Extract user information from the JWT payload
                email = id_info.get('email')
                first_name = id_info.get('given_name', '')
                last_name = id_info.get('family_name', '')

                # Add the user to Keycloak (if applicable)
                try:
                    userdata = add_user_to_keycloak(email, first_name, last_name,role)
                    user_id = get_keycloak_user_id(email)
                    return JsonResponse({'message': 'User authenticated and added to Keycloak', 'userdata': userdata, 'user': user_id})
                except Exception as e:
                    return JsonResponse({'error': f'Keycloak error: {str(e)}'}, status=500)

            except ValueError as e:
                return JsonResponse({'error': f'Invalid JWT credential: {str(e)}'}, status=400)

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON data in request body'}, status=400)
        except Exception as e:
            return JsonResponse({'error': f'Internal server error: {str(e)}'}, status=500)

class FacebookAuth(APIView):
    @csrf_exempt
    def post(self, request):
        try:
            data = json.loads(request.body)
            access_token = data.get('accessToken')
            user_id = data.get('userID')
            role=data.get('role')

            if not access_token or not user_id:
                return JsonResponse({'error': 'Access token and user ID are required'}, status=400)

            # App credentials (secure these in environment variables ideally)
            app_id = os.environ.get('FACEBOOK_APP_ID')
            app_secret = os.environ.get('FACEBOOK_APP_SECRET')

            # Step 1: Verify the Facebook access token
            debug_token_url = f"https://graph.facebook.com/debug_token?input_token={access_token}&access_token={app_id}|{app_secret}"
            debug_token_response = requests.get(debug_token_url)
            debug_data = debug_token_response.json()

            if 'error' in debug_data.get('data', {}):
                return JsonResponse({'error': 'Invalid Facebook token'}, status=400)

            # Step 2: Get user info from Facebook
            user_info_url = f"https://graph.facebook.com/{user_id}?fields=id,name,email,first_name,last_name&access_token={access_token}"
            user_info_response = requests.get(user_info_url)
            user_info = user_info_response.json()

            if 'error' in user_info:
                return JsonResponse({'error': 'Failed to fetch user info from Facebook'}, status=400)

            email = user_info.get('email')
            first_name = user_info.get('first_name', '')
            last_name = user_info.get('last_name', '')

            if not email:
                return JsonResponse({'error': 'Email is required but not provided by Facebook'}, status=400)

            # Step 3: Add the user to Keycloak
            try:
                userdata = add_user_to_keycloak(email, first_name, last_name,role)
                user_id = get_keycloak_user_id(email)
                return JsonResponse({
                    'message': 'User authenticated and added to Keycloak',
                    'userdata': userdata,
                    'user': user_id
                })
            except Exception as e:
                return JsonResponse({'error': f'Keycloak error: {str(e)}'}, status=500)

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON data in request body'}, status=400)
        except Exception as e:
            return JsonResponse({'error': f'Internal server error: {str(e)}'}, status=500)

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework import status
from django.conf import settings
import redis
import requests
import logging

logger = logging.getLogger(__name__)

logger = logging.getLogger(__name__)



from rest_framework.decorators import api_view
from rest_framework.response import Response

@api_view(["GET"])
def get_user_progress(request):
    user_id = request.query_params.get("user_id")
    token = get_keycloak_admin_token()
    user_info = get_keycloak_user_info(user_id, token)

    if user_info:
        progress = user_info.get("attributes", {}).get("registrationProgress", ["step1"])[0]
        return Response({"progress": progress})
    else:
        return Response({"error": "User not found"}, status=404)

@api_view(["PUT"])   
def update_registration_progress(user_id, progress, data=None):
    token = get_keycloak_admin_token()

    url = f"{settings.KEYCLOAK_URL}/admin/realms/{settings.KEYCLOAK_REALM}/users/{user_id}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    attributes = {
        "registrationProgress": [progress]
    }

    if data is not None:
        attributes["registrationData"] = [json.dumps(data)]

    payload = {
        "attributes": attributes
    }

    response = requests.put(url, headers=headers, json=payload)

    if response.status_code in [200, 204]:
        print(f"✅ Updated registration progress to {progress} for user {user_id}")
    else:
        raise Exception(f"❌ Failed to update progress: {response.status_code} - {response.text}")

class RegisterView(APIView):
    permission_classes = [AllowAnyRole]

    def post(self, request):
        data = request.data
        email = data.get("email")
        password = data.get("password")
        role_type = data.get("role")

        if not email or not password or not role_type:
            return Response({"message": "Email, password, and role are required."}, status=status.HTTP_400_BAD_REQUEST)

        username = email

        # 1. Create user in Keycloak
        result = create_keycloak_user(username, email, password)
        if not result["success"]:
            return Response(result, status=status.HTTP_400_BAD_REQUEST)

        # 2. Get user ID once after creation
        keycloak_user_id = result.get("user_id") or get_keycloak_user_id(email)
        if not keycloak_user_id:
            return Response({"message": "Failed to retrieve user ID"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # 3. Assign role (avoid re-checking user existence)
        assign_role_to_user(keycloak_user_id, role_type)

        # 4. Store registration progress (optional, avoid refetching attributes unless needed)
        initialize_registration_session(keycloak_user_id, "step1")

        # 5. Generate and store OTP (inline)
        otp = self.generate_and_store_otp(keycloak_user_id)
        if not otp:
            return Response({"message": "Failed to generate OTP"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # 6. Send mail in a background thread
        threading.Thread(target=self.send_otp_email, args=(email, otp)).start()

        # 7. Auto-login user (don't fetch admin token again)
        login_result = login_user(email, password)
        if login_result["success"]:
            return Response({
                "message": "User registered and logged in successfully!",
                "token": login_result["token"],
                "user_id": keycloak_user_id
            }, status=status.HTTP_201_CREATED)
        else:
            return Response({
                "message": "User registered but login failed",
                "error": login_result.get("message", "Unknown error")
            }, status=status.HTTP_400_BAD_REQUEST)

    def generate_and_store_otp(self, user_id):
        otp = str(random.randint(100000, 999999))
        cache.set(f"otp:{user_id}", otp, timeout=300)
        return otp

    def send_otp_email(self, email, otp):
        try:
            send_mail(
                subject="Email Verification OTP",
                message=f"Your OTP code is: {otp}",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[email],
                fail_silently=False,
            )
        except Exception as e:
            print(f"[❌ OTP Email Failed] {e}")
class LoginView(APIView):
    permission_classes = [AllowAnyRole]
    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")

        if not email or not password:
            return Response({"error": "Email and password are required."}, status=status.HTTP_400_BAD_REQUEST)

        # Login via Keycloak
        login_result = login_user(email, password)
        if not login_result.get("success"):
            return Response({"error": login_result.get("message", "Login failed.")}, status=status.HTTP_400_BAD_REQUEST)

        token_data = login_result["token"]
        access_token = token_data.get("access_token")
        refresh_token = token_data.get("refresh_token")

        try:
            decoded = jwt.decode(
                access_token,
                settings.YOUR_KEYCLOAK_PUBLIC_KEY,
                algorithms=["RS256"],
                options={"verify_aud": False},
            )
        except ExpiredSignatureError:
            return Response({"error": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
        except JWTError as e:
            return Response({"error": f"Token is invalid: {str(e)}"}, status=status.HTTP_401_UNAUTHORIZED)

        keycloak_id = decoded.get("sub")
        username = decoded.get("preferred_username", "unknown")
        roles = decoded.get("realm_access", {}).get("roles", [])

        # === PARALLEL TASKS ===
        with ThreadPoolExecutor() as executor:
            admin_token_future = executor.submit(get_keycloak_admin_token)
            revoke_sessions_future = executor.submit(revoke_user_sessions, keycloak_id)

            admin_token = admin_token_future.result()
            user_info = get_keycloak_user_info(keycloak_id, admin_token)

        if not user_info:
            return Response({"error": "Failed to fetch user info from Keycloak."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Extract additional user attributes
        attributes = user_info.get("attributes", {})
        email_from_info = user_info.get("email", email)
        is_verified = attributes.get("is_verified", ["false"])[0].lower() == "true"
        is_suspended = attributes.get("is_suspended", ["false"])[0].lower() == "true"

        created_timestamp = user_info.get("createdTimestamp")
        date_joined = datetime.fromtimestamp(created_timestamp / 1000.0).isoformat() if created_timestamp else None

        return Response({
            "token": access_token,
            "refresh_token": refresh_token,
            "user_id": keycloak_id,
            "user": {
                "username": username,
                "roles": roles,
                "email": email_from_info,
                "is_verified": is_verified,
                "is_suspended": is_suspended,
                "date_joined": date_joined,
            }
        }, status=status.HTTP_200_OK)
def process_identity_verification(ch, method, properties, body):
    try:
        message = json.loads(body)
        keycloak_id = message.get("keycloak_user")

        if not keycloak_id:
            print("❌ Message missing 'keycloak_user'")
            return

        token = get_keycloak_admin_token()
        user_info = get_keycloak_user_info(keycloak_id, token)

        if not user_info:
            print(f"❌ User with ID {keycloak_id} not found in Keycloak")
            return

        attributes = user_info.get("attributes", {})
        email = user_info.get("email")

        is_verified = attributes.get("is_verified", ["false"])[0].lower() == "true"

        if is_verified:
            print(f"✅ User {email} is already verified.")
            return

        # Update Keycloak attribute 'is_verified' to true
        attributes["is_verified"] = ["true"]
        user_info["attributes"] = attributes

        update_url = f"{settings.KEYCLOAK_URL}/admin/realms/{settings.KEYCLOAK_REALM}/users/{keycloak_id}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

        response = requests.put(update_url, headers=headers, json=user_info)

        if response.status_code in [200, 204]:
            print(f"✅ User {email} marked as verified in Keycloak.")

            # Optionally, send email notification
            if email:
                send_mail(
                    subject="Your Account is Verified",
                    message="🎉 Congratulations! Your account has been successfully verified.",
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[email],
                    fail_silently=False,
                )
                print(f"📧 Email sent to {email}")
        else:
            print(f"❌ Failed to update Keycloak user: {response.status_code} - {response.text}")

    except json.JSONDecodeError as e:
        print(f"❌ JSON decode error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")


def get_rabbitmq_channel(queue_name='identity_verification_queue'):
    try:
        amqp_url = 'amqps://poqribhv:LzwYFbmBXeyiQI0GveEEe-YQyDeH126c@kebnekaise.lmq.cloudamqp.com/poqribhv'
        parameters = pika.URLParameters(amqp_url)

        connection = pika.BlockingConnection(parameters)
        channel = connection.channel()
        channel.queue_declare(queue=queue_name, durable=True)
        logger.info(f"✅ Connected to RabbitMQ and declared queue '{queue_name}'")
        return connection, channel
    except Exception as e:
        logger.error(f"❌ Failed to connect to RabbitMQ: {e}")
        raise

def start_identity_verification_consumer():
    try:
        connection, channel = get_rabbitmq_channel(queue_name='identity_verification_queue')

        channel.basic_consume(
            queue='identity_verification_queue',
            on_message_callback=process_identity_verification,
            auto_ack=True
        )

        logger.info(" [*] Waiting for identity verification messages...")
        channel.start_consuming()

    except Exception as e:
        logger.error(f"❌ Consumer failed to start: {e}")

def start_consumer_thread():
    logger.info("📥 Starting consumer thread for identity verification...")
    consumer_thread = threading.Thread(target=start_identity_verification_consumer, daemon=True)
    consumer_thread.start()
    logger.info("✅ Consumer thread started")

class Role(APIView):
    permission_classes = [AllowAnyRole]
    def post(self, request):
        user_id = request.data.get("user_id")
        role = request.data.get("role")

        if not user_id or not role:
            return Response({"error": "user_id and role are required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            assign_role_to_user(user_id, role)
            return Response({"message": f"Role '{role}' assigned to user {user_id}"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class PasswordResetRequestView(APIView):
    permission_classes = [AllowAnyRole]
    def post(self, request):
        email = request.data.get("email")
        if not email:
            return Response({"error": "Email is required."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = CustomUser.objects.get(email=email)
            otp = random.randint(100000, 999999)
            user.otp = otp
            user.otp_created_at = now()
            user.save()

            # Send OTP via email
            send_mail(
                subject="Password Reset OTP",
                message=f"Your OTP code for password reset is: {otp}",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[email],
                fail_silently=False,
            )
            
            return Response({"message": "OTP sent successfully!"}, status=status.HTTP_200_OK)
        except CustomUser.DoesNotExist:
            return Response({"error": "User with this email does not exist."}, status=status.HTTP_404_NOT_FOUND)

class VerifyOTPView(APIView):
    permission_classes = [AllowAnyRole]

    def post(self, request):
        user_id = request.data.get("user_id")
        otp = request.data.get("otp")

        if not user_id or not otp:
            return Response(
                {"error": "Both user_id and otp are required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            if not self.verify_otp(user_id, otp):
                return Response(
                    {"error": "Invalid or expired OTP"},
                    status=status.HTTP_401_UNAUTHORIZED
                )
        except Exception as e:
            logger.error(f"OTP verification error: {str(e)}")
            return Response(
                {"error": "Internal error during OTP verification"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        # ✅ Verify email in Keycloak
        email_verification_result = verify_user_email_by_id(user_id)
        if not email_verification_result.get("success"):
            return Response(
                {"error": "OTP verified but email update failed", "details": email_verification_result.get("message")},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        return Response(
            {"message": "OTP and email verified successfully", "user_id": user_id},
            status=status.HTTP_200_OK
        )

    def verify_otp(self, user_id, otp):
        key = f"otp:{user_id}"
        try:
            stored_otp = cache.get(key)
            print(f"[DEBUG] Stored OTP: {stored_otp}, Provided OTP: {otp}")
            if stored_otp is None:
                raise ValueError("OTP not found or expired")
            if stored_otp != otp:
                raise ValueError("OTP mismatch")
            cache.delete(key)  # Remove OTP after successful verification
            return True
        except Exception as e:
            print(f"[ERROR] OTP verification error: {e}")
            raise

class PasswordResetView(APIView):
    permission_classes = [AllowAnyRole]
    def post(self, request):
        email = request.data.get("email")
        otp = request.data.get("otp")
        new_password = request.data.get("new_password")

        if not email or not otp or not new_password:
            return Response({"error": "Email, OTP, and new password are required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = CustomUser.objects.get(email=email)
            if user.otp != int(otp):
                return Response({"error": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST)
            
            if now() - user.otp_created_at > timedelta(minutes=10):
                return Response({"error": "OTP expired."}, status=status.HTTP_400_BAD_REQUEST)

            user.password = make_password(new_password)
            user.otp = None
            user.otp_created_at = None
            user.save()
            
            return Response({"message": "Password reset successfully!"}, status=status.HTTP_200_OK)
        except CustomUser.DoesNotExist:
            return Response({"error": "User with this email does not exist."}, status=status.HTTP_404_NOT_FOUND)

class LogoutView(APIView):
    permission_classes = [AllowAnyRole]
    def post(self, request):
        
        refresh_token = request.data.get('refresh_token')

        if not refresh_token:
            return Response(
                {"error": "Refresh token is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        data = {
            "client_id": settings.KEYCLOAK_CLIENT_ID,
            "client_secret": settings.KEYCLOAK_CLIENT_SECRET,
            "refresh_token": refresh_token
        }

        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }

        keycloak_logout_url = f"{settings.KEYCLOAK_URL}/realms/{settings.KEYCLOAK_REALM}/protocol/openid-connect/logout"

        try:
            response = requests.post(keycloak_logout_url, data=data, headers=headers, timeout=5)

            if response.status_code in [200, 204]:
                return Response(
                    {"message": "Logged out successfully!"},
                    status=status.HTTP_200_OK
                )

            elif response.status_code == 400:
                try:
                    details = response.json()
                except ValueError:
                    details = {"detail": "Bad Request"}
                return Response(
                    {"error": "Invalid refresh token or bad request.", "details": details},
                    status=status.HTTP_400_BAD_REQUEST
                )

            elif response.status_code == 401:
                try:
                    details = response.json()
                except ValueError:
                    details = {"detail": "Unauthorized"}
                return Response(
                    {"error": "Unauthorized. Check client credentials.", "details": details},
                    status=status.HTTP_401_UNAUTHORIZED
                )

            else:
                return Response(
                    {
                        "error": "Unexpected error during logout.",
                        "status_code": response.status_code,
                        "details": response.text
                    },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

        except requests.exceptions.Timeout:
            return Response(
                {"error": "Logout request timed out. Please try again later."},
                status=status.HTTP_504_GATEWAY_TIMEOUT
            )

        except requests.exceptions.ConnectionError:
            return Response(
                {"error": "Unable to connect to authentication server."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )

        except requests.exceptions.RequestException as e:
            return Response(
                {"error": "An error occurred while processing logout.", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
class AccountDetailsView(APIView):
    def get(self, request):
        user = request.user
        serializer = CustomUserSerializer(user)
        return Response(serializer.data)

    def put(self, request):
        user = request.user
        serializer = CustomUserSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Account details updated successfully."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
