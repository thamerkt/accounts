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
from .util import get_user_attributes,initialize_registration_session
import pika
from logging import getLogger
from django.utils import timezone
from rest_framework.permissions import IsAdminUser
import threading
class UserSuspendView(APIView):
    """
    API endpoint to suspend/unsuspend users
    Only accessible by admin users.
    """
    permission_classes = [AllowAny]

    def post(self, request, user_id):
        try:
            # Use keycloak_id for lookup
            user = CustomUser.objects.get(keycloak_id=user_id)
            action = request.data.get('action', 'suspend')  # 'suspend' or 'unsuspend'

            if action == 'suspend':
                user.is_suspended = True
                user.suspended_at = timezone.now()
                message = f"User {user.email} has been suspended"
                event_type = 'user.suspended'
            else:
                user.is_suspended = False
                user.suspended_at = None
                message = f"User {user.email} has been unsuspended"
                event_type = 'user.unsuspended'
            
            user.save()

            # Publish to RabbitMQ
            self.publish_rabbitmq_event(event_type, user.email)

            return Response({"message": message}, status=status.HTTP_200_OK)
        
        except CustomUser.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": f"Unexpected error: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def publish_rabbitmq_event(self, event_type, email):
        try:
            # Establish connection
            connection = pika.BlockingConnection(
                pika.ConnectionParameters(
                    host='rabbitmq.railway.internal',
                    port=15672,
                    heartbeat=600,  # Optional: helps keep connection alive
                    blocked_connection_timeout=300  # Optional: avoid hangs
                )
            )
            channel = connection.channel()

            # Declare exchange
            exchange_name = 'user_events'
            channel.exchange_declare(exchange=exchange_name, exchange_type='topic', durable=True)

            # Prepare message
            message = {
                'event': event_type,
                'payload': {
                    'email': email
                }
            }

            # Publish with persistence
            channel.basic_publish(
                exchange=exchange_name,
                routing_key=event_type,
                body=json.dumps(message),
                properties=pika.BasicProperties(
                    delivery_mode=2  # Make message persistent
                )
            )
        except Exception as e:
            # Log or handle RabbitMQ errors (optional)
            print(f"Failed to publish RabbitMQ message: {e}")
        finally:
            if 'connection' in locals() and connection.is_open:
                connection.close()



class ActiveUsersView(APIView):
    """
    API endpoint to list all active (not suspended) users.
    Only accessible by admin users.
    """
    permission_classes = [AllowAny]

    def get(self, request):
        active_users = CustomUser.objects.filter(is_suspended=False)
        serializer = CustomUserSerializer(active_users, many=True)
        data = serializer.data
        for user in data:
            user.pop('password', None)
        return Response(data, status=status.HTTP_200_OK)

class SuspendedUsersView(APIView):
    """
    API endpoint to list all suspended users and automatically remove those suspended for more than 30 days.
    Only accessible by admin users.
    """
    permission_classes = [AllowAny]

    def get(self, request):
        # Get all suspended users
        suspended_users = CustomUser.objects.filter(is_suspended=True)
        removed_users = []
        still_suspended = []

        for user in suspended_users:
            # If user has been suspended for more than 30 days, delete the user
            # We'll use date_joined as a proxy for suspension date if no dedicated field
            # In a real app, you should have a 'suspended_at' field
            suspended_since = user.date_joined  # Replace with user.suspended_at if available
            if (timezone.now() - suspended_since).days > 30:
                removed_users.append({
                    "id": user.id,
                    "email": user.email,
                    "suspended_since": suspended_since,
                })
                user.delete()
            else:
                still_suspended.append({
                    "id": user.id,
                    "email": user.email,
                    "suspended_since": suspended_since,
                })

        return Response({
            "removed_users": removed_users,
            "still_suspended": still_suspended,
        }, status=status.HTTP_200_OK)

class UserListView(APIView):
    """
    API endpoint to get all users (excluding password field).
    """
    permission_classes = [AllowAny]

    def get(self, request):
        users = CustomUser.objects.all()
        serializer = CustomUserSerializer(users, many=True)
        data = serializer.data
        for user in data:
            user.pop('password', None)
        return Response(data, status=status.HTTP_200_OK)

class UserDetailView(APIView):
    """
    Retrieve a single user by ID (excluding password).
    """
    permission_classes = [AllowAny]

    def get(self, request, keycloak_id):
        try:
            user = CustomUser.objects.get(keycloak_id=keycloak_id)
        except CustomUser.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        serializer = CustomUserSerializer(user)
        data = serializer.data
        data.pop('password', None)
        return Response(data, status=status.HTTP_200_OK)

class UserUpdateView(APIView):
    """
    Update a user by Keycloak ID.
    """
    permission_classes = [AllowAny]

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
    Delete a user by ID.
    """
    permission_classes = [AllowAny]

    def delete(self, request, pk):
        try:
            user = CustomUser.objects.get(pk=pk)
        except CustomUser.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        user.delete()
        return Response({"message": "User deleted successfully."}, status=status.HTTP_204_NO_CONTENT)


SECRET_KEY = 'your-secret-key'
from django.http import JsonResponse
from django.conf import settings
import jwt  # This is PyJWT
from jwt import InvalidTokenError


from .util import create_keycloak_user,get_keycloak_admin_token,get_keycloak_user_id,login_user,assign_role_to_user,revoke_user_sessions,generate_and_store_otp,get_keycloak_user_info,add_user_to_keycloak
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

import json
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from rest_framework.views import APIView
from google.oauth2 import id_token
import requests  # Standard requests library
from google.auth.transport import requests as google_requests

import json
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from rest_framework.views import APIView
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests  # Renaming to avoid conflict
import os
class GoogleAuth(APIView):
    
    @csrf_exempt
    def post(self, request):
        try:
            # Extract the JWT credential from the request body
            data = json.loads(request.body)
            credential = data.get('credential')  # Extract the JWT credential

            if not credential:
                return JsonResponse({'error': 'JWT credential is required'}, status=400)

            # Verify the JWT credential
            try:
                # Replace with your Google Client ID
                client_id = os.environ.get('GOOGLE_CLIENT_ID')

                # Use google_requests.Request() instead of requests.Request()
                id_info = id_token.verify_oauth2_token(credential, google_requests.Request(), client_id)

                # Extract user information from the JWT payload
                email = id_info.get('email')
                first_name = id_info.get('given_name', '')
                last_name = id_info.get('family_name', '')

                # Add the user to Keycloak (if applicable)
                try:
                    userdata = add_user_to_keycloak(email, first_name, last_name)
                    user_id=get_keycloak_user_id(email)
                    return JsonResponse({'message': 'User authenticated and added to Keycloak', 'userdata': userdata,'user':user_id})
                except Exception as e:
                    return JsonResponse({'error': f'Keycloak error: {str(e)}'}, status=500)

            except ValueError as e:
                # Handle JWT verification errors
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
                userdata = add_user_to_keycloak(email, first_name, last_name)
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

import requests
class VerifyOTPView(APIView):
    permission_classes = [AllowAny]
    

    def post(self, request):
        otp = request.data.get("otp")
        redis_client = redis.StrictRedis(host='host.docker.internal', port=6379, db=0, decode_responses=True)
        keycloak_token = get_keycloak_admin_token()

        # Get the user ID from the request
        user_id = request.data.get("user_id")

        # Fetch user info from Keycloak using the user_id and token
        user_info = get_keycloak_user_info(user_id, keycloak_token)

        if not user_info:
            return Response({"error": "Failed to fetch user info from Keycloak"}, status=status.HTTP_400_BAD_REQUEST)
        
        # Get the email from the user info
        email = user_info.get("email")
        if not email:
            return Response({"error": "Email not found in Keycloak user info"}, status=status.HTTP_400_BAD_REQUEST)

        # Attempt to get the OTP from Redis (with email as key)
        redis_otp = cache.get(f"otp:{email}")
        
        if not redis_otp:
            return Response({"error": f"OTP has expired or does not exist."}, status=status.HTTP_400_BAD_REQUEST)
        
        # Check if the OTP matches
        if redis_otp != otp:
            return Response({"error": f"Invalid OTP "}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            # Find the user in your database using the email
            user = CustomUser.objects.get(email=email)

            # Mark the user as active and clear the OTP field
            user.is_active = True
            user.otp = None
            user.keycloak_id = user_id  # Set the Keycloak user ID to the CustomUser model
            user.save()

            # Now update the Keycloak user to mark email as verified
            url = f"{settings.KEYCLOAK_URL}/admin/realms/{settings.KEYCLOAK_REALM}/users/{user_id}"
            headers = {
                "Authorization": f"Bearer {keycloak_token}",
                "Content-Type": "application/json"
            }
            data = {"emailVerified": True}  # Mark the email as verified in Keycloak

            response = requests.put(url, json=data, headers=headers)

            if response.status_code != 204:
                return Response({"error": "Failed to update Keycloak user"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            # OTP verification was successful
            return Response({"message": "Email verified successfully!"}, status=status.HTTP_200_OK)

        except CustomUser.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
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
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = CustomUserSerializer(data=request.data)
        data = request.data

        if serializer.is_valid():
            email = serializer.validated_data.get("email")
            password = serializer.validated_data.get("password")
            username = data.get("username")
            role_type = data.get("role")

            otp = generate_and_store_otp(email)
            user = serializer.save(is_active=False, otp=otp, password=make_password(password))

            # Send OTP via email
            send_mail(
                subject="Email Verification OTP",
                message=f"Your OTP code for email verification is: {otp}",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[email],
                fail_silently=False,
            )

            # ➡️ Create or Update user in Keycloak
            result = create_keycloak_user(username, email, password)

            if result["success"]:
                # Get Keycloak user ID
                keycloak_user_id = get_keycloak_user_id(email)

                # Save Keycloak ID locally
                user.keycloak_id = keycloak_user_id
                user.save()

                # Assign role
                assign_role_to_user(keycloak_user_id, role_type)

                # ✅ Initialize session attribute if not exists / Get existing attribute
                user_attributes = get_user_attributes(keycloak_user_id)
                if not user_attributes.get("registrationProgress"):
                    initialize_registration_session(keycloak_user_id, "step1")
                else:
                    print(f"User already has session attributes: {user_attributes}")

                # Auto-login after registration
                login_result = login_user(email, password)

                if login_result["success"]:
                    return Response(
                        {"message": "User registered and logged in successfully!", "token": login_result["token"], "user_id": keycloak_user_id},
                        status=status.HTTP_201_CREATED
                    )
                else:
                    return Response({"message": "User registered but login failed", "error": login_result["message"]}, status=400)

            return Response(result, status=400)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")

        if not email or not password:
            return Response({"error": "Email and password are required."}, status=status.HTTP_400_BAD_REQUEST)

        # Keycloak Login
        login_result = login_user(email, password)

        if not login_result.get("success"):
            return Response({"error": login_result.get("message", "Login failed.")}, status=status.HTTP_400_BAD_REQUEST)

        token = login_result["token"]
        accesstoken = token["access_token"]

        # Decode JWT token
        try:
            decoded = jwt.decode(
                accesstoken,
                settings.YOUR_KEYCLOAK_PUBLIC_KEY,
                algorithms=["RS256"],
                options={"verify_aud": False},
            )
        except InvalidTokenError as e:
            return Response({"error": f"Token is invalid: {str(e)}"}, status=status.HTTP_401_UNAUTHORIZED)

        roles = decoded.get("realm_access", {}).get("roles", [])
        username = decoded.get("preferred_username", "unknown")

        # Get Keycloak user ID
        keycloak_id = get_keycloak_user_id(email)

        # Fetch & Update CustomUser data
        try:
            user_obj = CustomUser.objects.get(email=email)

            # Update keycloak_id if null
            if not user_obj.keycloak_id and keycloak_id:
                user_obj.keycloak_id = keycloak_id
                user_obj.save()

            user_data = {
                "email": user_obj.email,
                "is_verified": user_obj.is_verified,
                "is_suspended": user_obj.is_suspended,
                "date_joined": user_obj.date_joined
            }
        except CustomUser.DoesNotExist:
            user_data = {
                "email": email,
                "is_verified": False,
                "is_suspended": False,
                "date_joined": None
            }

        # Optionally revoke old sessions
        if keycloak_id:
            revoke_user_sessions(keycloak_id)

        return Response({
            "token": token,
            "user_id": keycloak_id,
            "user": {
                "username": username,
                "roles": roles,
                **user_data
            }
        }, status=status.HTTP_200_OK)
def process_identity_verification(ch, method, properties, body):
    try:
        message = json.loads(body)
        keycloak_id = message.get("keycloak_user")

        if not keycloak_id:
            print("Received message missing 'keycloak_user_id'")
            return

        try:
            user = CustomUser.objects.get(keycloak_id=keycloak_id)
            if not user.is_verified:
                user.is_verified = True
                user.save()

                # Send email notification
                send_mail(
                    subject="Your Account is Verified",
                    message="Congratulations! Your account has been successfully verified.",
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[user.email],
                    fail_silently=False,
                )
                print(f"User {user.email} marked as verified and notified.")
            else:
                print(f"User {user.email} already verified.")
        except CustomUser.DoesNotExist:
            print(f"No user found with keycloak_id: {keycloak_id}")

    except json.JSONDecodeError as e:
        print(f"Failed to decode message: {e}")
    except Exception as e:
        print(f"Error processing message: {e}")

def start_identity_verification_consumer():
    connection_params = pika.ConnectionParameters(
        host='host.docker.internal',  # Adjust based on your Docker setup
        port=5672,
        virtual_host='/',
        credentials=pika.PlainCredentials('guest', 'guest')  # Adjust if you use auth
    )
    connection = pika.BlockingConnection(connection_params)
    channel = connection.channel()

    channel.queue_declare(queue='identity_verification_queue', durable=True)

    channel.basic_consume(
        queue='identity_verification_queue',
        on_message_callback=process_identity_verification,
        auto_ack=True
    )

    print(" [*] Waiting for identity verification messages...")
    channel.start_consuming()

def start_consumer_thread():
    print("start_consumer_thread() called")
    consumer_thread = threading.Thread(target=start_identity_verification_consumer, daemon=True)
    consumer_thread.start()
    print("Consumer thread started")

class Role(APIView):
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

class VerifyTokenView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        # Extract token from headers
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return Response({"error": "Authorization token is missing or invalid"}, status=status.HTTP_401_UNAUTHORIZED)
        
        token = auth_header.split(" ")[1]  # Extract the token
        otp = request.data.get('otp')  # Extract OTP from request body

        if not otp:
            return Response({"error": "OTP is required"}, status=status.HTTP_400_BAD_REQUEST)

        # Get user info from Keycloak
        response = requests.post(
            f"{settings.KEYCLOAK_URL}/userinfo",
            headers={"Authorization": f"Bearer {token}"}
        )

        if response.status_code != 200:
            return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

        user_info = response.json()
        email = user_info.get("email")  # Extract email from userinfo

        if not email:
            return Response({"error": "Email not found in token"}, status=status.HTTP_400_BAD_REQUEST)

        # Verify OTP
        if not self.verify_otp(email, otp):
            return Response({"error": "Invalid OTP"}, status=status.HTTP_401_UNAUTHORIZED)

        return Response({"message": "Token and OTP verified successfully", "email": email}, status=status.HTTP_200_OK)

    def verify_otp(self, email, otp):
        redis_client = redis.StrictRedis.from_url(settings.CACHES["default"]["LOCATION"], decode_responses=True)

        stored_otp = redis_client.get(f"otp:{email}")  # Retrieve OTP from Redis
        if stored_otp and stored_otp == otp:
            redis_client.delete(f"otp:{email}")  # Delete OTP after successful verification
            return True
        return False

class PasswordResetView(APIView):
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

        keycloak_logout_url = f"{settings.KEYCLOAK_URL}/realms/{settings.KEYCLOAK_REALM}/protocol/openid-connect/logout"

        try:
            response = requests.post(keycloak_logout_url, data=data, timeout=5)

            if response.status_code in [200, 204]:
                return Response(
                    {"message": "Logged out successfully!"},
                    status=status.HTTP_200_OK
                )
            elif response.status_code == 400:
                return Response(
                    {"error": "Invalid refresh token or bad request.", "details": response.json()},
                    status=status.HTTP_400_BAD_REQUEST
                )
            elif response.status_code == 401:
                return Response(
                    {"error": "Unauthorized. Check client credentials.", "details": response.json()},
                    status=status.HTTP_401_UNAUTHORIZED
                )
            else:
                print(f"Unexpected logout response: {response.status_code} - {response.text}")
                return Response(
                    {"error": "Unexpected error during logout.", "details": response.text},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

        except requests.exceptions.Timeout:
            print("Keycloak logout request timed out.")
            return Response(
                {"error": "Logout request timed out. Please try again later."},
                status=status.HTTP_504_GATEWAY_TIMEOUT
            )

        except requests.exceptions.ConnectionError as e:
            print(f"Connection error during logout: {str(e)}")
            return Response(
                {"error": "Unable to connect to authentication server."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )

        except requests.exceptions.RequestException as e:
            print(f"Request exception during logout: {str(e)}")
            return Response(
                {"error": "An error occurred while processing logout."},
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
