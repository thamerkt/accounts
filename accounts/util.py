import requests
from django.conf import settings
import random
import redis
from django.core.cache import cache

import json
from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.http import HttpResponse
import requests
from django.contrib.auth.signals import user_logged_in
from django.dispatch import receiver

from django.shortcuts import render, redirect
from django.http import HttpResponse
import requests

import requests
from django.http import HttpResponse
from django.shortcuts import redirect
from django.contrib.auth import authenticate, login


import requests
from django.conf import settings  # assuming you're using Django

def get_keycloak_admin_token():
    url = f"{settings.KEYCLOAK_URL}/realms/{settings.KEYCLOAK_REALM}/protocol/openid-connect/token"
    data = {
        "client_id": settings.KEYCLOAK_CLIENT_ID,
        "client_secret": settings.KEYCLOAK_CLIENT_SECRET,
        "username": settings.KEYCLOAK_ADMIN_USERNAME,
        "password": settings.KEYCLOAK_ADMIN_PASSWORD,
        "grant_type": "password"
    }
    print('data',data)
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    response = requests.post(url, data=data, headers=headers)
    if response.ok:
        return response.json().get("access_token")
    raise Exception(f"[Token Error] {response.status_code}: {response.text}")

def add_user_to_keycloak(email, first_name, last_name):
    access_token = get_keycloak_admin_token()

    user_data = {
        "username": email,
        "email": email,
        "firstName": first_name,
        "lastName": last_name,
        "enabled": True,
        "emailVerified": True,
    }

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    base_url = f"{settings.KEYCLOAK_URL}/admin/realms/{settings.KEYCLOAK_REALM}/users"

    # 1. Check if user exists
    search_response = requests.get(f"{base_url}?email={email}", headers=headers)
    if not search_response.ok:
        raise Exception(f"[User Lookup Failed] {search_response.status_code}: {search_response.text}")

    users = search_response.json()
    user_exists = False

    if users:
        # 2. User exists — update instead of create
        user_exists = True
        user_id = users[0]["id"]
        update_url = f"{base_url}/{user_id}"
        update_response = requests.put(update_url, json=user_data, headers=headers)

        if not update_response.ok:
            raise Exception(f"[User Update Failed] {update_response.status_code}: {update_response.text}")
        print("User already exists. Info updated.")
    else:
        # 3. User doesn't exist — create new user
        create_response = requests.post(base_url, json=user_data, headers=headers)
        if not create_response.ok:
            raise Exception(f"[User Creation Failed] {create_response.status_code}: {create_response.text}")
        print("User added to Keycloak successfully.")
        # Get newly created user ID
        search_response = requests.get(f"{base_url}?email={email}", headers=headers)
        user_id = search_response.json()[0]["id"]

    assign_role_to_user(user_id, "customer")

    return {
        "access_token": access_token,
        "user_id": user_id,
        "first_name": first_name,
        "last_name": last_name,
        "user_exists": user_exists
    }


def create_keycloak_user(username, email, password):
    token = get_keycloak_admin_token()
    url = f"{settings.KEYCLOAK_URL}/admin/realms/{settings.KEYCLOAK_REALM}/users"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    data = {
        "username": username,
        "email": email,
        "enabled": True,
        "credentials": [{"type": "password", "value": password, "temporary": False}]
    }
    
    print("Payload being sent to Keycloak:", data)
    response = requests.post(url, json=data, headers=headers)
    
    if response.status_code == 201:
        return {"success": True, "message": "User created successfully"}
    else:
        return {"success": False, "message": response.text}
def get_keycloak_user_id(email):
    token = get_keycloak_admin_token()
    url = f"{settings.KEYCLOAK_URL}/admin/realms/{settings.KEYCLOAK_REALM}/users?email={email}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200 and response.json():
        return response.json()[0]["id"]  # Get first user ID matching the email
    else:
        raise Exception(f"Failed to get Keycloak user ID: {response.text}")
def login_user(email, password):
    data = {
        "client_id": settings.KEYCLOAK_CLIENT_ID,  # You should have this in settings
        "client_secret": settings.KEYCLOAK_CLIENT_SECRET,  # You should have this in settings
        "grant_type": "password",
        "username": email,
        "password": password
    }
    
    # Send a POST request to the Keycloak token endpoint
    response = requests.post(
        f"{settings.KEYCLOAK_URL}/realms/{settings.KEYCLOAK_REALM}/protocol/openid-connect/token",
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )

    if response.status_code == 200:
        return {"success": True, "token": response.json()}  # Return the access token
    else:
        return {"success": False, "message": "Invalid credentials or failed to connect to Keycloak."}
import requests
import logging
from django.conf import settings

logger = logging.getLogger(__name__)

def assign_role_to_user(user_id, role_name):
    token = get_keycloak_admin_token()
    if not token:
        raise Exception("Failed to obtain Keycloak admin token.")

    # Get all roles
    roles_url = f"{settings.KEYCLOAK_URL}/admin/realms/{settings.KEYCLOAK_REALM}/roles"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    response = requests.get(roles_url, headers=headers)
    if response.status_code != 200:
        raise Exception(f"Failed to fetch roles: {response.status_code} - {response.text}")

    available_roles = response.json()

    # Find the target role
    role_data = next((role for role in available_roles if role["name"] == role_name), None)
    if not role_data:
        raise Exception(f"Role '{role_name}' not found in Keycloak.")

    # Assign the role to the user
    assign_url = f"{settings.KEYCLOAK_URL}/admin/realms/{settings.KEYCLOAK_REALM}/users/{user_id}/role-mappings/realm"
    assign_response = requests.post(assign_url, json=[role_data], headers=headers)

    if assign_response.status_code == 204:
        logger.info(f"Role '{role_name}' successfully assigned to user {user_id}.")
        return {"success": True, "message": f"Role '{role_name}' assigned successfully."}
    else:
        raise Exception(f"Failed to assign role: {assign_response.status_code} - {assign_response.text}")
def revoke_user_sessions(user_id):
    """
    Revoke all active sessions for a user in Keycloak.
    """
    admin_token = get_keycloak_admin_token()  # Get admin access token

    url = f"{settings.KEYCLOAK_URL}/admin/realms/{settings.KEYCLOAK_REALM}/users/{user_id}/logout"
    headers = {
        "Authorization": f"Bearer {admin_token}",
        "Content-Type": "application/json"
    }

    response = requests.post(url, headers=headers)

    if response.status_code == 204:
        print(f"✅ Successfully revoked all sessions for user: {user_id}")
    else:
        print(f"❌ Failed to revoke sessions: {response.text}")

def generate_and_store_otp(email):
    # Generate a 6-digit OTP
    otp = str(random.randint(100000, 999999))

    try:
        # Store OTP for 5 minutes (300 seconds) using Django's cache system
        cache.set(f"otp:{email}", otp, timeout=300)  # 300 seconds = 5 minutes
    except Exception as e:
        # Handle any errors (such as connection issues to Redis)
        print(f"Error while connecting to Redis via cache: {e}")
        return None

    return otp
def get_keycloak_user_info(user_id, keycloak_token):
    # Fetch user info from Keycloak using the user_id
    url = f"{settings.KEYCLOAK_URL}/admin/realms/{settings.KEYCLOAK_REALM}/users/{user_id}"
    
    headers = {
        "Authorization": f"Bearer {keycloak_token}",
        "Content-Type": "application/json"
    }

    # Make the request to the Keycloak Admin API to get user details
    response = requests.get(url, headers=headers)
    
    # Check if the request was successful
    if response.status_code == 200:
        return response.json()  # Return the user info as a dictionary
    else:
        return None  # Return None if failed to fetch user info
def initialize_registration_session(user_id, initial_progress="step1"):
    token = get_keycloak_admin_token()

    # Get the full user object first
    get_url = f"{settings.KEYCLOAK_URL}/admin/realms/{settings.KEYCLOAK_REALM}/users/{user_id}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    response = requests.get(get_url, headers=headers)
    if response.status_code != 200:
        raise Exception(f"❌ Failed to fetch user before update: {response.status_code} - {response.text}")

    user_data = response.json()

    # Update attributes
    attributes = user_data.get("attributes", {})
    attributes["registrationProgress"] = [initial_progress]
    attributes["registrationData"] = ["{}"]

    user_data["attributes"] = attributes

    # PUT full user object back with updated attributes
    put_url = f"{settings.KEYCLOAK_URL}/admin/realms/{settings.KEYCLOAK_REALM}/users/{user_id}"

    put_response = requests.put(put_url, headers=headers, json=user_data)
    if put_response.status_code in [200, 204]:
        print(f"✅ Initialized session attributes for user {user_id}")
    else:
        raise Exception(f"❌ Failed to update user attributes: {put_response.status_code} - {put_response.text}")


def get_user_attributes(user_id):
    token = get_keycloak_admin_token()
    url = f"{settings.KEYCLOAK_URL}/admin/realms/{settings.KEYCLOAK_REALM}/users/{user_id}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        user_data = response.json()
        return user_data.get("attributes", {})
    else:
        raise Exception(f"❌ Failed to fetch user attributes: {response.status_code} - {response.text}")

