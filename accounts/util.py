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
from django.core.cache import cache

import requests
from django.conf import settings  # assuming you're using Django

def get_keycloak_admin_token():
    cache_key = "keycloak_admin_token"
    token = cache.get(cache_key)
    if token:
        return token

    url = f"{settings.KEYCLOAK_URL}/realms/{settings.KEYCLOAK_REALM}/protocol/openid-connect/token"
    data = {
        "client_id": settings.KEYCLOAK_CLIENT_ID,
        "client_secret": settings.KEYCLOAK_CLIENT_SECRET,
        "username": settings.KEYCLOAK_ADMIN_USERNAME,
        "password": settings.KEYCLOAK_ADMIN_PASSWORD,
        "grant_type": "password"
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    response = requests.post(url, data=data, headers=headers)
    if response.ok:
        token = response.json().get("access_token")
        # Cache the token, assume expires in 5 minutes (adjust if needed)
        # You can also parse `expires_in` from response if available
        cache.set(cache_key, token, timeout=300)  # cache 5 min
        return token

    raise Exception(f"[Token Error] {response.status_code}: {response.text}")

def add_user_to_keycloak(email, first_name, last_name,role):
    access_token = get_keycloak_admin_token()

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
    user_exists = bool(users)

    if user_exists:
        user_id = users[0]["id"]
        print("User already exists. No update performed.")
    else:
        # 2. Create new user
        user_data = {
            "username": email,
            "email": email,
            "firstName": first_name,
            "lastName": last_name,
            "enabled": True,
            "emailVerified": True,
            "attributes": {
                "is_verified": ["false"],
                "is_suspended": ["false"]
            }
        }

        create_response = requests.post(base_url, json=user_data, headers=headers)
        if not create_response.ok:
            raise Exception(f"[User Creation Failed] {create_response.status_code}: {create_response.text}")
        print("User added to Keycloak successfully.")

        # Get new user ID
        search_response = requests.get(f"{base_url}?email={email}", headers=headers)
        user_id = search_response.json()[0]["id"]

        # Assign default role
        assign_role_to_user(user_id, role)

    # 3. Fetch user details and attributes
    user_details_response = requests.get(f"{base_url}/{user_id}", headers=headers)
    if not user_details_response.ok:
        raise Exception(f"[Fetch User Failed] {user_details_response.status_code}: {user_details_response.text}")
    
    user_details = user_details_response.json()
    attributes = user_details.get("attributes", {})

    # 4. Fetch user realm roles
    roles_response = requests.get(
        f"{base_url}/{user_id}/role-mappings/realm",
        headers=headers
    )
    if not roles_response.ok:
        raise Exception(f"[Fetch Roles Failed] {roles_response.status_code}: {roles_response.text}")
    
    role_names = [role["name"] for role in roles_response.json()]

    return {
        "access_token": access_token,
        "user_id": user_id,
        "first_name": user_details.get("firstName", first_name),
        "last_name": user_details.get("lastName", last_name),
        "user_exists": user_exists,
        "is_verified": attributes.get("is_verified", ["false"])[0],
        "is_suspended": attributes.get("is_suspended", ["false"])[0],
        "roles": role_names
    }

def create_keycloak_user(username, email, password):
    token = get_keycloak_admin_token()
    url = f"{settings.KEYCLOAK_URL}/admin/realms/{settings.KEYCLOAK_REALM}/users"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    # Generate default first and last names if not provided
    first_name = "User"
    last_name = username.split('@')[0] if '@' in username else "Auto"

    data = {
        "username": username,
        "email": email,
        "firstName": first_name,
        "lastName": last_name,
        "enabled": True,
        "emailVerified": False,
        "attributes": {
            "is_verified": ["false"],
            "is_suspended": ["false"]
        },
        "credentials": [{
            "type": "password",
            "value": password,
            "temporary": False
        }]
    }

    print("Payload being sent to Keycloak:", data)
    response = requests.post(url, json=data, headers=headers)
    print('response', response)

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
        "client_id": settings.KEYCLOAK_CLIENT_ID,
        "client_secret": settings.KEYCLOAK_CLIENT_SECRET,
        "grant_type": "password",
        "username": email,
        "password": password
    }
    
    response = requests.post(
        f"{settings.KEYCLOAK_URL}/realms/{settings.KEYCLOAK_REALM}/protocol/openid-connect/token",
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )

    if response.status_code == 200:
        return {"success": True, "token": response.json()}
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

def generate_and_store_otp(user_id):
    """
    Generate and store a 6-digit OTP in Redis using the user_id as key.
    """
    otp = str(random.randint(100000, 999999))

    try:
        # Save OTP in Redis under key 'otp:<user_id>' for 5 minutes
        cache.set(f"otp:{user_id}", otp, timeout=300)
        return otp
    except Exception as e:
        print(f"❌ Redis error while storing OTP for user_id {user_id}: {e}")
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

def update_keycloak_user_attributes(user_id, token, attributes):
    """
    Update custom attributes of a Keycloak user using their user ID.
    """
    url = f"{settings.KEYCLOAK_URL}/admin/realms/{settings.KEYCLOAK_REALM}/users/{user_id}"

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    try:
        # Fetch existing user data
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            print(f"❌ Failed to fetch user before update: {response.status_code} - {response.text}")
            return False

        user_data = response.json()

        # Merge/override attributes
        current_attrs = user_data.get("attributes", {})
        current_attrs.update(attributes)
        user_data["attributes"] = current_attrs

        # PUT updated user object
        put_response = requests.put(url, headers=headers, json=user_data)
        if put_response.status_code in [200, 204]:
            print(f"✅ User {user_id} attributes updated successfully.")
            return True
        else:
            print(f"❌ Failed to update user: {put_response.status_code} - {put_response.text}")
            return False

    except Exception as e:
        print(f"❌ Exception while updating user {user_id}: {str(e)}")
        return False



def get_all_keycloak_users():
    """
    Fetch all users from Keycloak realm.
    """
    token=get_keycloak_admin_token()
    print("to",token)
    url = f"{settings.KEYCLOAK_URL}/admin/realms/{settings.KEYCLOAK_REALM}/users"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"❌ Failed to fetch users: {response.status_code} - {response.text}")


def delete_keycloak_user(user_id, admin_token):
    """
    Delete a Keycloak user by their user ID.
    """
    url = f"{settings.KEYCLOAK_URL}/admin/realms/{settings.KEYCLOAK_REALM}/users/{user_id}"
    headers = {
        "Authorization": f"Bearer {admin_token}",
        "Content-Type": "application/json"
    }

    response = requests.delete(url, headers=headers)
    if response.status_code == 204:
        print(f"✅ User {user_id} deleted successfully.")
    else:
        raise Exception(f"❌ Failed to delete user: {response.status_code} - {response.text}")
def verify_user_email_by_id(user_id):
    """
    Set 'emailVerified' to True for a given user by user_id and return success status.
    """
    try:
        token = get_keycloak_admin_token()

        url = f"{settings.KEYCLOAK_URL}/admin/realms/{settings.KEYCLOAK_REALM}/users/{user_id}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

        # Get the full user object first
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            return {"success": False, "message": "Failed to fetch user details."}

        user_data = response.json()
        user_data["emailVerified"] = True

        # PUT updated user data
        update_response = requests.put(url, headers=headers, json=user_data)
        if update_response.status_code in [200, 204]:
            return {"success": True, "message": "Email verified successfully."}
        else:
            return {
                "success": False,
                "message": f"Failed to update email verification: {update_response.status_code} - {update_response.text}"
            }

    except Exception as e:
        return {"success": False, "message": f"Exception occurred: {str(e)}"}
