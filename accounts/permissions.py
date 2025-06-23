from rest_framework.permissions import BasePermission

class HasKeycloakRole(BasePermission):
    required_role = None  # Should be overridden by subclasses

    def has_permission(self, request, view):
        user_roles = getattr(request.user, "roles", [])
        return self.check_permission(user_roles)

    def check_permission(self, user_roles):
        if not self.required_role:
            return False
        return self.required_role in user_roles


class IsAdmin(HasKeycloakRole):
    # Admins are allowed if they have the required role OR no roles at all
    required_role = "admin"

    def check_permission(self, user_roles):
        if not user_roles:
            return True
        return self.required_role in user_roles


class IsClient(HasKeycloakRole):
    required_role = "client"

class IsPartner(HasKeycloakRole):
    required_role = "partner"

class IsIndividualManager(HasKeycloakRole):
    required_role = "equipment_manager_individual"

class IsCompanyManager(HasKeycloakRole):
    required_role = "equipment_manager_company"


class AllowAnyRole(BasePermission):
    def has_permission(self, request, view):
        user_roles = getattr(request.user, "roles", [])
        # Allow if roles are empty
        return not user_roles or True  # ← Simplified: always returns True
