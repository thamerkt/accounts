from django.urls import include, path
from rest_framework.routers import DefaultRouter
from .views import (
    RegisterView, LoginView, VerifyOTPView, PasswordResetRequestView,
    PasswordResetView, LogoutView, GoogleAuth,Role,FacebookAuth,UserListView,
    UserSuspendView, SuspendedUsersView, ActiveUsersView,get_user_progress,update_registration_progress,UserUpdateView,UserDetailView
)

from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from . import views
router = DefaultRouter()
from . import util


urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),

    path("token/", TokenObtainPairView.as_view(), name="get_token"),
    path('verify-otp/', VerifyOTPView.as_view(), name='verify-otp'),
    path('password-reset-request/', PasswordResetRequestView.as_view(), name='password-reset-request'),
    path('reset-password/<str:uidb64>/<str:token>/', PasswordResetView.as_view(), name='password-reset'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('auth/google/', GoogleAuth.as_view(), name='google_auth'),
    path('assign/role/',Role.as_view(),name='assign_role'),
    path('auth/facebook/', FacebookAuth.as_view(), name='facebook_auth'),
    path('users/', UserListView.as_view(), name='user_list'),
    path('users/<str:user_id>/suspend/', UserSuspendView.as_view(), name='user-suspend'),
    path('users/suspended/', SuspendedUsersView.as_view(), name='suspended-users'),
    path('users/active/', ActiveUsersView.as_view(), name='active-users'),
    path('get-user-progress/', get_user_progress, name='get-user-progress'),
    path('update-user-progress/', update_registration_progress, name='update-user-progress'),
    path('update-user/<uuid:keycloak_id>/', UserUpdateView.as_view(), name='user-update'),
    path('user-details/<str:keycloak_id>/', UserDetailView.as_view(), name='user-details')
]


urlpatterns += router.urls
