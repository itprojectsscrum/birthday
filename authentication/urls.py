from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from authentication.views import (
    RegistrationAPIView,
    VerifyEmailAPIView,
    LoginAPIView,
    PasswordTokenCheckAPIView,
    RequestPasswordResetEmail,
    SetNewPasswordAPIView, LogoutAPIView,
    CookieTokenRefreshView,
)

urlpatterns = [
    path('register/', RegistrationAPIView.as_view(), name='register'),
    path('email-verify/', VerifyEmailAPIView.as_view(), name='email-verify'),
    path('login/', LoginAPIView.as_view(), name='login'),
    path('logout/', LogoutAPIView.as_view(), name='logout'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('password-reset-email/', RequestPasswordResetEmail.as_view(), name='password-reset-email'),
    path('password-reset/<uidb64>/<token>/', PasswordTokenCheckAPIView.as_view(), name='password-reset-confirm'),
    path('password-reset-complete', SetNewPasswordAPIView.as_view(), name='password-reset-complete'),
]
