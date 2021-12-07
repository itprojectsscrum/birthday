from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from authentication.views import (
    RegistrationAPIView,
    VerifyEmailAPIView,
    IsEmailVerifyAPIView,
    LoginAPIView,
    PasswordTokenCheckAPIView,
    RequestPasswordResetEmail,
    SetNewPasswordAPIView,
    LogoutAPIView,
    CookieTokenRefreshView,
    CustomTokenRefreshView,
    RepeatVerifyEmailAPIView,
    SupportEmailAPIView,
    ChangePasswordAPIView,
)

urlpatterns = [
    path('register/', RegistrationAPIView.as_view(), name='register'),
    path('email-verify/', VerifyEmailAPIView.as_view(), name='email-verify'),
    path('is-email-verify', IsEmailVerifyAPIView.as_view(), name='is_email-verify'),
    path('repeat-email-verify/', RepeatVerifyEmailAPIView.as_view(), name='repeat-email-verify'),
    path('login/', LoginAPIView.as_view(), name='login'),
    path('logout/', LogoutAPIView.as_view(), name='logout'),
    path('token/refresh/', CustomTokenRefreshView.as_view(), name='token_refresh'),
    path('password-change/', ChangePasswordAPIView.as_view(), name='password-change'),
    path('password-reset-email/', RequestPasswordResetEmail.as_view(), name='password-reset-email'),
    path('password-reset/<uidb64>/<token>/', PasswordTokenCheckAPIView.as_view(), name='password-reset-confirm'),
    path('password-reset-complete/', SetNewPasswordAPIView.as_view(), name='password-reset-complete'),
    path('support-email/', SupportEmailAPIView.as_view(), name='support-email'),
]
