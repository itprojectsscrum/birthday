from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from authentication.views import (
    RegistrationAPIView,
    LoginAPIView,
    PasswordTokenCheckAPIView,
    RequestPasswordResetEmail,
    SetNewPasswordAPIView,
)

urlpatterns = [
    path('register/', RegistrationAPIView.as_view(), name='register'),
    path('login/', LoginAPIView.as_view(), name='register'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('request-reset-email/', RequestPasswordResetEmail.as_view(), name='request-reset-email'),
    path('password-rest/<uidb64>/<token>/', PasswordTokenCheckAPIView.as_view(), name='password-reset-confirm'),
    path('password-rest-complete', SetNewPasswordAPIView.as_view(), name='password-reset-complete'),
]
