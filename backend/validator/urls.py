from django.urls import path

from validator.views import (
    EmailValidatorAPIView,
)

urlpatterns = [
    path('email/', EmailValidatorAPIView.as_view(), name='email_validator'),
]
