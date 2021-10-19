from rest_framework_simplejwt.authentication import JWTAuthentication
from django.conf import settings

from rest_framework.authentication import CSRFCheck
from rest_framework import exceptions


# def enforce_csrf(request):
#     check = CSRFCheck()
#     check.process_request(request)
#     reason = check.process_view(request, None, (), {})
#     if reason:
#         raise exceptions.PermissionDenied('CSRF Failed: %s' % reason)


class CustomAuthentication(JWTAuthentication):
    """
    Extend the TokenAuthentication class to support cookie based authentication
    """
    def authenticate(self, request):
        # Check if 'auth_token' is in the request cookies.
        # Give precedence to 'Authorization' header.
        if 'auth_token' in request.COOKIES and \
                        'HTTP_AUTHORIZATION' not in request.META:
            return self.authenticate_credentials(
                request.COOKIES.get('auth_token').encode("utf-8")
            )
        return super().authenticate(request)
