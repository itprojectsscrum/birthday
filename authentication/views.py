import jwt
# from django.middleware import csrf

from rest_framework import status, permissions
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework_simplejwt.tokens import RefreshToken

from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.sites.shortcuts import get_current_site
from django.conf import settings
from django.urls import reverse
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from rest_framework_simplejwt.views import TokenRefreshView

from .models import User
from .renderers import UserRenderer
from .serializers import (
    RegistrationSerializer,
    EmailVerificationSerializer,
    LoginSerializer,
    ResetPasswordEmailRequestSerializer,
    SetNewPasswordSerializer,
    LogoutSerializer, CookieTokenRefreshSerializer,
)
from .utils import Util


class RegistrationAPIView(GenericAPIView):
    """
    Регистация нового пользователя
    """
    permission_classes = (AllowAny,)
    serializer_class = RegistrationSerializer
    renderer_classes = (UserRenderer,)

    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user_data = serializer.data
        user = User.objects.get(email=user_data['email'])
        token = RefreshToken.for_user(user).access_token
        current_site = get_current_site(request).domain
        relative_link = reverse('email-verify')
        absurl = f'http://{current_site}{relative_link}?token={str(token)}'
        email_body = f'Hello. Use link below to verify your email \n{absurl}'
        data = {
            'email_subject': 'Verify your email',
            'email_body': email_body,
            'to_email': user.email
        }
        Util.send_email(data)
        return Response(user_data, status=status.HTTP_201_CREATED)


class VerifyEmailAPIView(GenericAPIView):
    """
    Верификация нового пользователя
    """
    serializer_class = EmailVerificationSerializer

    def get(self, request):
        token = request.GET.get('token')
        try:
            payload = jwt.decode(jwt=token, key=settings.SECRET_KEY, algorithms=['HS256'])
            user = User.objects.get(id=payload['user_id'])
            if not user.is_verified:
                user.is_verified = True
                user.save()
            return Response({'email': 'Successfully activated'}, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError:
            return Response({'error': 'Activation Expired'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError:
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)


class LoginAPIView(GenericAPIView):
    """
    Авторизация пользователя
    """
    serializer_class = LoginSerializer

    def post(self, request):

        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        protocol = request.build_absolute_uri(request.get_host()).split('/')[0]

        response = Response()
        tokens = serializer.data['tokens']
        response.set_cookie(
            key=settings.SIMPLE_JWT['AUTH_COOKIE'],
            value=tokens["refresh"],
            # domain=settings.SIMPLE_JWT['AUTH_COOKIE_DOMAIN'],
            expires=settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'],
            secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],  # True if protocol == 'https:' else False,
            # httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
            samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE'],
            max_age=3600 * 24 * 365,
        )
        # csrf.get_token(request)
        response.data = {"Success": "Login successfully", "access_token": tokens['access']}
        response.status_code = status.HTTP_200_OK
        return response


class RequestPasswordResetEmail(GenericAPIView):
    """
        Отправка Email пользователю для подтверждения запроса на смену пароля
    """
    serializer_class = ResetPasswordEmailRequestSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        email = request.data['email']

        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            current_site = get_current_site(request=request).domain
            relative_link = reverse('password-reset-confirm', kwargs={'uidb64': uidb64, 'token': token})

            absurl = 'http://' + current_site + relative_link
            email_body = 'Hello,\n Use link below to reset your password \n' + absurl
            data = {'email_body': email_body, 'to_email': user.email,
                    'email_subject': 'Reset your password'}
            Util.send_email(data)
        return Response({'success': 'We have sent you a link to reset your password'}, status=status.HTTP_200_OK)


class PasswordTokenCheckAPIView(GenericAPIView):
    """
        Подтверждение Email пользователя на смену пароля
    """
    serializer_class = SetNewPasswordSerializer

    def get(self, request, uidb64, token):

        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'error': 'Token is not valid, please request a new one'})

            return Response({'success': True, 'messagee': 'Creantails Vaild', 'uidb64': uidb64})
        except DjangoUnicodeDecodeError as e:
            return Response({'error': 'Token is not valid, please request a new one'})


class SetNewPasswordAPIView(GenericAPIView):
    """
       Установка нового пароля
    """
    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'success': True, 'message': 'Password reset success'}, status=status.HTTP_200_OK)


class LogoutAPIView(GenericAPIView):
    """
       Выход из профиля пользователя

       Занесение refresh token в blacklist
    """
    serializer_class = LogoutSerializer

    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request):

        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(status=status.HTTP_204_NO_CONTENT)


class CookieTokenRefreshView(TokenRefreshView):
    serializer_class = CookieTokenRefreshSerializer

    def finalize_response(self, request, response, *args, **kwargs):
        if response.data.get('refresh'):
            response.set_cookie(
                key=settings.SIMPLE_JWT['AUTH_COOKIE'],
                value=response.data['refresh'],
                # domain=settings.SIMPLE_JWT['AUTH_COOKIE_DOMAIN'],
                max_age=3600 * 24 * 365,
                expires=settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'],
                secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],  # True if protocol == 'https:' else False,
                # httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
                samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE'],
            )
            del response.data['refresh']
        return super().finalize_response(request, response, *args, **kwargs)


