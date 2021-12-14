from datetime import datetime

import jwt
# from django.middleware import csrf
from drf_yasg import openapi

from rest_framework import status, permissions
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.serializers import BaseSerializer
from rest_framework_simplejwt.tokens import RefreshToken

from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.sites.shortcuts import get_current_site
from django.conf import settings
from django.urls import reverse
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from rest_framework_simplejwt.views import TokenRefreshView
from drf_yasg.utils import swagger_auto_schema

from .models import User
from .renderers import UserRenderer
from .serializers import (
    RegistrationSerializer,
    EmailVerificationSerializer,
    LoginSerializer,
    ResetPasswordEmailRequestSerializer,
    SetNewPasswordSerializer,
    LogoutSerializer, CookieTokenRefreshSerializer, CustomTokenRefreshSerializer, RepeatVerifyEmailSerializer,
    SupportEmailSerializer,
    IsEmailVerificationSerializer,
    ChangePasswordSerializer,
)
from .utils import Util


class RegistrationAPIView(GenericAPIView):
    """
    Регистация нового пользователя

    Регистация нового пользователя
    """
    permission_classes = (AllowAny,)
    serializer_class = RegistrationSerializer
    renderer_classes = (UserRenderer,)
    registation_response = openapi.Response('Успешная регистрация')
    code_201 = openapi.Response(
        description="Успешное создание записи",
        examples={
            "application/json": {
                "data": {
                    "email": "testemail@email.com"
                }
            }
        },
        schema=openapi.Schema(
            title='See Example Value',
            type=openapi.TYPE_OBJECT,
        )
    )
    code_400 = openapi.Response(
        description="Ошибка авторизации",
        examples={
            "application/json": {
                "errors": {
                    "email": [
                        "message email error."
                    ],
                    "password": [
                        "message password error."
                    ]
                }
            }
        },
        schema=openapi.Schema(
            title='See Example Value',
            type=openapi.TYPE_OBJECT,
        )
    )

    response_schema = {
        status.HTTP_201_CREATED: code_201,
        status.HTTP_400_BAD_REQUEST: code_400,
    }

    @swagger_auto_schema(responses=response_schema)
    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user_data = serializer.data
        user = User.objects.get(email=user_data['email'])
        send_verify_email(request, user)
        return Response(user_data, status=status.HTTP_201_CREATED)


class VerifyEmailAPIView(GenericAPIView):
    """
    Верификация нового пользователя

    Верификация нового пользователя
    """
    serializer_class = EmailVerificationSerializer
    test_param = openapi.Parameter('Токен', openapi.IN_QUERY, description="Токен из email", type=openapi.TYPE_STRING)
    code_200 = openapi.Response(
        description="Email подтвержден успешно",
        examples={
            "application/json": {
                "data": {
                    "email": "Successfully activated"
                }
            }
        },
        schema=openapi.Schema(
            title='See Example Value',
            type=openapi.TYPE_OBJECT,
        )
    )
    code_400 = openapi.Response(
        description="Токен не действителен",
        examples={
            "application/json": {
                "error": "Invalid token"
            }
        },
        schema=openapi.Schema(
            title='See Example Value',
            type=openapi.TYPE_OBJECT,
        )
    )

    response_schema = {
        status.HTTP_200_OK: code_200,
        status.HTTP_400_BAD_REQUEST: code_400,
    }

    @swagger_auto_schema(responses=response_schema, manual_parameters=[test_param])
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


class IsEmailVerifyAPIView(GenericAPIView):
    """
    Проверка верификации пользоваетеля

    Проверка верификации пользоваетеля
    """
    serializer_class = IsEmailVerificationSerializer

    code_200 = openapi.Response(
        description="Email верифицирован или не вериицирован",
        examples={
            "application/json": {
                "data": {
                    "email": "Email is verified"
                }
            }
        },
        schema=openapi.Schema(
            title='See Example Value',
            type=openapi.TYPE_OBJECT,
        )
    )
    code_404 = openapi.Response(
        description="Email не найден",
        examples={
            "application/json": {
                "error": "Email not found"
            }
        },
        schema=openapi.Schema(
            title='See Example Value',
            type=openapi.TYPE_OBJECT,
        )
    )

    response_schema = {
        status.HTTP_200_OK: code_200,
        status.HTTP_404_NOT_FOUND: code_404,
    }

    @swagger_auto_schema(responses=response_schema)
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.data['email']
        user = User.objects.filter(email=email).first()
        if user:
            if user.is_verified:
                return Response({'email': 'Email is verified'}, status=status.HTTP_200_OK)
            else:
                return Response({'email': 'Email not verified'}, status=status.HTTP_200_OK)
        return Response({'error': 'Email not found'}, status=status.HTTP_404_NOT_FOUND)


class LoginAPIView(GenericAPIView):
    """
    Авторизация пользователя

    Авторизация пользователя
    """
    serializer_class = LoginSerializer

    ## With cookie
    # def post(self, request):
    #
    #     serializer = self.serializer_class(data=request.data)
    #     serializer.is_valid(raise_exception=True)
    #
    #     protocol = request.build_absolute_uri(request.get_host()).split('/')[0]
    #
    #     response = Response()
    #     tokens = serializer.data['tokens']
    #     response.set_cookie(
    #         key=settings.SIMPLE_JWT['AUTH_COOKIE'],
    #         value=tokens["refresh"],
    #         domain=settings.SIMPLE_JWT['AUTH_COOKIE_DOMAIN'],
    #         expires=datetime.now() + settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'],
    #         secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],  # True if protocol == 'https:' else False,
    #         httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
    #         samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE'],
    #         max_age=3600 * 24 * 365,
    #     )
    #     # csrf.get_token(request)
    #     response.data = {"Success": "Login successfully", "access_token": tokens['access']}
    #     response.status_code = status.HTTP_200_OK
    #     return response

    # With local
    code_200 = openapi.Response(
        description="Вход выполнен успешно",
        examples={
            "application/json": {
                  "email": "testmail@email.com",
                  "tokens": {
                    "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0b2tlbl90eXBlIjoicmVmcmVzaCIsImV4cCI6MTY3MTAzNjg2NCwianRpIjoiZmViMDJhZjIwYWRkNDNkZDkxNjRmNjIzYzAxM2FlOWEiLCJ1c2VyX2lkIjoyfQ.K7H2KZp2XLaFZrHFwRhH2fSZiEqFYMeHHG-c2HdRKrM",
                    "refresh_live": "2022-12-14 16:54:24.669612",
                    "access": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0b2tlbl90eXBlIjoiYWNjZXNzIiwiZXhwIjoxNjM5NTAxNDY0LCJqdGkiOiJkMjViODMyZGQ1ZTc0MmU1OThmOTExMjNjN2RkMDNjNCIsInVzZXJfaWQiOjJ9.JTjL8TtdeT8oZMfGQiU5k5Us3NoW6tVT1kIpK8zpk5Q",
                    "access_live": "2021-12-14 17:04:24.673909"
                  }
            }
        },
        schema=openapi.Schema(
            title='See Example Value',
            type=openapi.TYPE_OBJECT,
        )
    )
    code_401 = openapi.Response(
        description="Ошибка учетных данных",
        examples={
            "application/json": {
                "detail": "Invalid credentials, try again"
            }
        },
        schema=openapi.Schema(
            title='See Example Value',
            type=openapi.TYPE_OBJECT,
        )
    )

    response_schema = {
        status.HTTP_200_OK: code_200,
        status.HTTP_401_UNAUTHORIZED: code_401,
    }

    @swagger_auto_schema(responses=response_schema)
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class ChangePasswordAPIView(GenericAPIView):
    """
    Изменение пароля пользователя.

    Изменение пароля пользователя.
    Доступно только для аутентифицированных пользователей
    """
    permission_classes = (permissions.IsAuthenticated,)
    serializer_class = ChangePasswordSerializer

    code_200 = openapi.Response(
        description="Пароль изменен успешно",
        examples={
            "application/json": {
                "success": 'true',
                "message": "Password reset success"
            }
        },
        schema=openapi.Schema(
            title='See Example Value',
            type=openapi.TYPE_OBJECT,
        )
    )
    code_401 = openapi.Response(
        description="Ошибка учетных данных",
        examples={
            "application/json": {
                "detail": "Invalid credentials, try again"
            }
        },
        schema=openapi.Schema(
            title='See Example Value',
            type=openapi.TYPE_OBJECT,
        )
    )

    response_schema = {
        status.HTTP_200_OK: code_200,
        status.HTTP_401_UNAUTHORIZED: code_401,
    }

    @swagger_auto_schema(responses=response_schema)
    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        password = request.data['password']
        import logging
        logging.warning(f"{request.META['HTTP_AUTHORIZATION'].split()[1]}\n{password=}")
        token = request.META['HTTP_AUTHORIZATION'].split()[1]
        payload = jwt.decode(jwt=token, key=settings.SECRET_KEY, algorithms=['HS256'])
        try:
            user = User.objects.get(id=payload['user_id'])
            user.set_password(password)
            user.save()
        except User.DoesNotExist:
            return Response({'error': 'Token is not valid, please request a new one'}, status=status.HTTP_403_FORBIDDEN)
        return Response({'success': True, 'message': 'Password reset success'}, status=status.HTTP_200_OK)


class RequestPasswordResetEmail(GenericAPIView):
    """
    Email для подтверждения встановление пароля.

    Отправка Email пользователю для подтверждения запроса на встановление пароля.
    """
    serializer_class = ResetPasswordEmailRequestSerializer

    code_200 = openapi.Response(
        description="Успех. Email отправлен",
        examples={
            "application/json": {
                "success": "We have sent you a link to reset your password"
            }
        },
        schema=openapi.Schema(
            title='See Example Value',
            type=openapi.TYPE_OBJECT,
        )
    )
    code_404 = openapi.Response(
        description="Email не найден",
        examples={
            "application/json": {
                "error": "Email not found"
            }
        },
        schema=openapi.Schema(
            title='See Example Value',
            type=openapi.TYPE_OBJECT,
        )
    )

    response_schema = {
        status.HTTP_200_OK: code_200,
        status.HTTP_404_NOT_FOUND: code_404,
    }

    @swagger_auto_schema(responses=response_schema)
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = request.data['email']

        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            current_site = get_current_site(request=request).domain
            relative_link = reverse(f'password-reset-confirm', kwargs={'uidb64': uidb64, 'token': token})
            # remove api/v1
            relative_link = '/'.join(relative_link.split('/')[3:])

            absurl = 'https://' + current_site + '/' + relative_link
            email_body = 'Hello,\n Use link below to reset your password \n' + absurl
            data = {'email_body': email_body, 'to_email': user.email,
                    'email_subject': 'Reset your password'}
            Util.send_email(data)
            return Response({'success': 'We have sent you a link to reset your password'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Email not found'}, status=status.HTTP_404_NOT_FOUND)


class PasswordTokenCheckAPIView(GenericAPIView):
    """
    Проверка возможности восстановления пароля

    Проверка данных пользователя для восстановление пароля
    """
    serializer_class = SetNewPasswordSerializer

    code_200 = openapi.Response(
        description="Данные действительны. Пароль возможно изменить",
        examples={
            "application/json": {
                'success': 'true',
                'message': 'Creantails Vaild'
            }
        },
        schema=openapi.Schema(
            title='See Example Value',
            type=openapi.TYPE_OBJECT,
        )
    )
    code_400 = openapi.Response(
        description="Ошибка. Токен не действителен",
        examples={
            "application/json": {
                "error": "Token is not valid, please request a new one"
            }
        },
        schema=openapi.Schema(
            title='See Example Value',
            type=openapi.TYPE_OBJECT,
        )
    )

    response_schema = {
        status.HTTP_200_OK: code_200,
        status.HTTP_400_BAD_REQUEST: code_400,
    }

    @swagger_auto_schema(responses=response_schema)
    def get(self, request, uidb64, token):

        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'error': 'Token is not valid, please request a new one'},
                                status=status.HTTP_400_BAD_REQUEST)

            return Response({'success': True, 'message': 'Creantails Vaild', 'uidb64': uidb64},
                            status=status.HTTP_200_OK)
        except DjangoUnicodeDecodeError:
            return Response({'error': 'Token is not valid, please request a new one'},
                            status=status.HTTP_400_BAD_REQUEST)


class SetNewPasswordAPIView(GenericAPIView):
    """
    Установка нового пароля

    Установка нового пароля
    """
    serializer_class = SetNewPasswordSerializer

    code_200 = openapi.Response(
        description="Пароль изменен успешно",
        examples={
            "application/json": {
                "success": 'true',
                "message": "Password reset success"
            }
        },
        schema=openapi.Schema(
            title='See Example Value',
            type=openapi.TYPE_OBJECT,
        )
    )
    code_401 = openapi.Response(
        description="Ошибка. Данные не верны",
        examples={
            "application/json": {
                "detail": "The reset link is invalid"
            }
        },
        schema=openapi.Schema(
            title='See Example Value',
            type=openapi.TYPE_OBJECT,
        )
    )

    response_schema = {
        status.HTTP_200_OK: code_200,
        status.HTTP_401_UNAUTHORIZED: code_401,
    }

    @swagger_auto_schema(responses=response_schema)
    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'success': True, 'message': 'Password reset success'}, status=status.HTTP_200_OK)


class LogoutAPIView(GenericAPIView):
    """
    Выход из профиля пользователя

    Выход из профиля пользователя
    Занесение refresh token в blacklist
    """
    serializer_class = LogoutSerializer

    permission_classes = (permissions.IsAuthenticated,)

    code_204 = openapi.Response(
        description="Выход прошел успешно",
    )
    code_401 = openapi.Response(
        description="Ошибка учетных данных",
        examples={
            "application/json": {
                "detail": "Authentication credentials were not provided."
            }
        },
        schema=openapi.Schema(
            title='See Example Value',
            type=openapi.TYPE_OBJECT,
        )
    )

    response_schema = {
        status.HTTP_204_NO_CONTENT: code_204,
        status.HTTP_401_UNAUTHORIZED: code_401,
    }

    @swagger_auto_schema(responses=response_schema)
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
                domain=settings.SIMPLE_JWT['AUTH_COOKIE_DOMAIN'],
                max_age=3600 * 24 * 365,
                expires=settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'],
                secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
                # httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
                samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE'],
            )
            del response.data['refresh']
        return super().finalize_response(request, response, *args, **kwargs)


class CustomTokenRefreshView(TokenRefreshView):
    """
    Обновление refresh токена

    Обновление refresh токена
    """
    serializer_class = CustomTokenRefreshSerializer


class RepeatVerifyEmailAPIView(GenericAPIView):
    """
    Повторная отправка Email запроса верификации

    Повторная отправка Email запроса верификации
    """
    serializer_class = RepeatVerifyEmailSerializer
    renderer_classes = (UserRenderer,)

    code_200 = openapi.Response(
        description="Запрос отправлен успешно",
        examples={
            "application/json": {
                "data": {
                "email": "testemail@email.com"
                }
            }
        },
        schema=openapi.Schema(
            title='See Example Value',
            type=openapi.TYPE_OBJECT,
        )
    )
    code_404 = openapi.Response(
        description="Ошибка. Email не найден",
        examples={
            "application/json": {
                "error": "Email not found"
            }
        },
        schema=openapi.Schema(
            title='See Example Value',
            type=openapi.TYPE_OBJECT,
        )
    )

    response_schema = {
        status.HTTP_200_OK: code_200,
        status.HTTP_404_NOT_FOUND: code_404,
    }

    @swagger_auto_schema(responses=response_schema)
    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        user_data = serializer.data
        user = User.objects.filter(email=user_data['email']).first()
        if user:
            send_verify_email(request, user)
            return Response(user_data, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Email not found'}, status=status.HTTP_404_NOT_FOUND)


def send_verify_email(request, user):
    token = RefreshToken.for_user(user).access_token
    current_site = get_current_site(request).domain
    relative_link = reverse('email-verify')

    # remove api/v1
    relative_link = '/'.join(relative_link.split('/')[3:])

    absurl = f'https://{current_site}/{relative_link}?token={str(token)}'

    email_body = f'Hello. Use link below to verify your email \n{absurl}'
    data = {
        'email_subject': 'Verify your email',
        'email_body': email_body,
        'to_email': user.email
    }
    Util.send_email(data)


class SupportEmailAPIView(GenericAPIView):
    """
    Отправка Email службе поддержки

    Отправка Email службе поддержки
    """
    serializer_class = SupportEmailSerializer

    code_200 = openapi.Response(
        description="Успех. Сообщение отправлено.",
        examples={
            "application/json": {
                "success": "We have sent email"
            }
        },
        schema=openapi.Schema(
            title='See Example Value',
            type=openapi.TYPE_OBJECT,
        )
    )
    code_400 = openapi.Response(
        description="Ошибка. Введенные данные не верны",
        examples={
            "application/json": {
                "email": [
                    "This field is required."
                ],
                "name": [
                    "This field is required."
                ],
                "body": [
                    "This field is required."
                ]
            }
        },
        schema=openapi.Schema(
            title='See Example Value',
            type=openapi.TYPE_OBJECT,
        )
    )

    response_schema = {
        status.HTTP_200_OK: code_200,
        status.HTTP_400_BAD_REQUEST: code_400,
    }

    @swagger_auto_schema(responses=response_schema)
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.data

        name = data['name']
        email = data['email']
        body = data['body']

        data = {'email_body': f'From: {name}\n Email: {email}\n + Message: {body}',
                'to_email': settings.EMAIL_SUPPORT,
                'email_subject': 'Support user'}
        Util.send_email(data)
        return Response({'success': f'We have sent email'}, status=status.HTTP_200_OK)
