from datetime import datetime

import jwt
from django.conf import settings
from django.contrib import auth
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode

from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from rest_framework_simplejwt.state import token_backend
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken

from .models import User


class RegistrationSerializer(serializers.ModelSerializer):
    """ Сериализация регистрации пользователя и создания нового. """

    # Проверяем, что пароль содержит не менее 6 символов, не более 50,
    # и так же что он не может быть прочитан клиентской стороной
    password = serializers.CharField(
        min_length=6,
        write_only=True
    )

    class Meta:
        model = User
        # Указываем все поля, которые могут быть включены в запрос или ответ
        fields = ['email', 'password']

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)


class EmailVerificationSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=555)

    class Meta:
        model = User
        fields = ['token']


class IsEmailVerificationSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(
        max_length=100,
        min_length=7
    )

    class Meta:
        model = User
        fields = ['email']


class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(
        max_length=100,
        min_length=7
    )
    password = serializers.CharField(
        min_length=6,
        write_only=True)

    tokens = serializers.SerializerMethodField()

    def get_tokens(self, obj):
        user = User.objects.get(email=obj['email'])

        return {
            'refresh': user.tokens()['refresh'],
            'refresh_live': user.tokens()['refresh_live'],
            'access': user.tokens()['access'],
            'access_live': user.tokens()['access_live'],
        }

    class Meta:
        model = User
        fields = ['email', 'password', 'tokens']

    def validate(self, attrs):
        email = attrs.get('email', '')
        password = attrs.get('password', '')
        user = auth.authenticate(email=email, password=password)

        if not user:
            raise AuthenticationFailed('Invalid credentials, try again')
        if not user.is_active:
            raise AuthenticationFailed('Account disabled, contact admin')
        # if not user.is_verified:
        #     raise AuthenticationFailed('Email is not verified')
        return {
            'email': user.email,
            'tokens': user.tokens
        }


class ChangePasswordSerializer(serializers.Serializer):
    password = serializers.CharField(
        min_length=6,
        write_only=True
    )

    class Meta:
        model = User
        fields = ['password']


class ResetPasswordEmailRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(min_length=7,
                                   max_length=100)

    class Meta:
        fields = ['email']


class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(
        min_length=6, write_only=True)
    token = serializers.CharField(
        min_length=1, write_only=True)
    uidb64 = serializers.CharField(
        min_length=1, write_only=True)

    class Meta:
        fields = ['password', 'token', 'uidb64']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            token = attrs.get('token')
            uidb64 = attrs.get('uidb64')

            id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed('The reset link is invalid', 401)

            user.set_password(password)
            user.save()

            return (user)
        except Exception as e:
            raise AuthenticationFailed('The reset link is invalid', 401)


class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    default_error_message = {
        'bad_token': ('Token is expired or invalid')
    }

    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs

    def save(self, **kwargs):

        try:
            RefreshToken(self.token).blacklist()

        except TokenError:
            self.fail('bad_token')


class CookieTokenRefreshSerializer(TokenRefreshSerializer):
    refresh = None

    def validate(self, attrs):
        attrs['refresh'] = self.context['request'].COOKIES.get('refresh_token')
        if attrs['refresh']:
            return attrs
        else:
            raise InvalidToken('No valid token found in cookie \'refresh_token\'')


class CustomTokenRefreshSerializer(TokenRefreshSerializer):

    def validate(self, attrs):
        data = super(CustomTokenRefreshSerializer, self).validate(attrs)
        decoded_payload = token_backend.decode(data['access'], verify=True)
        user_uid=decoded_payload['user_id']
        # add filter query
        data.update({'access_live': str(datetime.now() + settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'])})
        return data


class RepeatVerifyEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(min_length=7,
                                   max_length=100)

    class Meta:
        model = User
        fields = ['email']


class SupportEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(min_length=7,
                                   max_length=100)
    name = serializers.CharField(min_length=1)
    body = serializers.CharField(min_length=1)

    class Meta:
        fields = ['email', 'name', 'body']
