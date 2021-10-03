import os

from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework_simplejwt.tokens import RefreshToken

from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode


from .models import User
from .renderers import UserRenderer
from .serializers import (
    RegistrationSerializer,
    LoginSerializer,
    ResetPasswordEmailRequestSerializer, SetNewPasswordSerializer,
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

        return Response(user_data, status=status.HTTP_201_CREATED)


class LoginAPIView(GenericAPIView):
    """
    Авторизация пользователя
    """
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class RequestPasswordResetEmail(GenericAPIView):
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

            redirect_url = request.data.get('redirect_url', '')
            absurl = 'http://' + current_site + relative_link
            email_body = 'Hello,\n Use link below to reset your password \n' + \
                         absurl + '?redirect_url=' + redirect_url
            print(email_body)  # TODO
            data = {'email_body': email_body, 'to_email': user.email,
                    'email_subject': 'Reset your password'}
            Util.send_email(data)
        return Response({'success': 'We have sent you a link to reset your password'}, status=status.HTTP_200_OK)


class PasswordTokenCheckAPIView(GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def get(self, request, uidb64, token):

        redirect_url = request.GET.get('redirect_url')

        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user,token):
                return Response({'error': 'Token is not valid, please request a new one'})

            return Response({'success': True, 'messagee': 'Creantails Vaild', 'uidb64': uidb64})
        except DjangoUnicodeDecodeError as e:
            return Response({'error': 'Token is not valid, please request a new one'})

        #     if not PasswordResetTokenGenerator().check_token(user, token):
        #         if len(redirect_url) > 3:
        #             return CustomRedirect(redirect_url + '?token_valid=False')
        #         else:
        #             return CustomRedirect(os.environ.get('FRONTEND_URL', '') + '?token_valid=False')
        #
        #     if redirect_url and len(redirect_url) > 3:
        #         return CustomRedirect(
        #             redirect_url + '?token_valid=True&message=Credentials Valid&uidb64=' + uidb64 + '&token=' + token)
        #     else:
        #         return CustomRedirect(os.environ.get('FRONTEND_URL', '') + '?token_valid=False')
        #
        # except DjangoUnicodeDecodeError as identifier:
        #     try:
        #         if not PasswordResetTokenGenerator().check_token(user):
        #             return CustomRedirect(redirect_url + '?token_valid=False')
        #
        #     except UnboundLocalError as e:
        #         return Response({'error': 'Token is not valid, please request a new one'},
        #                         status=status.HTTP_400_BAD_REQUEST)


class SetNewPasswordAPIView(GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'success': True, 'message': 'Password reset success'}, status=status.HTTP_200_OK)


# class LogoutAPIView(GenericAPIView):
#     serializer_class = LogoutSerializer
#
#     permission_classes = (permissions.IsAuthenticated,)
#
#     def post(self, request):
#
#         serializer = self.serializer_class(data=request.data)
#         serializer.is_valid(raise_exception=True)
#         serializer.save()
#
#         return Response(status=status.HTTP_204_NO_CONTENT)
