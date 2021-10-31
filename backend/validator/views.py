from django.core.validators import EmailValidator

from rest_framework.response import Response
from rest_framework.views import APIView


class EmailValidatorAPIView(APIView):

    def get(self, request):
        user_regex = EmailValidator.user_regex.pattern
        domain_regex = EmailValidator.domain_regex.pattern
        return Response({'user_regex': user_regex, 'domain_regex': domain_regex})
