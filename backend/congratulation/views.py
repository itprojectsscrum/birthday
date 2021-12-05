from drf_yasg import openapi
from rest_framework import permissions
from rest_framework.generics import ListCreateAPIView, RetrieveUpdateDestroyAPIView
from drf_yasg.utils import swagger_auto_schema

from .models import Congratulate
from .permissions import IsOwner
from .serializer import CongratulateSerializer


class CongratulateListAPIView(ListCreateAPIView):
    """
    Записи поздравлений пользователя

    Записи поздравлений пользователя
    Только аутентифицированные пользователи имеют доступ к данному эндпоинту.
    """
    serializer_class = CongratulateSerializer
    queryset = Congratulate.objects.all()
    permission_classes = (permissions.IsAuthenticated,)

    def perform_create(self, serializer):
        return serializer.save(owner=self.request.user)

    def get_queryset(self):
        return self.queryset.filter(owner=self.request.user).order_by('-alert_datetime')


class CongratulateDetailAPIView(RetrieveUpdateDestroyAPIView):
    """
    Редактирование и удаление записей поздравлений пользователя

    Редактирование и удаление записей поздравлений пользователя
    Только аутентифицированные пользователи имеют доступ к данному эндпоинту.
    """
    serializer_class = CongratulateSerializer
    queryset = Congratulate.objects.all()
    permission_classes = (permissions.IsAuthenticated, IsOwner)
    lookup_field = 'id'
    delete_response = openapi.Response('Запись успешно удалена')

    def perform_create(self, serializer):
        return serializer.save(owner=self.request.user)

    def get_queryset(self):
        return self.queryset.filter(owner=self.request.user)

    @swagger_auto_schema(operation_description="Удаление записи пользоателя", responses={204: delete_response})
    def delete(self, request, *args, **kwargs):
        return super().delete(request, *args, **kwargs)


