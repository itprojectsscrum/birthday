from drf_yasg import openapi
from rest_framework import permissions
from rest_framework.generics import ListCreateAPIView, RetrieveUpdateDestroyAPIView
from drf_yasg.utils import swagger_auto_schema
from rest_framework.exceptions import NotAuthenticated

from .models import Congratulate
from .permissions import IsOwner
from .serializer import CongratulateSerializer


class CongratulateListAPIView(ListCreateAPIView):
    serializer_class = CongratulateSerializer
    queryset = Congratulate.objects.all()
    permission_classes = (permissions.IsAuthenticated,)
    code_200 = lambda text: openapi.Response(
        description=text,
        examples={
            "application/json": {
                "id": 258,
                "bday_name": "Иванов Иван Иванович",
                "alert_datetime": "2021-12-05T18:54:11.633000Z",
                "notify_by_email": True,
                "comment": "Обязательно поздравить!"
            }
        }
    )
    code_401 = openapi.Response(
        description="Ошибка авторизации",
        examples={
            "application/json": {
                "detail": "Authentication credentials were not provided."
            }
        }
    )
    response_schema_create = {
        "200": code_200("Успешное создание записи"),
        "401": code_401,
    }
    response_schema_list = {
        "200": code_200("Все записи пользователя"),
        "401": code_401,
    }

    def perform_create(self, serializer):
        return serializer.save(owner=self.request.user)

    def get_queryset(self):
        return self.queryset.filter(owner=self.request.user).order_by('-alert_datetime')

    @swagger_auto_schema(responses=response_schema_list)
    def get(self, request, *args, **kwargs):
        """
        Список всех записей пользователя

        Список всех записей пользователя
        """
        return super().get(request, *args, **kwargs)

    @swagger_auto_schema(responses=response_schema_create)
    def post(self, request, *args, **kwargs):
        """
        Создание записи

        Создание записи
        """
        return super().post(request, *args, **kwargs)


class CongratulateDetailAPIView(RetrieveUpdateDestroyAPIView):
    """
    Редактирование и удаление записей поздравлений пользователя
    Только аутентифицированные пользователи имеют доступ к данному эндпоинту.
    """
    serializer_class = CongratulateSerializer
    queryset = Congratulate.objects.all()
    permission_classes = (permissions.IsAuthenticated, IsOwner)
    lookup_field = 'id'
    code_200 = lambda text: openapi.Response(
        description=text,
        examples={
            "application/json": {
                "id": 258,
                "bday_name": "Иванов Иван Иванович",
                "alert_datetime": "2021-12-05T18:54:11.633000Z",
                "notify_by_email": True,
                "comment": "Обязательно поздравить!"
            }
        }
    )
    code_401 = openapi.Response(
        description="Ошибка авторизации",
        examples={
            "application/json": {
                "detail": "Authentication credentials were not provided."
            }
        }
    )
    code_404 = openapi.Response(
        description="Запись не найдена",
        examples={
            "application/json": {
                "detail": "Not found."
            }
        }
    )
    response_schema_get = {
        "200": code_200("Успешное получение записи"),
        "401": code_401,
        "404": code_404,

    }
    response_schema_update = {
        "200": code_200("Запись успешно изменена"),
        "401": code_401,
        "404": code_404,
    }
    response_schema_delete = {
        "204": openapi.Response(description="Запись успешно удалена"),
        "401": code_401,
        "404": code_404
    }

    def perform_create(self, serializer):
        return serializer.save(owner=self.request.user)

    def get_queryset(self):
        return self.queryset.filter(owner=self.request.user)

    @swagger_auto_schema(responses=response_schema_get)
    def get(self, request, *args, **kwargs):
        """
        Просмотр записи

        Просмотр записи
        """
        return super().get(request, *args, **kwargs)

    @swagger_auto_schema(responses=response_schema_update)
    def put(self, request, *args, **kwargs):
        """
        Изменение записи

        Изменение записи
        """
        return super().put(request, *args, **kwargs)

    @swagger_auto_schema(responses=response_schema_update)
    def patch(self, request, *args, **kwargs):
        """
        Редактирование записи

        Редактирование записи
        """
        return super().patch(request, *args, **kwargs)

    @swagger_auto_schema(responses=response_schema_delete)
    def delete(self, request, *args, **kwargs):
        """
        Удаление записи

        Удаление записи
        """
        return super().delete(request, *args, **kwargs)
