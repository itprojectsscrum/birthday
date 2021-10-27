from rest_framework import permissions
from rest_framework.generics import ListCreateAPIView, RetrieveUpdateDestroyAPIView

from .models import Congratulate
from .permissions import IsOwner
from .serializer import CongratulateSerializer


class CongratulateListAPIView(ListCreateAPIView):
    """
        Записи поздравлений пользователя
        Только аутентифицированные пользователи имеют доступ к данному эндпоинту.
    """
    serializer_class = CongratulateSerializer
    queryset = Congratulate.objects.all()
    permission_classes = (permissions.IsAuthenticated,)

    def perform_create(self, serializer):
        return serializer.save(owner=self.request.user)

    def get_queryset(self):
        return self.queryset.filter(owner=self.request.user)


class CongratulateDetailAPIView(RetrieveUpdateDestroyAPIView):
    """
        Редактирование и удаление записей поздравлений пользователя
        Только аутентифицированные пользователи имеют доступ к данному эндпоинту.
    """
    serializer_class = CongratulateSerializer
    queryset = Congratulate.objects.all()
    permission_classes = (permissions.IsAuthenticated, IsOwner)
    lookup_field = 'id'

    def perform_create(self, serializer):
        return serializer.save(owner=self.request.user)

    def get_queryset(self):
        return self.queryset.filter(owner=self.request.user)

