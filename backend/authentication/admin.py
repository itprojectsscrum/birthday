from django.contrib import admin
from rest_framework_simplejwt.token_blacklist import models
from rest_framework_simplejwt.token_blacklist.admin import OutstandingTokenAdmin

from .models import User


# Преопределяем метод, т.к. в стандартной реализации нет возможности из
# админки удалить пользователя, которому был выдан токен
# https://github.com/jazzband/djangorestframework-simplejwt/issues/266#issuecomment-850985081
class NewOutstandingTokenAdmin(OutstandingTokenAdmin):

    def has_delete_permission(self, *args, **kwargs):
        return True


admin.site.unregister(models.OutstandingToken)
admin.site.register(models.OutstandingToken, NewOutstandingTokenAdmin)

admin.site.register(User)
