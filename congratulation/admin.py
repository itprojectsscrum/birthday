from django.contrib import admin

from .models import Congratulate


class CongratulateAdmin(admin.ModelAdmin):
    list_display = ('owner', 'bday_name', 'alert_datetime', 'notify_by_email', 'notify_by_push', 'comment')


admin.site.register(Congratulate, CongratulateAdmin)
