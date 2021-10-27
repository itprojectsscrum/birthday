from django.db import models
from authentication.models import User


class Congratulate(models.Model):
    owner = models.ForeignKey(to=User, on_delete=models.CASCADE)
    bday_name = models.CharField(max_length=128)
    alert_datetime = models.DateTimeField(null=False, blank=False)
    notify_by_email = models.BooleanField(default=True)
    notify_by_push = models.BooleanField(default=False)
    comment = models.TextField(null=True, blank=True)

    def __str__(self):
        return self.bday_name
