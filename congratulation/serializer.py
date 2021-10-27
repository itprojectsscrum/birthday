from rest_framework import serializers

from .models import Congratulate


class CongratulateSerializer(serializers.ModelSerializer):

    class Meta:
        model = Congratulate
        fields = [
            'id',
            'bday_name',
            'alert_datetime',
            'notify_by_email',
            'notify_by_push',
            'comment'
        ]

