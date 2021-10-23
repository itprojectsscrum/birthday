from django.conf import settings
from celery import shared_task
from datetime import datetime, timedelta

from authentication.utils import Util
from .models import Congratulate


@shared_task
def to_schedule():
    congratulates = Congratulate.objects.\
        filter(alert_datetime__gte=datetime.now()).\
        filter(alert_datetime__lt=datetime.now() + timedelta(minutes=1))  # As app.conf.beat_schedule
    data = {}
    for congratulate in congratulates:
        if congratulate:
            if congratulate.notify_by_email:
                data['email_subject'] = f'Congratulate {congratulate.bday_name}'
                data['email_body'] = f'Congratulate {congratulate.bday_name}. \nComment: {congratulate.comment}'
                data['to_email'] = [congratulate.owner.email]
                email_send.apply_async(
                    args=(
                        f'Congratulate {congratulate.bday_name}',
                        f'Congratulate {congratulate.bday_name}. \nComment: {congratulate.comment}',
                        congratulate.owner.email
                    ),
                    eta=congratulate.alert_datetime
                )


@shared_task
def email_send(subject, body, to):
    data = {}
    data['email_subject'] = subject
    data['email_body'] = body
    data['to_email'] = to
    print(f' send email {data=}')
    Util.send_email(data)
